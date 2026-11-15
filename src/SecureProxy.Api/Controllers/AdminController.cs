using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Admin;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Infrastructure;
using SecureProxy.Api.Proxy;
using SecureProxy.Api.Security;

namespace SecureProxy.Api.Controllers;

/// <summary>
/// Minimal configuration administration: read, enable/disable and update operations and destinations, and read the change
/// history. Updates require the current concurrency stamp (<c>If-Match</c> header or <c>concurrencyStamp</c> body member);
/// a stale stamp yields <c>409 Conflict</c> with the current stamp in the <c>ETag</c> header.
/// </summary>
[ApiController]
[Route("api/admin")]
[EnableRateLimiting(RateLimitPolicies.Admin)]
[ServiceFilter(typeof(AdminApiKeyFilter))]
public sealed class AdminController : ControllerBase
{
    private readonly ConfigurationAdminService _admin;
    private readonly IOptionsMonitor<AdminOptions> _options;

    public AdminController(ConfigurationAdminService admin, IOptionsMonitor<AdminOptions> options)
    {
        _admin = admin;
        _options = options;
    }

    [HttpGet("operations")]
    public async Task<ActionResult<IReadOnlyList<OperationAdminDto>>> ListOperations(CancellationToken cancellationToken)
        => Ok(await _admin.ListOperationsAsync(cancellationToken));

    [HttpGet("operations/{key}")]
    public async Task<ActionResult<OperationAdminDto>> GetOperation(string key, CancellationToken cancellationToken)
    {
        var dto = await _admin.GetOperationAsync(key, cancellationToken);
        if (dto is null)
        {
            return NotFound();
        }

        Response.Headers.ETag = Quote(dto.ConcurrencyStamp);
        return Ok(dto);
    }

    [HttpPut("operations/{key}")]
    public async Task<ActionResult<OperationAdminDto>> UpdateOperation(string key, [FromBody] UpdateOperationRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var dto = await _admin.UpdateOperationAsync(key, request, ExpectedStamp(request.ConcurrencyStamp), _options.CurrentValue.PrincipalName, CorrelationIdMiddleware.Get(HttpContext), cancellationToken);
            Response.Headers.ETag = Quote(dto.ConcurrencyStamp);
            return Ok(dto);
        }
        catch (ConfigurationNotFoundException)
        {
            return NotFound();
        }
        catch (InvalidConfigurationChangeException ex)
        {
            return Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest, title: "Invalid configuration change");
        }
        catch (ConcurrencyConflictException ex)
        {
            return Conflict(ex);
        }
    }

    [HttpGet("destinations")]
    public async Task<ActionResult<IReadOnlyList<DestinationAdminDto>>> ListDestinations(CancellationToken cancellationToken)
        => Ok(await _admin.ListDestinationsAsync(cancellationToken));

    [HttpGet("destinations/{key}")]
    public async Task<ActionResult<DestinationAdminDto>> GetDestination(string key, CancellationToken cancellationToken)
    {
        var dto = await _admin.GetDestinationAsync(key, cancellationToken);
        if (dto is null)
        {
            return NotFound();
        }

        Response.Headers.ETag = Quote(dto.ConcurrencyStamp);
        return Ok(dto);
    }

    [HttpPut("destinations/{key}")]
    public async Task<ActionResult<DestinationAdminDto>> UpdateDestination(string key, [FromBody] UpdateDestinationRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var dto = await _admin.UpdateDestinationAsync(key, request, ExpectedStamp(request.ConcurrencyStamp), _options.CurrentValue.PrincipalName, CorrelationIdMiddleware.Get(HttpContext), cancellationToken);
            Response.Headers.ETag = Quote(dto.ConcurrencyStamp);
            return Ok(dto);
        }
        catch (ConfigurationNotFoundException)
        {
            return NotFound();
        }
        catch (InvalidConfigurationChangeException ex)
        {
            return Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest, title: "Invalid configuration change");
        }
        catch (ConcurrencyConflictException ex)
        {
            return Conflict(ex);
        }
    }

    [HttpGet("configuration-changes")]
    public async Task<ActionResult<IReadOnlyList<ConfigurationChangeDto>>> GetHistory([FromQuery] string? entityType, [FromQuery] string? entityKey, [FromQuery] int take = 50, CancellationToken cancellationToken = default)
        => Ok(await _admin.GetHistoryAsync(entityType, entityKey, take, cancellationToken));

    private string ExpectedStamp(string? bodyStamp)
    {
        var ifMatch = Request.Headers.IfMatch.ToString();
        return !string.IsNullOrWhiteSpace(ifMatch) ? ifMatch.Trim().Trim('"') : bodyStamp ?? string.Empty;
    }

    private ObjectResult Conflict(ConcurrencyConflictException ex)
    {
        Response.Headers.ETag = Quote(ex.CurrentStamp);
        var problem = new ProblemDetails
        {
            Type = $"https://secureproxy.example/errors/{ProxyErrorCodes.ConcurrencyConflict}",
            Title = "Configuration concurrency conflict",
            Status = StatusCodes.Status409Conflict,
            Detail = "The configuration was modified by someone else. Reload it and retry with the current concurrency stamp."
        };
        problem.Extensions["code"] = ProxyErrorCodes.ConcurrencyConflict;
        problem.Extensions["currentConcurrencyStamp"] = ex.CurrentStamp;
        problem.Extensions["correlationId"] = CorrelationIdMiddleware.Get(HttpContext);
        return new ObjectResult(problem) { StatusCode = StatusCodes.Status409Conflict, ContentTypes = { "application/problem+json" } };
    }

    private static string Quote(string stamp) => $"\"{stamp}\"";
}
