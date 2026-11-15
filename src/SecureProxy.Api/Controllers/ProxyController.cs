using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecureProxy.Api.Proxy;

namespace SecureProxy.Api.Controllers;

/// <summary>
/// The single public entry point. All validation, policy enforcement, forwarding and auditing is delegated to
/// <see cref="ProxyExecutor"/> so the whole request flow can be traced in one place.
/// </summary>
[ApiController]
[Route("api/proxy")]
[EnableRateLimiting(RateLimitPolicies.PerClient)]
public sealed class ProxyController : ControllerBase
{
    private readonly ProxyExecutor _executor;

    public ProxyController(ProxyExecutor executor)
    {
        _executor = executor;
    }

    /// <summary>Executes a configured operation. Body: <c>{ "clientId": "...", "json": { "urlId": "...", ... } }</c>.</summary>
    [HttpPost("execute")]
    public Task Execute() => _executor.ExecuteAsync(HttpContext);
}

public static class RateLimitPolicies
{
    public const string PerClient = "per-client";

    /// <summary>Tight per-client limit for the admin surface, mainly to make API-key guessing impractical.</summary>
    public const string Admin = "admin";
}
