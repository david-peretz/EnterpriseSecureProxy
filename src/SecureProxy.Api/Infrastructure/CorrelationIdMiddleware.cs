using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;

namespace SecureProxy.Api.Infrastructure;

/// <summary>
/// Accepts a well-formed caller supplied correlation id or generates one, exposes it on the response and wraps the
/// request in a logging scope so every structured log line can be traced back to the execution.
/// </summary>
public sealed partial class CorrelationIdMiddleware
{
    public const string ItemKey = "SecureProxy.CorrelationId";

    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, IOptionsMonitor<ProxyOptions> options, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var headerName = _options.CurrentValue.CorrelationHeaderName;
        var incoming = context.Request.Headers[headerName].ToString();
        var correlationId = IsValid(incoming) ? incoming : Guid.NewGuid().ToString("N");

        context.Items[ItemKey] = correlationId;
        context.TraceIdentifier = correlationId;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[headerName] = correlationId;
            return Task.CompletedTask;
        });

        using (_logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
        {
            await _next(context).ConfigureAwait(false);
        }
    }

    public static string Get(HttpContext context)
        => context.Items.TryGetValue(ItemKey, out var value) && value is string s ? s : context.TraceIdentifier;

    private static bool IsValid(string value) => value.Length is > 0 and <= 64 && CorrelationRegex().IsMatch(value);

    [GeneratedRegex("^[A-Za-z0-9._:-]+$")]
    private static partial Regex CorrelationRegex();
}
