using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;

namespace SecureProxy.Api.Security;

/// <summary>
/// Protects the admin API with a shared secret supplied in a header. The comparison is constant-time and the endpoints
/// behave as if they do not exist (404) when no key is configured, so an unconfigured deployment cannot be administered remotely.
/// (A production deployment would typically replace this with OAuth/mTLS; the filter is the single seam to swap.)
/// </summary>
public sealed class AdminApiKeyFilter : IAsyncAuthorizationFilter
{
    private readonly IOptionsMonitor<AdminOptions> _options;

    public AdminApiKeyFilter(IOptionsMonitor<AdminOptions> options)
    {
        _options = options;
    }

    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var options = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(options.ApiKey))
        {
            context.Result = new NotFoundResult();
            return Task.CompletedTask;
        }

        var supplied = context.HttpContext.Request.Headers[options.HeaderName].ToString();
        if (!FixedTimeEquals(supplied, options.ApiKey))
        {
            context.Result = new UnauthorizedResult();
        }

        return Task.CompletedTask;
    }

    private static bool FixedTimeEquals(string supplied, string expected)
    {
        var a = Encoding.UTF8.GetBytes(supplied);
        var b = Encoding.UTF8.GetBytes(expected);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }
}
