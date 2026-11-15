using Microsoft.AspNetCore.Mvc;

namespace SecureProxy.Api.Proxy;

/// <summary>
/// Machine readable error codes returned in <see cref="ProblemDetails"/> extensions and recorded in the audit log.
/// Messages are deliberately generic: they never contain upstream host names, configuration values or exception text.
/// </summary>
public static class ProxyErrorCodes
{
    public const string UnsupportedMediaType = "request.unsupported_media_type";
    public const string EnvelopeTooLarge = "request.too_large";
    public const string InvalidJson = "envelope.invalid_json";
    public const string InvalidEnvelope = "envelope.invalid";
    public const string UnknownEnvelopeMember = "envelope.unknown_member";
    public const string UnknownOperation = "operation.unknown";
    public const string OperationDisabled = "operation.disabled";
    public const string DestinationUnavailable = "destination.unavailable";
    public const string InvalidConfiguration = "configuration.invalid";
    public const string ConfigurationUnavailable = "configuration.unavailable";
    public const string ConcurrencyConflict = "configuration.concurrency_conflict";
    public const string UrlIdMismatch = "envelope.url_id_mismatch";
    public const string EncryptionRequired = "payload.encryption_required";
    public const string EncryptionNotExpected = "payload.encryption_not_expected";
    public const string DecryptionFailed = "payload.invalid_encrypted_payload";
    public const string InvalidParameters = "parameters.invalid";
    public const string RequestBodyTooLarge = "request.body_too_large";
    public const string RateLimited = "request.rate_limited";
    public const string Overloaded = "proxy.overloaded";
    public const string CircuitOpen = "upstream.circuit_open";
    public const string UpstreamTimeout = "upstream.timeout";
    public const string UpstreamUnreachable = "upstream.unreachable";
    public const string UpstreamResponseTooLarge = "upstream.response_too_large";
    public const string AuditUnavailable = "audit.unavailable";
    public const string InternalError = "proxy.internal_error";
}

/// <summary>A request that must not be forwarded, together with the public response describing why.</summary>
public sealed record ProxyRejection(int StatusCode, string Code, string Message, IReadOnlyList<ParameterError>? Errors = null)
{
    /// <summary>
    /// Text stored in the audit record. Defaults to <see cref="Message"/>; override it when the public message echoes
    /// caller supplied data (e.g. unknown member names) so that caller input never reaches the audit table.
    /// </summary>
    public string AuditDetail { get; init; } = Message;

    public static ProxyRejection BadRequest(string code, string message, IReadOnlyList<ParameterError>? errors = null)
        => new(StatusCodes.Status400BadRequest, code, message, errors);
}

public sealed record ParameterError(string Name, string Code, string Message);

public static class ProblemDetailsFactoryExtensions
{
    public const string ProxySourceHeader = "X-Proxy-Source";

    /// <summary>Builds the uniform, non-sensitive error body used for every proxy generated failure.</summary>
    public static ProblemDetails ToProblemDetails(this ProxyRejection rejection, string correlationId)
    {
        var problem = new ProblemDetails
        {
            Type = $"https://secureproxy.example/errors/{rejection.Code}",
            Title = rejection.Message,
            Status = rejection.StatusCode,
            Detail = rejection.Errors is { Count: > 0 } ? "One or more parameters are invalid." : null
        };
        problem.Extensions["code"] = rejection.Code;
        problem.Extensions["correlationId"] = correlationId;
        problem.Extensions["source"] = "proxy";
        if (rejection.Errors is { Count: > 0 })
        {
            problem.Extensions["errors"] = rejection.Errors;
        }

        return problem;
    }

    public static async Task WriteProblemAsync(this HttpContext context, ProxyRejection rejection, string correlationId)
    {
        var response = context.Response;
        if (response.HasStarted)
        {
            // Headers already sent (streaming an upstream body); the only honest option is to abort the connection.
            context.Abort();
            return;
        }

        response.Clear();
        response.StatusCode = rejection.StatusCode;
        response.Headers[ProxySourceHeader] = "proxy";
        if (rejection.StatusCode == StatusCodes.Status429TooManyRequests || rejection.StatusCode == StatusCodes.Status503ServiceUnavailable)
        {
            response.Headers.RetryAfter = "1";
        }

        await response.WriteAsJsonAsync(rejection.ToProblemDetails(correlationId), options: null, contentType: "application/problem+json", context.RequestAborted)
            .ConfigureAwait(false);
    }
}
