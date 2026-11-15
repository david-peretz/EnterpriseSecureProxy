using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;

namespace SecureProxy.Api.Proxy;

public enum UpstreamFailure
{
    None = 0,
    Timeout,
    Unreachable,
    CallerCancelled
}

/// <summary>
/// Result of an upstream send. Owns the linked cancellation token source so the timeout keeps applying while the
/// response body is streamed to the caller; dispose it when relaying is finished.
/// </summary>
public sealed class UpstreamSendResult : IDisposable
{
    private readonly CancellationTokenSource _cts;

    public UpstreamSendResult(HttpResponseMessage? response, UpstreamFailure failure, CancellationTokenSource cts, int attempts)
    {
        Response = response;
        Failure = failure;
        _cts = cts;
        Attempts = attempts;
    }

    public HttpResponseMessage? Response { get; }
    public UpstreamFailure Failure { get; }
    public int Attempts { get; }

    /// <summary>Token that cancels on caller disconnect <em>or</em> timeout expiry.</summary>
    public CancellationToken Token => _cts.Token;

    public void Dispose()
    {
        Response?.Dispose();
        _cts.Dispose();
    }
}

public interface IUpstreamClient
{
    Task<UpstreamSendResult> SendAsync(HttpRequestMessage request, TimeSpan timeout, bool isSafeMethod, CancellationToken callerCancellation);
}

/// <summary>
/// Sends requests through a long-lived <see cref="IHttpClientFactory"/> client ("upstream"), enforcing the configured
/// timeout with a linked <see cref="CancellationTokenSource"/> so that caller cancellation and upstream timeout can be told apart.
/// Retries are limited to a single immediate retry of <b>safe</b> methods after a connection failure in which no response
/// bytes were received; timeouts and non-idempotent methods are never retried (see DESIGN-NOTES.md).
/// </summary>
public sealed class UpstreamClient : IUpstreamClient
{
    public const string HttpClientName = "upstream";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsMonitor<ResilienceOptions> _resilience;
    private readonly ILogger<UpstreamClient> _logger;

    public UpstreamClient(IHttpClientFactory httpClientFactory, IOptionsMonitor<ResilienceOptions> resilience, ILogger<UpstreamClient> logger)
    {
        _httpClientFactory = httpClientFactory;
        _resilience = resilience;
        _logger = logger;
    }

    public async Task<UpstreamSendResult> SendAsync(HttpRequestMessage request, TimeSpan timeout, bool isSafeMethod, CancellationToken callerCancellation)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(callerCancellation);
        cts.CancelAfter(timeout);
        var client = _httpClientFactory.CreateClient(HttpClientName);
        var maxAttempts = isSafeMethod && _resilience.CurrentValue.RetrySafeMethodsOnConnectFailure ? 2 : 1;

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                return new UpstreamSendResult(response, UpstreamFailure.None, cts, attempt);
            }
            catch (OperationCanceledException) when (callerCancellation.IsCancellationRequested)
            {
                return new UpstreamSendResult(null, UpstreamFailure.CallerCancelled, cts, attempt);
            }
            catch (OperationCanceledException)
            {
                // Only our own timeout can cancel at this point.
                return new UpstreamSendResult(null, UpstreamFailure.Timeout, cts, attempt);
            }
            catch (HttpRequestException ex) when (attempt < maxAttempts && IsRetriableConnectFailure(ex) && !cts.IsCancellationRequested)
            {
                _logger.LogWarning(ex, "Upstream connection failure on attempt {Attempt}; retrying once because the method is safe", attempt);
                request = Clone(request);
                continue;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogWarning(ex, "Upstream connection failure ({HttpRequestError})", ex.HttpRequestError);
                return new UpstreamSendResult(null, UpstreamFailure.Unreachable, cts, attempt);
            }
        }
    }

    /// <summary>A failure before any response bytes arrived: DNS, connect refused, TLS handshake. Safe to retry a safe method.</summary>
    private static bool IsRetriableConnectFailure(HttpRequestException ex)
        => ex.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or HttpRequestError.SecureConnectionError;

    private static HttpRequestMessage Clone(HttpRequestMessage original)
    {
        // Safe methods carry no body, so a shallow clone of headers and URI is sufficient.
        var clone = new HttpRequestMessage(original.Method, original.RequestUri) { Version = original.Version, VersionPolicy = original.VersionPolicy };
        foreach (var header in original.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        original.Dispose();
        return clone;
    }
}
