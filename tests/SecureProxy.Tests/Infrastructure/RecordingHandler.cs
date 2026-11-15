using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace SecureProxy.Tests.Infrastructure;

/// <summary>Everything the mock destination saw for one upstream request.</summary>
public sealed class RecordedRequest
{
    public required string Method { get; init; }
    public required Uri Uri { get; init; }
    public required IReadOnlyDictionary<string, string[]> Headers { get; init; }
    public string? ContentType { get; init; }
    public string? Body { get; init; }

    /// <summary>Set when the proxy cancelled the upstream call while the mock was still "processing".</summary>
    public bool CancellationObserved { get; set; }

    public bool HasHeader(string name) => Headers.Keys.Any(k => string.Equals(k, name, StringComparison.OrdinalIgnoreCase));

    public string? Header(string name) => Headers.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value?.FirstOrDefault();
}

/// <summary>
/// The mock destination service. It is installed as the primary <see cref="HttpMessageHandler"/> of the proxy's upstream
/// <see cref="HttpClient"/>, records <b>every</b> request it receives and answers with a scripted response.
/// Tests assert on <see cref="Requests"/> to prove that rejected requests never reached the destination.
/// </summary>
public sealed class RecordingHandler : HttpMessageHandler
{
    private readonly ConcurrentQueue<RecordedRequest> _requests = new();

    public IReadOnlyCollection<RecordedRequest> Requests => _requests.ToArray();

    public int Count => _requests.Count;

    /// <summary>Scripted behaviour; defaults to a 200 JSON echo of the request.</summary>
    public Func<RecordedRequest, CancellationToken, Task<HttpResponseMessage>> Responder { get; set; } = EchoAsync;

    public void Reset()
    {
        _requests.Clear();
        Responder = EchoAsync;
    }

    public void RespondWith(HttpStatusCode status, string body = "{}", string contentType = "application/json", Action<HttpResponseMessage>? configure = null)
        => Responder = (_, _) =>
        {
            var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, contentType) };
            configure?.Invoke(response);
            return Task.FromResult(response);
        };

    /// <summary>Simulates a slow upstream; honours the proxy's cancellation token and records that it fired.</summary>
    public void DelayFor(TimeSpan delay)
        => Responder = async (recorded, ct) =>
        {
            try
            {
                await Task.Delay(delay, ct);
            }
            catch (OperationCanceledException)
            {
                recorded.CancellationObserved = true;
                throw;
            }

            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"slow\":true}", Encoding.UTF8, "application/json") };
        };

    /// <summary>Simulates a transport failure (nothing listening at the destination) with the given classification.</summary>
    public void FailToConnect(HttpRequestError error = HttpRequestError.ConnectionError)
        => Responder = (_, _) => throw new HttpRequestException(error, "connection refused (simulated)", new IOException("simulated"));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in request.Headers)
        {
            headers[header.Key] = header.Value.ToArray();
        }

        string? body = null;
        string? contentType = null;
        if (request.Content is not null)
        {
            foreach (var header in request.Content.Headers)
            {
                headers[header.Key] = header.Value.ToArray();
            }

            contentType = request.Content.Headers.ContentType?.ToString();
            body = await request.Content.ReadAsStringAsync(cancellationToken);
        }

        var recorded = new RecordedRequest
        {
            Method = request.Method.Method,
            Uri = request.RequestUri!,
            Headers = headers,
            ContentType = contentType,
            Body = body
        };
        _requests.Enqueue(recorded);

        return await Responder(recorded, cancellationToken);
    }

    private static Task<HttpResponseMessage> EchoAsync(RecordedRequest recorded, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"echo\":true,\"method\":\"{recorded.Method}\",\"path\":\"{recorded.Uri.PathAndQuery}\"}}", Encoding.UTF8, "application/json")
        };
        response.Headers.TryAddWithoutValidation("X-RateLimit-Remaining", "41");
        response.Headers.TryAddWithoutValidation("Set-Cookie", "session=secret; HttpOnly");
        response.Headers.TryAddWithoutValidation("Server", "upstream-server/9.9");
        response.Headers.TryAddWithoutValidation("X-Internal-Trace", "node-17");
        return Task.FromResult(response);
    }
}
