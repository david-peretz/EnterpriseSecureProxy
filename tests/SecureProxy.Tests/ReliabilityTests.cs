using System.Net;

using SecureProxy.Api.Domain;
using SecureProxy.Api.Proxy;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

/// <summary>Timeouts, cancellation, upstream failures, response limits and retries.</summary>
public sealed class ReliabilityTests : IClassFixture<ProxyApiFactory>
{
    private readonly ProxyApiFactory _factory;

    public ReliabilityTests(ProxyApiFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact] // Required test 13
    public async Task Upstream_timeout_returns_504_and_is_audited_as_timeout()
    {
        _factory.Upstream.DelayFor(TimeSpan.FromSeconds(30)); // slow.get has a 1 second timeout
        var correlationId = "timeout-" + Guid.NewGuid().ToString("N");

        var response = await _factory.CreateProxyClient().ExecuteAsync(
            new { clientId = "slow.get", json = new { urlId = "crm" } },
            r => r.Headers.Add("X-Correlation-ID", correlationId));

        Assert.Equal(HttpStatusCode.GatewayTimeout, response.StatusCode);
        Assert.Equal("proxy", response.Headers.GetValues("X-Proxy-Source").Single());
        Assert.Equal(ProxyErrorCodes.UpstreamTimeout, await response.ReadErrorCodeAsync());

        var upstream = Assert.Single(_factory.Upstream.Requests);
        Assert.True(upstream.CancellationObserved, "the proxy must cancel the upstream call when its timeout expires");

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome != RequestOutcome.Forwarding);
        Assert.Equal(RequestOutcome.UpstreamTimeout, record.Outcome);
        Assert.True(record.Forwarded);
        Assert.Equal(504, record.ProxyStatusCode);
        Assert.Null(record.UpstreamStatusCode);
    }

    [Fact] // Required test 15
    public async Task Caller_cancellation_is_propagated_to_the_upstream_and_distinguished_from_a_timeout()
    {
        _factory.Upstream.DelayFor(TimeSpan.FromSeconds(30));
        var correlationId = "cancel-" + Guid.NewGuid().ToString("N");
        using var cts = new CancellationTokenSource();

        var pending = _factory.CreateProxyClient().ExecuteAsync(
            new { clientId = "customer.search", json = new { urlId = "crm", q = "abc" } },
            r => r.Headers.Add("X-Correlation-ID", correlationId),
            cts.Token);

        // Wait until the mock destination is actually processing the request, then disconnect the caller.
        await WaitUntilAsync(() => _factory.Upstream.Count == 1);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        var upstream = Assert.Single(_factory.Upstream.Requests);
        await WaitUntilAsync(() => upstream.CancellationObserved);
        Assert.True(upstream.CancellationObserved);

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome != RequestOutcome.Forwarding);
        Assert.Equal(RequestOutcome.CallerCancelled, record.Outcome);
        Assert.NotEqual(RequestOutcome.UpstreamTimeout, record.Outcome);
    }

    [Theory] // Required test 14
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task Upstream_http_error_responses_are_relayed_with_their_status_and_marked_as_upstream(HttpStatusCode upstreamStatus)
    {
        _factory.Upstream.RespondWith(upstreamStatus, """{"error":"from upstream"}""");
        var correlationId = $"upstream-{(int)upstreamStatus}-" + Guid.NewGuid().ToString("N");

        var response = await _factory.CreateProxyClient().ExecuteAsync(
            new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } },
            r => r.Headers.Add("X-Correlation-ID", correlationId));

        Assert.Equal(upstreamStatus, response.StatusCode);
        Assert.Equal("upstream", response.Headers.GetValues("X-Proxy-Source").Single());
        Assert.Equal("""{"error":"from upstream"}""", await response.Content.ReadAsStringAsync());

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome == RequestOutcome.Forwarded);
        Assert.Equal((int)upstreamStatus, record.UpstreamStatusCode);
        Assert.Equal((int)upstreamStatus, record.ProxyStatusCode);
        Assert.Equal("upstream.http_error", record.ReasonCode);
    }

    [Fact]
    public async Task Connection_failure_returns_502_and_safe_methods_are_retried_exactly_once()
    {
        _factory.Upstream.FailToConnect(HttpRequestError.ConnectionError);

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } });

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal(ProxyErrorCodes.UpstreamUnreachable, await response.ReadErrorCodeAsync());
        Assert.Equal(2, _factory.Upstream.Count); // GET: one retry after a connection failure
    }

    [Fact]
    public async Task Connection_failure_never_retries_non_idempotent_methods()
    {
        _factory.Upstream.FailToConnect(HttpRequestError.ConnectionError);

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.create", json = new { urlId = "crm", customerId = Guid.NewGuid().ToString(), amount = 1 } });

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal(1, _factory.Upstream.Count); // POST: attempted once, never duplicated
    }

    [Fact]
    public async Task Upstream_response_declaring_an_oversized_body_is_rejected_before_relaying()
    {
        _factory.Upstream.RespondWith(HttpStatusCode.OK, new string('a', 5000)); // report.get allows 1024 bytes

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "report.get", json = new { urlId = "crm" } });

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal(ProxyErrorCodes.UpstreamResponseTooLarge, await response.ReadErrorCodeAsync());
    }

    [Fact]
    public async Task Oversized_streamed_response_without_content_length_is_cut_off()
    {
        // report.get allows 1024 bytes; the mock streams 5000 bytes in 400 byte chunks with no Content-Length.
        _factory.Upstream.Responder = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new DrippingContent(totalBytes: 5000, chunkSize: 400) });
        var correlationId = "oversized-" + Guid.NewGuid().ToString("N");

        var client = _factory.CreateProxyClient();
        var threw = false;
        HttpResponseMessage? response = null;
        try
        {
            response = await client.ExecuteAsync(new { clientId = "report.get", json = new { urlId = "crm" } }, r => r.Headers.Add("X-Correlation-ID", correlationId));
            await response.Content.ReadAsByteArrayAsync();
        }
        catch (Exception)
        {
            threw = true; // connection dropped mid-stream
        }

        Assert.True(threw || response!.StatusCode == HttpStatusCode.BadGateway, "the caller must never receive an oversized body as if it were complete");

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome != RequestOutcome.Forwarding);
        Assert.Equal(RequestOutcome.ResponseTooLarge, record.Outcome);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("Condition not met in time.");
            }

            await Task.Delay(20);
        }
    }

    /// <summary>HttpContent of unknown length whose body arrives in small chunks, so the proxy must stream and count.</summary>
    private sealed class DrippingContent : HttpContent
    {
        private readonly int _totalBytes;
        private readonly int _chunkSize;

        public DrippingContent(int totalBytes, int chunkSize)
        {
            _totalBytes = totalBytes;
            _chunkSize = chunkSize;
            Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        }

        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new DrippingStream(_totalBytes, _chunkSize));

        protected override async Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
        {
            await using var source = new DrippingStream(_totalBytes, _chunkSize);
            await source.CopyToAsync(stream);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class DrippingStream : Stream
    {
        private readonly int _chunkSize;
        private int _remaining;

        public DrippingStream(int totalBytes, int chunkSize)
        {
            _remaining = totalBytes;
            _chunkSize = chunkSize;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = Math.Min(Math.Min(count, _chunkSize), _remaining);
            buffer.AsSpan(offset, n).Fill((byte)'b');
            _remaining -= n;
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            var n = Math.Min(Math.Min(buffer.Length, _chunkSize), _remaining);
            buffer.Span[..n].Fill((byte)'b');
            _remaining -= n;
            return n;
        }
    }
}
