using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using SecureProxy.Api.Proxy;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

public sealed class RateLimitedFactory : ProxyApiFactory
{
    protected override IDictionary<string, string?> AdditionalConfiguration => new Dictionary<string, string?>
    {
        ["Resilience:RateLimitEnabled"] = "true",
        ["Resilience:RateLimitPermitLimit"] = "2",
        ["Resilience:RateLimitWindowSeconds"] = "60"
    };
}

public sealed class RateLimitingTests : IClassFixture<RateLimitedFactory>
{
    private readonly RateLimitedFactory _factory;

    public RateLimitingTests(RateLimitedFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact]
    public async Task Requests_beyond_the_per_client_limit_are_rejected_with_429_and_not_forwarded()
    {
        var client = _factory.CreateProxyClient();
        var envelope = new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } };

        Assert.Equal(HttpStatusCode.OK, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.ExecuteAsync(envelope)).StatusCode);

        var limited = await client.ExecuteAsync(envelope);

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal(ProxyErrorCodes.RateLimited, await limited.ReadErrorCodeAsync());
        Assert.True(limited.Headers.Contains("Retry-After"));
        Assert.Equal(2, _factory.Upstream.Count);
    }
}

public sealed class CircuitBreakerFactory : ProxyApiFactory
{
    /// <summary>Controllable clock so the test can move past the break period without waiting.</summary>
    public ManualTimeProvider Clock { get; } = new();

    protected override IDictionary<string, string?> AdditionalConfiguration => new Dictionary<string, string?>
    {
        ["Resilience:CircuitBreakerFailureThreshold"] = "2",
        ["Resilience:CircuitBreakerBreakSeconds"] = "60",
        ["Resilience:RetrySafeMethodsOnConnectFailure"] = "false"
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services => services.AddSingleton<TimeProvider>(Clock));
    }

    public sealed class ManualTimeProvider : TimeProvider
    {
        private long _ticks = new DateTimeOffset(2026, 11, 8, 12, 0, 0, TimeSpan.Zero).UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
        public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
    }
}

public sealed class CircuitBreakerTests : IClassFixture<CircuitBreakerFactory>
{
    private readonly CircuitBreakerFactory _factory;

    public CircuitBreakerTests(CircuitBreakerFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact]
    public async Task Circuit_opens_after_consecutive_transport_failures_and_rejects_without_calling_the_destination()
    {
        _factory.Upstream.FailToConnect();
        var client = _factory.CreateProxyClient();
        var envelope = new { clientId = "customer.search", json = new { urlId = "crm", q = "x" } };

        Assert.Equal(HttpStatusCode.BadGateway, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(HttpStatusCode.BadGateway, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(2, _factory.Upstream.Count);

        var open = await client.ExecuteAsync(envelope);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, open.StatusCode);
        Assert.Equal(ProxyErrorCodes.CircuitOpen, await open.ReadErrorCodeAsync());
        Assert.Equal(2, _factory.Upstream.Count); // the third request never reached the (dead) destination

        // After the break period a single probe goes through; when it succeeds the circuit closes again.
        _factory.Clock.Advance(TimeSpan.FromSeconds(61));
        _factory.Upstream.Reset();
        Assert.Equal(HttpStatusCode.OK, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(2, _factory.Upstream.Count);
    }

    [Fact]
    public async Task Probe_abandoned_by_a_cancelling_caller_does_not_latch_the_circuit_open()
    {
        _factory.Upstream.FailToConnect();
        var client = _factory.CreateProxyClient();
        var envelope = new { clientId = "customer.get", json = new { urlId = "crm", customerId = "7" } };

        Assert.Equal(HttpStatusCode.BadGateway, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(HttpStatusCode.BadGateway, (await client.ExecuteAsync(envelope)).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.ExecuteAsync(envelope)).StatusCode);

        // Half-open: the probe request hangs and its caller gives up.
        _factory.Clock.Advance(TimeSpan.FromSeconds(61));
        _factory.Upstream.DelayFor(TimeSpan.FromSeconds(30));
        using var cts = new CancellationTokenSource();
        var probe = client.ExecuteAsync(envelope, null, cts.Token);
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (_factory.Upstream.Count < 3 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);

        // The destination recovered; the next request must be allowed to try (the abandoned probe was released).
        _factory.Upstream.Reset();
        var recovered = await client.ExecuteAsync(envelope);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        Assert.Equal(1, _factory.Upstream.Count);
    }
}

public sealed class SingleSlotFactory : ProxyApiFactory
{
    protected override IDictionary<string, string?> AdditionalConfiguration => new Dictionary<string, string?> { ["Resilience:MaxConcurrentForwards"] = "1" };
}

public sealed class BoundedConcurrencyTests : IClassFixture<SingleSlotFactory>
{
    private readonly SingleSlotFactory _factory;

    public BoundedConcurrencyTests(SingleSlotFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact]
    public async Task Requests_beyond_the_concurrency_limit_fail_fast_with_503()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _factory.Upstream.Responder = async (_, ct) =>
        {
            await gate.Task.WaitAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
        };
        var client = _factory.CreateProxyClient();
        var envelope = new { clientId = "customer.search", json = new { urlId = "crm", q = "x" } };

        var first = client.ExecuteAsync(envelope);
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (_factory.Upstream.Count == 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        var second = await client.ExecuteAsync(envelope);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, second.StatusCode);
        Assert.Equal(ProxyErrorCodes.Overloaded, await second.ReadErrorCodeAsync());
        Assert.Equal(1, _factory.Upstream.Count);

        gate.SetResult();
        Assert.Equal(HttpStatusCode.OK, (await first).StatusCode);
    }
}
