using System.Net;
using Microsoft.EntityFrameworkCore;
using SecureProxy.Api.Domain;
using SecureProxy.Api.Proxy;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

/// <summary>Audit policy: mandatory audit for forwarded requests fails closed when the database is unavailable.</summary>
public sealed class AuditPolicyTests : IClassFixture<ProxyApiFactory>
{
    private readonly ProxyApiFactory _factory;

    public AuditPolicyTests(ProxyApiFactory factory)
    {
        _factory = factory;
        _factory.EnsureStarted();
        _factory.Upstream.Reset();
        _factory.AuditFailure.FailWrites = false;
        _factory.ReadFailure.FailReads = false;
    }

    [Fact] // Required test 17 + "what happens if SQL Server is unavailable"
    public async Task When_the_audit_store_is_unavailable_a_forwardable_request_is_rejected_and_never_forwarded()
    {
        _factory.AuditFailure.FailWrites = true;
        try
        {
            var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } });

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(ProxyErrorCodes.AuditUnavailable, await response.ReadErrorCodeAsync());
            Assert.Equal(0, _factory.Upstream.Count);
            Assert.True(_factory.AuditFailure.FailedAttempts > 0);
        }
        finally
        {
            _factory.AuditFailure.FailWrites = false;
        }
    }

    [Fact]
    public async Task Unresolvable_configuration_store_fails_closed_with_503()
    {
        _factory.ReadFailure.FailReads = true;
        try
        {
            // "config.never.cached" has never been resolved, so the proxy must hit the database and fail closed.
            var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "config.never.cached", json = new { urlId = "crm" } });

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(ProxyErrorCodes.ConfigurationUnavailable, await response.ReadErrorCodeAsync());
            Assert.Equal(0, _factory.Upstream.Count);
            var text = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("Simulated", text);
        }
        finally
        {
            _factory.ReadFailure.FailReads = false;
        }
    }

    [Fact]
    public async Task Rejections_are_still_answered_when_the_audit_store_is_unavailable()
    {
        _factory.AuditFailure.FailWrites = true;
        try
        {
            // Nothing can reach the upstream here, so best-effort auditing must not turn a 404 into a 503.
            var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "no.such.op", json = new { urlId = "crm" } });

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal(0, _factory.Upstream.Count);
        }
        finally
        {
            _factory.AuditFailure.FailWrites = false;
        }
    }

    [Fact]
    public async Task Mandatory_policy_writes_a_forwarding_record_before_the_upstream_call_and_completes_it_afterwards()
    {
        var correlationId = "two-phase-" + Guid.NewGuid().ToString("N");
        var observedDuringUpstreamCall = (RequestOutcome?)null;

        _factory.Upstream.Responder = async (_, _) =>
        {
            // While the upstream is "processing", the durable audit row must already exist.
            await using var db = _factory.CreateDbContext();
            var row = await db.RequestLogs.AsNoTracking().SingleOrDefaultAsync(r => r.CorrelationId == correlationId);
            observedDuringUpstreamCall = row?.Outcome;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json") };
        };

        var response = await _factory.CreateProxyClient().ExecuteAsync(
            new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } },
            r => r.Headers.Add("X-Correlation-ID", correlationId));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(RequestOutcome.Forwarding, observedDuringUpstreamCall);

        var final = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome == RequestOutcome.Forwarded);
        await using var verify = _factory.CreateDbContext();
        Assert.Equal(1, await verify.RequestLogs.CountAsync(r => r.CorrelationId == correlationId)); // same row, updated in place
        Assert.Equal(200, final.UpstreamStatusCode);
    }

    [Fact]
    public async Task Audit_records_never_contain_headers_bodies_or_secrets()
    {
        var correlationId = "no-secrets-" + Guid.NewGuid().ToString("N");
        var secretNote = "card=4111111111111111";

        var response = await _factory.CreateProxyClient().ExecuteAsync(
            new { clientId = "order.create", json = new { urlId = "crm", customerId = Guid.NewGuid().ToString(), amount = 5, note = secretNote } },
            r =>
            {
                r.Headers.Add("X-Correlation-ID", correlationId);
                r.Headers.Add("Authorization", "Bearer caller-token-should-never-be-stored");
            });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome == RequestOutcome.Forwarded);
        var serialized = System.Text.Json.JsonSerializer.Serialize(record);
        Assert.DoesNotContain("4111", serialized);
        Assert.DoesNotContain("caller-token", serialized);
        Assert.DoesNotContain(ProxyApiFactory.CrmUpstreamApiKey, serialized);

        // ...and the caller's Authorization header never went upstream either.
        Assert.False(Assert.Single(_factory.Upstream.Requests).HasHeader("Authorization"));
    }
}

/// <summary>Buffered forwarding policy: availability over audit durability (documented trade-off).</summary>
public sealed class BufferedAuditFactory : ProxyApiFactory
{
    protected override IDictionary<string, string?> AdditionalConfiguration => new Dictionary<string, string?> { ["Audit:ForwardingPolicy"] = "Buffered" };
}

public sealed class BufferedAuditPolicyTests : IClassFixture<BufferedAuditFactory>
{
    private readonly BufferedAuditFactory _factory;

    public BufferedAuditPolicyTests(BufferedAuditFactory factory)
    {
        _factory = factory;
        _factory.EnsureStarted();
        _factory.Upstream.Reset();
        _factory.AuditFailure.FailWrites = false;
    }

    [Fact]
    public async Task Buffered_policy_forwards_even_when_the_audit_store_is_down_and_persists_later()
    {
        var correlationId = "buffered-" + Guid.NewGuid().ToString("N");
        _factory.AuditFailure.FailWrites = true;
        try
        {
            var response = await _factory.CreateProxyClient().ExecuteAsync(
                new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } },
                r => r.Headers.Add("X-Correlation-ID", correlationId));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(1, _factory.Upstream.Count);
        }
        finally
        {
            _factory.AuditFailure.FailWrites = false;
        }

        // Once the store is back, the queued record is written by the background writer.
        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId);
        Assert.Equal(RequestOutcome.Forwarded, record.Outcome);
    }
}
