using System.Net;
using System.Text.Json;
using SecureProxy.Api.Domain;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

/// <summary>Happy-path behaviour: configured operations are forwarded exactly as configured.</summary>
public sealed class ForwardingTests : IClassFixture<ProxyApiFactory>
{
    private readonly ProxyApiFactory _factory;

    public ForwardingTests(ProxyApiFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact] // Required test 1
    public async Task Valid_configured_operation_is_forwarded_to_the_configured_destination()
    {
        var client = _factory.CreateProxyClient();

        var response = await client.ExecuteAsync(
            new { clientId = "customer.get", json = new { urlId = "crm", customerId = "42", include = "orders" } },
            r =>
            {
                r.Headers.Add("X-Correlation-ID", "fwd-0001");
                r.Headers.Add("X-Tenant-Id", "tenant-7");
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("upstream", response.Headers.GetValues("X-Proxy-Source").Single());
        Assert.Equal("fwd-0001", response.Headers.GetValues("X-Correlation-ID").Single());

        var body = await response.ReadJsonAsync();
        Assert.True(body.GetProperty("echo").GetBoolean());

        var upstream = Assert.Single(_factory.Upstream.Requests);
        Assert.Equal("GET", upstream.Method);
        Assert.Equal("http://crm.test/api/customers/42?include=orders", upstream.Uri.ToString());
        Assert.Equal("tenant-7", upstream.Header("X-Tenant-Id"));
        Assert.Equal("fwd-0001", upstream.Header("X-Correlation-ID"));
        Assert.Equal(ProxyApiFactory.CrmUpstreamApiKey, upstream.Header("X-Upstream-Key")); // proxy's own credential, resolved from the secret source
        Assert.Null(upstream.Body);
    }

    [Fact]
    public async Task Post_operation_sends_validated_body_parameters_and_idempotency_key()
    {
        var client = _factory.CreateProxyClient();
        var customerId = Guid.NewGuid();

        var response = await client.ExecuteAsync(new
        {
            clientId = "order.create",
            idempotencyKey = "idem-123",
            json = new { urlId = "crm", customerId = customerId.ToString(), amount = 12.5, note = "first" }
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var upstream = Assert.Single(_factory.Upstream.Requests);
        Assert.Equal("POST", upstream.Method);
        Assert.Equal("http://crm.test/api/orders", upstream.Uri.ToString());
        Assert.StartsWith("application/json", upstream.ContentType);
        Assert.Equal("idem-123", upstream.Header("Idempotency-Key"));

        using var sent = JsonDocument.Parse(upstream.Body!);
        Assert.Equal(customerId.ToString(), sent.RootElement.GetProperty("customerId").GetString());
        Assert.Equal(12.5m, sent.RootElement.GetProperty("amount").GetDecimal());
        Assert.Equal("first", sent.RootElement.GetProperty("note").GetString());
        Assert.False(sent.RootElement.TryGetProperty("urlId", out _)); // never forwarded
    }

    [Fact]
    public async Task Idempotency_key_is_not_forwarded_when_operation_does_not_support_it()
    {
        var client = _factory.CreateProxyClient();

        var response = await client.ExecuteAsync(new { clientId = "customer.get", idempotencyKey = "idem-999", json = new { urlId = "crm", customerId = "1" } });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(Assert.Single(_factory.Upstream.Requests).HasHeader("Idempotency-Key"));
    }

    [Fact] // Required test 8 (allowed branch)
    public async Task Unknown_parameters_are_forwarded_when_the_operation_explicitly_allows_them()
    {
        var client = _factory.CreateProxyClient();

        var response = await client.ExecuteAsync(new { clientId = "order.bulk", json = new { urlId = "crm", batchId = "b-1", extra = "value", nested = new { a = 1 } } });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var upstream = Assert.Single(_factory.Upstream.Requests);
        using var sent = JsonDocument.Parse(upstream.Body!);
        Assert.Equal("b-1", sent.RootElement.GetProperty("batchId").GetString());
        Assert.Equal("value", sent.RootElement.GetProperty("extra").GetString());
        Assert.Equal(1, sent.RootElement.GetProperty("nested").GetProperty("a").GetInt32());
    }

    [Fact] // Required test 10
    public async Task Disallowed_headers_are_not_forwarded_even_when_present_on_the_request()
    {
        var client = _factory.CreateProxyClient();

        var response = await client.ExecuteAsync(
            new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } },
            r =>
            {
                r.Headers.TryAddWithoutValidation("Authorization", "Bearer caller-secret");
                r.Headers.TryAddWithoutValidation("Cookie", "session=abc");
                r.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.9");
                r.Headers.TryAddWithoutValidation("X-Api-Key", "caller-api-key");
                r.Headers.TryAddWithoutValidation("X-Not-Allowlisted", "should-not-pass");
                r.Headers.TryAddWithoutValidation("X-Tenant-Id", "tenant-1");
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var upstream = Assert.Single(_factory.Upstream.Requests);
        Assert.Equal("tenant-1", upstream.Header("X-Tenant-Id"));
        foreach (var blocked in new[] { "Authorization", "Cookie", "X-Forwarded-For", "X-Api-Key", "X-Not-Allowlisted" })
        {
            Assert.False(upstream.HasHeader(blocked), $"{blocked} must not be forwarded");
        }

        // The only credential on the upstream request is the proxy's own destination credential.
        Assert.Equal(ProxyApiFactory.CrmUpstreamApiKey, upstream.Header("X-Upstream-Key"));
    }

    [Fact]
    public async Task Upstream_response_headers_are_relayed_only_when_allow_listed()
    {
        var client = _factory.CreateProxyClient();

        var response = await client.ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1" } });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("41", response.Headers.GetValues("X-RateLimit-Remaining").Single()); // operation response allow-list
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);   // default allow-list
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.False(response.Headers.Contains("Server"));
        Assert.False(response.Headers.Contains("X-Internal-Trace"));
    }

    [Fact]
    public async Task Successful_forward_creates_an_audit_record_with_metadata_only()
    {
        var client = _factory.CreateProxyClient();
        var correlationId = "audit-success-" + Guid.NewGuid().ToString("N");

        var response = await client.ExecuteAsync(
            new { clientId = "customer.get", json = new { urlId = "crm", customerId = "77" } },
            r => r.Headers.Add("X-Correlation-ID", correlationId));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId, r => r.Outcome == RequestOutcome.Forwarded);
        Assert.True(record.Forwarded);
        Assert.Equal("customer.get", record.OperationKey);
        Assert.Equal("crm", record.DestinationKey);
        Assert.Equal(200, record.UpstreamStatusCode);
        Assert.Equal(200, record.ProxyStatusCode);
        Assert.NotNull(record.CompletedAtUtc);
        Assert.NotNull(record.DurationMs);
        Assert.Null(record.ReasonCode);
        Assert.DoesNotContain("77", record.ReasonDetail ?? string.Empty); // no payload data in audit
    }
}
