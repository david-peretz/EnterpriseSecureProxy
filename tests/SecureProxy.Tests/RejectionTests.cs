using System.Net;
using System.Text;
using SecureProxy.Api.Domain;
using SecureProxy.Api.Proxy;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

/// <summary>
/// Every test here proves two things: the caller receives a consistent, non-sensitive error response <b>and</b> the
/// mock destination received nothing (<c>Upstream.Count == 0</c>). A status code alone is never accepted as proof.
/// </summary>
public sealed class RejectionTests : IClassFixture<ProxyApiFactory>
{
    private readonly ProxyApiFactory _factory;

    public RejectionTests(ProxyApiFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact] // Required test 2
    public async Task Unknown_operation_is_rejected_and_not_forwarded()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.nope", json = new { urlId = "crm" } });

        await AssertRejectedAsync(response, HttpStatusCode.NotFound, ProxyErrorCodes.UnknownOperation);
    }

    [Fact] // Required test 3
    public async Task Disabled_operation_is_rejected_and_not_forwarded()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.disabled", json = new { urlId = "crm" } });

        await AssertRejectedAsync(response, HttpStatusCode.Forbidden, ProxyErrorCodes.OperationDisabled);
    }

    [Fact] // Required test 4
    public async Task Disabled_destination_is_rejected_and_not_forwarded()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "legacy.get", json = new { urlId = "legacy" } });

        await AssertRejectedAsync(response, HttpStatusCode.ServiceUnavailable, ProxyErrorCodes.DestinationUnavailable);
    }

    [Theory] // Required test 5
    [InlineData("destinationUrl")]
    [InlineData("baseUrl")]
    [InlineData("url")]
    [InlineData("method")]
    [InlineData("path")]
    public async Task Caller_supplied_routing_information_cannot_override_configuration(string memberName)
    {
        var body = $$"""{ "clientId": "customer.get", "{{memberName}}": "https://evil.example/steal", "json": { "urlId": "crm", "customerId": "1" } }""";

        var response = await _factory.CreateProxyClient().ExecuteRawAsync(body);

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.UnknownEnvelopeMember);
    }

    [Fact] // Required test 5 (urlId variant)
    public async Task UrlId_that_does_not_match_the_configured_destination_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "https://evil.example/", customerId = "1" } });

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.UrlIdMismatch);
    }

    [Fact]
    public async Task Missing_urlId_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { customerId = "1" } });

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.UrlIdMismatch);
    }

    [Fact] // Required test 6 (endpoint level)
    public async Task Wrong_http_method_on_the_proxy_endpoint_is_rejected()
    {
        var response = await _factory.CreateProxyClient().GetAsync(ProxyClientExtensions.ExecutePath);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Equal(0, _factory.Upstream.Count);
    }

    [Fact] // Required test 6 (configuration level)
    public async Task Operation_configured_with_a_disallowed_http_method_is_rejected_as_invalid_configuration()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "bad.method", json = new { urlId = "crm" } });

        await AssertRejectedAsync(response, HttpStatusCode.InternalServerError, ProxyErrorCodes.InvalidConfiguration);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("TRACE", body); // internal configuration detail stays in the log
    }

    [Fact] // Required test 7
    public async Task Missing_required_parameters_are_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.create", json = new { urlId = "crm", note = "no ids" } });

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidParameters);
        var json = await response.ReadJsonAsync();
        var names = json.GetProperty("errors").EnumerateArray().Select(e => e.GetProperty("name").GetString()).ToArray();
        Assert.Contains("customerId", names);
        Assert.Contains("amount", names);
    }

    [Fact] // Required test 8 (strict branch)
    public async Task Unknown_parameters_are_rejected_when_the_operation_does_not_allow_them()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1", admin = true } });

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidParameters);
        var json = await response.ReadJsonAsync();
        var error = Assert.Single(json.GetProperty("errors").EnumerateArray());
        Assert.Equal("admin", error.GetProperty("name").GetString());
        Assert.Equal("unknown", error.GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("amount", "\"12\"")]            // string where number expected
    [InlineData("amount", "0")]                 // below minimum
    [InlineData("customerId", "\"not-a-guid\"")]
    public async Task Parameters_with_wrong_type_or_range_are_rejected(string name, string rawValue)
    {
        var customerId = name == "customerId" ? rawValue : $"\"{Guid.NewGuid()}\"";
        var amount = name == "amount" ? rawValue : "10";
        var body = $$"""{ "clientId": "order.create", "json": { "urlId": "crm", "customerId": {{customerId}}, "amount": {{amount}} } }""";

        var response = await _factory.CreateProxyClient().ExecuteRawAsync(body);

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidParameters);
    }

    [Fact]
    public async Task Query_parameter_outside_allowed_values_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId = "1", include = "secrets" } });

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidParameters);
    }

    [Theory] // Required test 9
    [InlineData("../admin")]
    [InlineData("..")]
    [InlineData("42/../../admin")]
    [InlineData("..%2F..%2Fadmin")]
    [InlineData("%2e%2e/admin")]
    [InlineData("42?role=admin")]
    [InlineData("42#frag")]
    [InlineData("42\\..\\admin")]
    [InlineData("//evil.example/x")]
    [InlineData("42\r\nX-Injected: 1")]
    public async Task Path_traversal_attempts_are_rejected(string customerId)
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "customer.get", json = new { urlId = "crm", customerId } });

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidParameters);
    }

    [Fact]
    public async Task Non_json_content_type_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteRawAsync("clientId=customer.get", "application/x-www-form-urlencoded");

        await AssertRejectedAsync(response, HttpStatusCode.UnsupportedMediaType, ProxyErrorCodes.UnsupportedMediaType);
    }

    [Fact]
    public async Task Malformed_json_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteRawAsync("{ \"clientId\": ");

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidJson);
    }

    [Fact]
    public async Task Envelope_larger_than_the_configured_limit_is_rejected()
    {
        var huge = new string('x', 1024 * 1024 + 100);
        var body = $$"""{ "clientId": "customer.get", "json": { "urlId": "crm", "customerId": "{{huge}}" } }""";

        var response = await _factory.CreateProxyClient().ExecuteRawAsync(body);

        await AssertRejectedAsync(response, HttpStatusCode.RequestEntityTooLarge, ProxyErrorCodes.EnvelopeTooLarge);
    }

    [Fact]
    public async Task Request_body_larger_than_the_operation_limit_is_rejected()
    {
        // order.bulk allows unknown parameters but caps the upstream body at 512 bytes.
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.bulk", json = new { urlId = "crm", batchId = "b-2", blob = new string('z', 2000) } });

        await AssertRejectedAsync(response, HttpStatusCode.RequestEntityTooLarge, ProxyErrorCodes.RequestBodyTooLarge);
    }

    [Fact]
    public async Task Envelope_must_contain_exactly_one_payload_member()
    {
        var none = await _factory.CreateProxyClient().ExecuteRawAsync("""{ "clientId": "customer.get" }""");
        await AssertRejectedAsync(none, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidEnvelope);

        var both = await _factory.CreateProxyClient().ExecuteRawAsync("""{ "clientId": "customer.get", "json": {}, "encryptedJson": { "nonce": "AA==", "ciphertext": "AA==", "tag": "AA==", "keyVersion": 1 } }""");
        await AssertRejectedAsync(both, HttpStatusCode.BadRequest, ProxyErrorCodes.InvalidEnvelope);
    }

    [Fact]
    public async Task Error_responses_never_expose_upstream_hosts_or_internals()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "legacy.get", json = new { urlId = "legacy" } });
        var text = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain("legacy.test", text);
        Assert.DoesNotContain("Exception", text);
        Assert.DoesNotContain("   at ", text);
    }

    [Fact] // Required test 17 (rejection branch)
    public async Task Rejected_request_is_audited_as_rejected_and_not_forwarded()
    {
        var correlationId = "audit-reject-" + Guid.NewGuid().ToString("N");
        var response = await _factory.CreateProxyClient().ExecuteAsync(
            new { clientId = "customer.disabled", json = new { urlId = "crm" } },
            r => r.Headers.Add("X-Correlation-ID", correlationId));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        var record = await AuditAssertions.WaitForAuditAsync(_factory, correlationId);
        Assert.Equal(RequestOutcome.Rejected, record.Outcome);
        Assert.False(record.Forwarded);
        Assert.Equal(ProxyErrorCodes.OperationDisabled, record.ReasonCode);
        Assert.Equal(403, record.ProxyStatusCode);
        Assert.Null(record.UpstreamStatusCode);
        Assert.Equal("customer.disabled", record.OperationKey);
        Assert.Equal(0, _factory.Upstream.Count);
    }

    private async Task AssertRejectedAsync(HttpResponseMessage response, HttpStatusCode expectedStatus, string expectedCode)
    {
        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Equal("proxy", response.Headers.GetValues("X-Proxy-Source").Single());
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(expectedCode, await response.ReadErrorCodeAsync());
        Assert.Equal(0, _factory.Upstream.Count); // the destination must never have seen the request
    }
}
