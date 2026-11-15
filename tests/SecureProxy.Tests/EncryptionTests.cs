using System.Net;
using System.Text;
using System.Text.Json;
using SecureProxy.Api.Proxy;
using SecureProxy.Tests.Infrastructure;

namespace SecureProxy.Tests;

/// <summary>AES-256-GCM payload handling. Any defect in the encrypted payload must stop the request before forwarding.</summary>
public sealed class EncryptionTests : IClassFixture<ProxyApiFactory>
{
    private readonly ProxyApiFactory _factory;
    private static readonly object ValidPayload = new { urlId = "crm", customerId = Guid.NewGuid().ToString(), amount = 250.75 };

    public EncryptionTests(ProxyApiFactory factory)
    {
        _factory = factory;
        _factory.Upstream.Reset();
    }

    [Fact]
    public async Task Valid_encrypted_payload_is_decrypted_validated_and_forwarded()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = AesGcmTestHelper.Encrypt(ValidPayload, "order.secure") });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var upstream = Assert.Single(_factory.Upstream.Requests);
        Assert.Equal("http://crm.test/api/secure/orders", upstream.Uri.ToString());
        using var sent = JsonDocument.Parse(upstream.Body!);
        Assert.Equal(250.75m, sent.RootElement.GetProperty("amount").GetDecimal());
        Assert.False(sent.RootElement.TryGetProperty("urlId", out _));
    }

    [Fact] // Required test 11
    public async Task Invalid_authentication_tag_is_rejected_and_never_forwarded()
    {
        var tampered = AesGcmTestHelper.Encrypt(ValidPayload, "order.secure", tamperTag: tag => tag[0] ^= 0xFF);

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = tampered });

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Fact] // Required test 12
    public async Task Tampered_ciphertext_is_rejected_and_never_forwarded()
    {
        var tampered = AesGcmTestHelper.Encrypt(ValidPayload, "order.secure", tamperCiphertext: ct => ct[^1] ^= 0x01);

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = tampered });

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Fact] // Required test 12
    public async Task Payload_encrypted_with_the_wrong_key_is_rejected()
    {
        var wrongKey = Convert.ToBase64String(Encoding.UTF8.GetBytes("ffffffffffffffffffffffffffffffff"));

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = AesGcmTestHelper.Encrypt(ValidPayload, "order.secure", keyBase64: wrongKey) });

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Fact] // Required test 12 - replay of a ciphertext captured for another operation
    public async Task Payload_encrypted_for_a_different_operation_is_rejected()
    {
        var forOtherOperation = AesGcmTestHelper.Encrypt(ValidPayload, "order.create");

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = forOtherOperation });

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Fact]
    public async Task Wrong_key_version_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = AesGcmTestHelper.Encrypt(ValidPayload, "order.secure", keyVersion: 2) });

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Theory] // Required test 12 - structurally invalid payloads
    [InlineData("""{ "nonce": "not base64!!", "ciphertext": "AAAA", "tag": "AAAAAAAAAAAAAAAAAAAAAA==" }""")]
    [InlineData("""{ "nonce": "AAAA", "ciphertext": "AAAA", "tag": "AAAAAAAAAAAAAAAAAAAAAA==" }""")]
    [InlineData("""{ "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAA", "tag": "AAAA" }""")]
    [InlineData("""{ "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAA" }""")]
    [InlineData("""{ "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAA", "tag": "AAAAAAAAAAAAAAAAAAAAAA==", "url": "https://evil.example" }""")]
    [InlineData("\"just-a-string\"")]
    public async Task Malformed_encrypted_payloads_are_rejected(string encryptedJson)
    {
        var body = $$"""{ "clientId": "order.secure", "encryptedJson": {{encryptedJson}} }""";

        var response = await _factory.CreateProxyClient().ExecuteRawAsync(body);

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Fact]
    public async Task Decrypted_plaintext_that_is_not_a_json_object_is_rejected()
    {
        var key = Convert.FromBase64String(TestSeed.TestKeyBase64);
        var notAnObject = AesGcmTestHelper.EncryptBytes(Encoding.UTF8.GetBytes("[1,2,3]"), key, "order.secure");

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = notAnObject });

        await AssertRejectedAsync(response, ProxyErrorCodes.DecryptionFailed);
    }

    [Fact]
    public async Task Decrypted_payload_still_goes_through_parameter_validation()
    {
        var invalid = AesGcmTestHelper.Encrypt(new { urlId = "crm", customerId = "not-a-guid", amount = -5 }, "order.secure");

        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", encryptedJson = invalid });

        await AssertRejectedAsync(response, ProxyErrorCodes.InvalidParameters);
    }

    [Fact]
    public async Task Plaintext_sent_to_an_operation_that_requires_encryption_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.secure", json = ValidPayload });

        await AssertRejectedAsync(response, ProxyErrorCodes.EncryptionRequired);
    }

    [Fact]
    public async Task Encrypted_payload_sent_to_a_plaintext_operation_is_rejected()
    {
        var response = await _factory.CreateProxyClient().ExecuteAsync(new { clientId = "order.create", encryptedJson = AesGcmTestHelper.Encrypt(ValidPayload, "order.create") });

        await AssertRejectedAsync(response, ProxyErrorCodes.EncryptionNotExpected);
    }

    private async Task AssertRejectedAsync(HttpResponseMessage response, string expectedCode)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(expectedCode, await response.ReadErrorCodeAsync());
        var text = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("AES", text);          // no cryptographic detail in public errors
        Assert.DoesNotContain("tag", text, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, _factory.Upstream.Count);
    }
}
