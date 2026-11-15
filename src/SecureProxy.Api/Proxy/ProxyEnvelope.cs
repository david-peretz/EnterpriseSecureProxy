using System.Text.Json;
using SecureProxy.Api.Security;

namespace SecureProxy.Api.Proxy;

/// <summary>
/// Parsed <c>POST /api/proxy/execute</c> body.
/// <code>
/// { "clientId": "customer.get", "json": { "urlId": "crm-core", "customerId": "42" } }
/// { "clientId": "order.create", "encryptedJson": { "nonce": "...", "ciphertext": "...", "tag": "...", "keyVersion": 1 } }
/// </code>
/// <c>clientId</c> is the configured operation key. <c>json</c> carries the operation parameters and <b>must</b> contain
/// <c>urlId</c>, which has to match the key of the destination bound to the operation; it is a consistency assertion and is
/// never used to pick or build a URL. Any other top-level member (<c>url</c>, <c>method</c>, <c>path</c>, ...) is rejected.
/// </summary>
public sealed class ProxyEnvelope : IDisposable
{
    public const string ClientIdMember = "clientId";
    public const string JsonMember = "json";
    public const string EncryptedJsonMember = "encryptedJson";
    public const string IdempotencyKeyMember = "idempotencyKey";
    public const string UrlIdMember = "urlId";

    private readonly JsonDocument _document;

    private ProxyEnvelope(JsonDocument document, string clientId, JsonElement? json, EncryptedPayload? encryptedJson, string? idempotencyKey)
    {
        _document = document;
        ClientId = clientId;
        Json = json;
        EncryptedJson = encryptedJson;
        IdempotencyKey = idempotencyKey;
    }

    /// <summary>The operation key.</summary>
    public string ClientId { get; }

    /// <summary>Plaintext parameters object (mutually exclusive with <see cref="EncryptedJson"/>).</summary>
    public JsonElement? Json { get; }

    public EncryptedPayload? EncryptedJson { get; }

    public string? IdempotencyKey { get; }

    public static ProxyEnvelope Create(JsonDocument document, string clientId, JsonElement? json, EncryptedPayload? encryptedJson, string? idempotencyKey)
        => new(document, clientId, json, encryptedJson, idempotencyKey);

    public void Dispose() => _document.Dispose();
}
