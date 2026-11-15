using System.Buffers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Security;

namespace SecureProxy.Api.Proxy;

public sealed record EnvelopeReadResult(ProxyEnvelope? Envelope, ProxyRejection? Rejection, long BytesRead)
{
    public bool Succeeded => Envelope is not null;
}

public interface IEnvelopeReader
{
    Task<EnvelopeReadResult> ReadAsync(HttpRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Reads and strictly validates the request envelope. The body is read through a hard byte limit so a hostile client
/// cannot make the proxy buffer an unbounded payload, and unknown top-level members are rejected so no caller can smuggle
/// routing information (destination URL, method, path) past the configuration.
/// </summary>
public sealed partial class EnvelopeReader : IEnvelopeReader
{
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 32
    };

    private readonly IOptionsMonitor<ProxyOptions> _options;

    public EnvelopeReader(IOptionsMonitor<ProxyOptions> options)
    {
        _options = options;
    }

    public async Task<EnvelopeReadResult> ReadAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        var maxBytes = _options.CurrentValue.MaxEnvelopeBytes;

        if (!IsJsonContentType(request.ContentType))
        {
            return Reject(new ProxyRejection(StatusCodes.Status415UnsupportedMediaType, ProxyErrorCodes.UnsupportedMediaType, "Content-Type must be application/json."));
        }

        if (request.ContentLength is { } declared && declared > maxBytes)
        {
            return Reject(new ProxyRejection(StatusCodes.Status413PayloadTooLarge, ProxyErrorCodes.EnvelopeTooLarge, "Request envelope exceeds the permitted size."));
        }

        var sizeFeature = request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = maxBytes;
        }

        var buffer = new ArrayBufferWriter<byte>(4096);
        long total = 0;
        try
        {
            while (true)
            {
                var memory = buffer.GetMemory(16 * 1024);
                var read = await request.Body.ReadAsync(memory, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > maxBytes)
                {
                    return Reject(new ProxyRejection(StatusCodes.Status413PayloadTooLarge, ProxyErrorCodes.EnvelopeTooLarge, "Request envelope exceeds the permitted size."), total);
                }

                buffer.Advance(read);
            }
        }
        catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            return Reject(new ProxyRejection(StatusCodes.Status413PayloadTooLarge, ProxyErrorCodes.EnvelopeTooLarge, "Request envelope exceeds the permitted size."), total);
        }

        if (total == 0)
        {
            return Reject(ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "Request body is empty."), total);
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(buffer.WrittenMemory, DocumentOptions);
        }
        catch (JsonException)
        {
            return Reject(ProxyRejection.BadRequest(ProxyErrorCodes.InvalidJson, "Request body is not valid JSON."), total);
        }

        var parsed = Parse(document);
        if (parsed.Rejection is not null)
        {
            document.Dispose();
            return Reject(parsed.Rejection, total);
        }

        return new EnvelopeReadResult(parsed.Envelope, null, total);
    }

    private static (ProxyEnvelope? Envelope, ProxyRejection? Rejection) Parse(JsonDocument document)
    {
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            return (null, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "Request envelope must be a JSON object."));
        }

        string? clientId = null;
        JsonElement? json = null;
        EncryptedPayload? encrypted = null;
        string? idempotencyKey = null;
        List<string>? unknown = null;

        foreach (var member in root.EnumerateObject())
        {
            switch (member.Name)
            {
                case ProxyEnvelope.ClientIdMember:
                    if (member.Value.ValueKind != JsonValueKind.String)
                    {
                        return (null, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "'clientId' must be a string."));
                    }

                    clientId = member.Value.GetString();
                    break;

                case ProxyEnvelope.JsonMember:
                    if (member.Value.ValueKind != JsonValueKind.Object)
                    {
                        return (null, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "'json' must be a JSON object."));
                    }

                    json = member.Value;
                    break;

                case ProxyEnvelope.EncryptedJsonMember:
                    if (!TryReadEncrypted(member.Value, out encrypted))
                    {
                        return (null, ProxyRejection.BadRequest(ProxyErrorCodes.DecryptionFailed, "'encryptedJson' is malformed."));
                    }

                    break;

                case ProxyEnvelope.IdempotencyKeyMember:
                    if (member.Value.ValueKind != JsonValueKind.String || member.Value.GetString() is not { Length: > 0 and <= 128 } key || !IdempotencyKeyRegex().IsMatch(key))
                    {
                        return (null, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "'idempotencyKey' must be a string of 1-128 safe characters."));
                    }

                    idempotencyKey = key;
                    break;

                default:
                    (unknown ??= []).Add(member.Name.Length > 64 ? member.Name[..64] : member.Name);
                    break;
            }
        }

        if (unknown is not null)
        {
            // Fail closed: a caller cannot introduce routing information ("url", "method", "path", ...) the configuration does not know.
            return (null, ProxyRejection.BadRequest(ProxyErrorCodes.UnknownEnvelopeMember, $"Unknown envelope member(s): {string.Join(", ", unknown)}.") with { AuditDetail = "Unknown envelope member(s) present." });
        }

        if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 200 || !OperationKeyRegex().IsMatch(clientId))
        {
            return (null, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "'clientId' is required and must be a valid operation key."));
        }

        if ((json is null) == (encrypted is null))
        {
            return (null, ProxyRejection.BadRequest(ProxyErrorCodes.InvalidEnvelope, "Exactly one of 'json' or 'encryptedJson' must be supplied."));
        }

        return (ProxyEnvelope.Create(document, clientId, json, encrypted, idempotencyKey), null);
    }

    private static bool TryReadEncrypted(JsonElement element, out EncryptedPayload? payload)
    {
        payload = null;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        string? nonce = null, ciphertext = null, tag = null;
        int? keyVersion = null;
        foreach (var member in element.EnumerateObject())
        {
            switch (member.Name)
            {
                case "nonce" when member.Value.ValueKind == JsonValueKind.String:
                    nonce = member.Value.GetString();
                    break;
                case "ciphertext" when member.Value.ValueKind == JsonValueKind.String:
                    ciphertext = member.Value.GetString();
                    break;
                case "tag" when member.Value.ValueKind == JsonValueKind.String:
                    tag = member.Value.GetString();
                    break;
                case "keyVersion" when member.Value.ValueKind == JsonValueKind.Number && member.Value.TryGetInt32(out var version):
                    keyVersion = version;
                    break;
                default:
                    return false;
            }
        }

        if (string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(ciphertext) || string.IsNullOrEmpty(tag) || keyVersion is null)
        {
            return false; // keyVersion is mandatory so that rotated keys are never silently accepted
        }

        payload = new EncryptedPayload(nonce, ciphertext, tag, keyVersion);
        return true;
    }

    private static bool IsJsonContentType(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType) || !MediaTypeHeaderValue.TryParse(contentType, out var parsed))
        {
            return false;
        }

        return parsed.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
               && (parsed.Charset.Length == 0 || parsed.Charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase));
    }

    private static EnvelopeReadResult Reject(ProxyRejection rejection, long bytesRead = 0) => new(null, rejection, bytesRead);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")]
    private static partial Regex OperationKeyRegex();

    [GeneratedRegex("^[A-Za-z0-9._:-]{1,128}$")]
    private static partial Regex IdempotencyKeyRegex();
}
