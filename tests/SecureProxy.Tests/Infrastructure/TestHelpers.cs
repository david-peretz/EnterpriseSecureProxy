using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using SecureProxy.Api.Domain;

namespace SecureProxy.Tests.Infrastructure;

public static class ProxyClientExtensions
{
    public const string ExecutePath = "/api/proxy/execute";

    /// <summary>Posts an envelope as JSON; <paramref name="configure"/> can add headers (tenant id, correlation id, ...).</summary>
    public static Task<HttpResponseMessage> ExecuteAsync(this HttpClient client, object envelope, Action<HttpRequestMessage>? configure = null, CancellationToken cancellationToken = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, ExecutePath)
        {
            Content = JsonContent.Create(envelope)
        };
        configure?.Invoke(request);
        return client.SendAsync(request, cancellationToken);
    }

    public static Task<HttpResponseMessage> ExecuteRawAsync(this HttpClient client, string body, string contentType = "application/json")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, ExecutePath)
        {
            Content = new StringContent(body, Encoding.UTF8, contentType)
        };
        return client.SendAsync(request);
    }

    public static async Task<JsonElement> ReadJsonAsync(this HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    /// <summary>Reads the machine readable error code from a proxy generated problem+json body.</summary>
    public static async Task<string?> ReadErrorCodeAsync(this HttpResponseMessage response)
    {
        var json = await response.ReadJsonAsync();
        return json.TryGetProperty("code", out var code) ? code.GetString() : null;
    }
}

/// <summary>Produces AES-256-GCM payloads exactly the way a legitimate caller would.</summary>
public static class AesGcmTestHelper
{
    public static object Encrypt(object payload, string operationKey, string keyBase64 = TestSeed.TestKeyBase64, int? keyVersion = 1, Action<byte[]>? tamperTag = null, Action<byte[]>? tamperCiphertext = null)
    {
        var key = Convert.FromBase64String(keyBase64);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload);
        return EncryptBytes(plaintext, key, operationKey, keyVersion, tamperTag, tamperCiphertext);
    }

    public static object EncryptBytes(byte[] plaintext, byte[] key, string operationKey, int? keyVersion = 1, Action<byte[]>? tamperTag = null, Action<byte[]>? tamperCiphertext = null)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(operationKey));
        }

        tamperTag?.Invoke(tag);
        tamperCiphertext?.Invoke(ciphertext);

        var encrypted = new JsonObject
        {
            ["nonce"] = Convert.ToBase64String(nonce),
            ["ciphertext"] = Convert.ToBase64String(ciphertext),
            ["tag"] = Convert.ToBase64String(tag)
        };
        if (keyVersion.HasValue)
        {
            encrypted["keyVersion"] = keyVersion.Value;
        }

        return encrypted;
    }
}

public static class AuditAssertions
{
    /// <summary>Waits (briefly) for the audit record of a correlation id to exist and returns the latest one.</summary>
    public static async Task<RequestLog> WaitForAuditAsync(ProxyApiFactory factory, string correlationId, Func<RequestLog, bool>? predicate = null, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (true)
        {
            await factory.FlushAuditAsync();
            await using var db = factory.CreateDbContext();
            var record = await db.RequestLogs.AsNoTracking()
                .Where(r => r.CorrelationId == correlationId)
                .OrderByDescending(r => r.Id)
                .FirstOrDefaultAsync();
            if (record is not null && (predicate is null || predicate(record)))
            {
                return record;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"No audit record for correlation id {correlationId} within {timeoutMs} ms.");
            }

            await Task.Delay(50);
        }
    }
}
