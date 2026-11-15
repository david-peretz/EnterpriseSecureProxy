using System.Security.Cryptography;
using System.Text;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Security;

/// <summary>Caller supplied encrypted payload (all fields base64).</summary>
public sealed record EncryptedPayload(string Nonce, string Ciphertext, string Tag, int? KeyVersion);

public enum DecryptionFailure
{
    None = 0,
    ProfileDisabled,
    UnsupportedAlgorithm,
    KeyUnavailable,
    KeyVersionMismatch,
    MalformedInput,
    AuthenticationFailed
}

public readonly record struct DecryptionResult(byte[]? Plaintext, DecryptionFailure Failure)
{
    public bool Succeeded => Failure == DecryptionFailure.None && Plaintext is not null;
    public static DecryptionResult Fail(DecryptionFailure failure) => new(null, failure);
}

public interface IPayloadDecryptor
{
    ValueTask<DecryptionResult> DecryptAsync(EncryptionProfile profile, string operationKey, EncryptedPayload payload, CancellationToken cancellationToken);
}

/// <summary>
/// AES-256-GCM payload decryption. The operation key is bound as additional authenticated data so a ciphertext
/// captured for one operation can never be replayed against another. Any failure is reported as a category only;
/// the executor maps every category to the same non-descriptive 400 response.
/// </summary>
public sealed class AesGcmPayloadDecryptor : IPayloadDecryptor
{
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;
    public const int KeySizeBytes = 32;

    private readonly ISecretSource _secretSource;

    public AesGcmPayloadDecryptor(ISecretSource secretSource)
    {
        _secretSource = secretSource;
    }

    public async ValueTask<DecryptionResult> DecryptAsync(EncryptionProfile profile, string operationKey, EncryptedPayload payload, CancellationToken cancellationToken)
    {
        if (!profile.IsEnabled)
        {
            return DecryptionResult.Fail(DecryptionFailure.ProfileDisabled);
        }

        if (!string.Equals(profile.Algorithm, EncryptionAlgorithms.Aes256Gcm, StringComparison.Ordinal))
        {
            return DecryptionResult.Fail(DecryptionFailure.UnsupportedAlgorithm);
        }

        if (payload.KeyVersion is null || payload.KeyVersion.Value != profile.KeyVersion)
        {
            return DecryptionResult.Fail(DecryptionFailure.KeyVersionMismatch);
        }

        if (!TryDecode(payload.Nonce, NonceSizeBytes, out var nonce) ||
            !TryDecode(payload.Tag, TagSizeBytes, out var tag) ||
            !TryDecode(payload.Ciphertext, null, out var ciphertext))
        {
            return DecryptionResult.Fail(DecryptionFailure.MalformedInput);
        }

        var key = await _secretSource.GetSecretBytesAsync(profile.KeyReference, cancellationToken).ConfigureAwait(false);
        if (key is null || key.Length != KeySizeBytes)
        {
            return DecryptionResult.Fail(DecryptionFailure.KeyUnavailable);
        }

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(operationKey));
            return new DecryptionResult(plaintext, DecryptionFailure.None);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            return DecryptionResult.Fail(DecryptionFailure.AuthenticationFailed);
        }
    }

    private static bool TryDecode(string? base64, int? expectedLength, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(base64) || base64.Length > 64 * 1024 * 1024)
        {
            return false;
        }

        var buffer = new byte[(base64.Length * 3 / 4) + 3];
        if (!Convert.TryFromBase64String(base64, buffer, out var written))
        {
            return false;
        }

        if (expectedLength.HasValue && written != expectedLength.Value)
        {
            return false;
        }

        bytes = buffer.AsSpan(0, written).ToArray();
        return true;
    }
}
