namespace SecureProxy.Api.Domain;

/// <summary>
/// Metadata about a payload encryption key. The key material is <b>never</b> stored here; <see cref="KeyReference"/>
/// is resolved at runtime through <c>ISecretSource</c> (environment, user-secrets, or a secret manager).
/// </summary>
public sealed class EncryptionProfile
{
    public Guid Id { get; set; }

    /// <summary>Unique profile key, e.g. <c>orders-v1</c>.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Only <c>AES-256-GCM</c> is supported in this version.</summary>
    public string Algorithm { get; set; } = EncryptionAlgorithms.Aes256Gcm;

    /// <summary>Opaque reference understood by the secret source, e.g. <c>cfg:orders-v1</c>.</summary>
    public string KeyReference { get; set; } = string.Empty;

    /// <summary>Key version callers must echo in <c>encryptedJson.keyVersion</c>, enabling rotation.</summary>
    public int KeyVersion { get; set; } = 1;

    public bool IsEnabled { get; set; } = true;

    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }

    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");
}

public static class EncryptionAlgorithms
{
    public const string Aes256Gcm = "AES-256-GCM";
}
