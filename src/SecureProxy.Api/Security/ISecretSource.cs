namespace SecureProxy.Api.Security;

/// <summary>
/// Abstraction over where secrets (payload encryption keys, upstream credentials) are obtained from.
/// The database only ever stores <em>references</em>; this service turns a reference into the secret value.
/// </summary>
public interface ISecretSource
{
    /// <summary>Returns the raw secret bytes for a reference, or <c>null</c> when it cannot be resolved.</summary>
    ValueTask<byte[]?> GetSecretBytesAsync(string reference, CancellationToken cancellationToken);

    /// <summary>Returns the secret as a string (API keys, bearer tokens), or <c>null</c> when it cannot be resolved.</summary>
    ValueTask<string?> GetSecretStringAsync(string reference, CancellationToken cancellationToken);
}

/// <summary>
/// Resolves <c>cfg:&lt;name&gt;</c> references from the <c>Secrets:&lt;name&gt;</c> configuration section.
/// Because <see cref="IConfiguration"/> composes environment variables, user-secrets and (in production)
/// a secret-manager provider such as Azure Key Vault, this single implementation covers local assessment
/// and an "approved secret manager" without code changes. Key material is expected as base64.
/// Values are read on every call (no process-lifetime cache) so a rotated secret behind the same reference takes effect
/// as soon as the configuration provider exposes it; <see cref="IConfiguration"/> lookups are in-memory and cheap.
/// </summary>
public sealed class ConfigurationSecretSource : ISecretSource
{
    public const string Prefix = "cfg:";
    public const string ConfigurationSection = "Secrets";

    private readonly IConfiguration _configuration;

    public ConfigurationSecretSource(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public ValueTask<byte[]?> GetSecretBytesAsync(string reference, CancellationToken cancellationToken)
    {
        var raw = Resolve(reference);
        if (raw is null)
        {
            return ValueTask.FromResult<byte[]?>(null);
        }

        try
        {
            return ValueTask.FromResult<byte[]?>(Convert.FromBase64String(raw.Trim()));
        }
        catch (FormatException)
        {
            // Mis-configured key material is treated as "not resolvable" (fail closed); nothing about the value is logged.
            return ValueTask.FromResult<byte[]?>(null);
        }
    }

    public ValueTask<string?> GetSecretStringAsync(string reference, CancellationToken cancellationToken)
        => ValueTask.FromResult(Resolve(reference));

    private string? Resolve(string reference)
    {
        if (string.IsNullOrWhiteSpace(reference) || !reference.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var name = reference[Prefix.Length..];
        if (name.Length == 0 || name.Contains(':'))
        {
            return null;
        }

        var value = _configuration[$"{ConfigurationSection}:{name}"];
        return string.IsNullOrEmpty(value) ? null : value;
    }
}
