namespace SecureProxy.Api.Domain;

/// <summary>
/// A configured upstream API. The proxy only ever forwards to a destination that exists in this table,
/// is enabled, and is referenced by an enabled <see cref="Operation"/>.
/// </summary>
public sealed class Destination
{
    public Guid Id { get; set; }

    /// <summary>Stable, unique, human readable identifier (e.g. <c>crm-core</c>). Also the value callers must echo as <c>urlId</c>.</summary>
    public string Key { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    /// <summary>Absolute base URL, always normalised to end with '/'. Never taken from a caller.</summary>
    public string BaseUrl { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    /// <summary>Upstream timeout applied when the operation does not override it.</summary>
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>Optional comma separated list of permitted TCP ports. Empty = any port implied by the base URL.</summary>
    public string? AllowedPorts { get; set; }

    /// <summary>How the proxy authenticates itself to the upstream (never the caller's credentials).</summary>
    public UpstreamAuthType AuthType { get; set; } = UpstreamAuthType.None;

    /// <summary>Header name used for <see cref="UpstreamAuthType.ApiKeyHeader"/>.</summary>
    public string? AuthHeaderName { get; set; }

    /// <summary>Reference to the secret (e.g. <c>cfg:crm-api-key</c>). The secret value itself is never stored.</summary>
    public string? AuthSecretReference { get; set; }

    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>Optimistic concurrency token; regenerated on every update. Exposed to admin clients as an ETag.</summary>
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");

    public ICollection<Operation> Operations { get; set; } = new List<Operation>();
}

public enum UpstreamAuthType
{
    None = 0,
    ApiKeyHeader = 1,
    BearerToken = 2
}
