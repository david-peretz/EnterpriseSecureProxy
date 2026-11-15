namespace SecureProxy.Api.Domain;

/// <summary>
/// An explicitly allowed action. Everything that decides <em>where</em> and <em>how</em> a request is forwarded
/// (destination, HTTP method, path template, limits) lives here and is never taken from the caller.
/// </summary>
public sealed class Operation
{
    public Guid Id { get; set; }

    /// <summary>Unique operation key, e.g. <c>customer.get</c>. Callers reference it as <c>clientId</c>.</summary>
    public string Key { get; set; } = string.Empty;

    public Guid DestinationId { get; set; }
    public Destination Destination { get; set; } = null!;

    /// <summary>Upper-case HTTP method (GET, POST, PUT, PATCH, DELETE).</summary>
    public string HttpMethod { get; set; } = "GET";

    /// <summary>
    /// Relative path template, e.g. <c>customers/{customerId}</c>. Placeholders must occupy a whole path segment
    /// and are bound from <see cref="ParameterLocation.Path"/> parameters only.
    /// </summary>
    public string PathTemplate { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    /// <summary>Maximum size of the upstream request body built by the proxy.</summary>
    public long MaxRequestBytes { get; set; } = 256 * 1024;

    /// <summary>Maximum size of the upstream response body relayed to the caller. Null = proxy default.</summary>
    public long? MaxResponseBytes { get; set; }

    /// <summary>Per-operation upstream timeout override. Null = destination timeout.</summary>
    public int? TimeoutSeconds { get; set; }

    /// <summary>When true the caller must send <c>encryptedJson</c> (AES-256-GCM) instead of <c>json</c>.</summary>
    public bool RequiresEncryption { get; set; }

    public Guid? EncryptionProfileId { get; set; }
    public EncryptionProfile? EncryptionProfile { get; set; }

    /// <summary>When false (default) any parameter not described by a <see cref="ParameterRule"/> is rejected.</summary>
    public bool AllowUnknownParameters { get; set; }

    /// <summary>When true a caller supplied <c>idempotencyKey</c> is forwarded as the <c>Idempotency-Key</c> header.</summary>
    public bool SupportsIdempotencyKey { get; set; }

    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>Optimistic concurrency token; regenerated on every update. Exposed to admin clients as an ETag.</summary>
    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");

    public ICollection<ParameterRule> ParameterRules { get; set; } = new List<ParameterRule>();
    public ICollection<HeaderRule> HeaderRules { get; set; } = new List<HeaderRule>();
}
