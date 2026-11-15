using System.ComponentModel.DataAnnotations;

namespace SecureProxy.Api.Configuration;

/// <summary>Global proxy behaviour. Bound from the <c>Proxy</c> configuration section.</summary>
public sealed class ProxyOptions
{
    public const string SectionName = "Proxy";

    /// <summary>Hard cap on the size of the JSON envelope the proxy is willing to read (prevents unbounded buffering).</summary>
    [Range(1024, 64 * 1024 * 1024)]
    public long MaxEnvelopeBytes { get; set; } = 1024 * 1024;

    /// <summary>Default cap for relayed upstream response bodies when the operation does not specify one.</summary>
    [Range(1024, long.MaxValue)]
    public long DefaultMaxResponseBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>Hard upper bound for any configured timeout (protects against mis-configuration).</summary>
    [Range(1, 600)]
    public int MaxTimeoutSeconds { get; set; } = 120;

    /// <summary>How long resolved operation configuration is cached in memory.</summary>
    [Range(0, 3600)]
    public int ConfigCacheSeconds { get; set; } = 30;

    /// <summary>How long a miss (unknown operation key) is cached. Protects the database from enumeration load.</summary>
    [Range(0, 600)]
    public int NegativeCacheSeconds { get; set; } = 5;

    /// <summary>Header used to accept/emit the correlation id.</summary>
    public string CorrelationHeaderName { get; set; } = "X-Correlation-ID";

    /// <summary>HTTP methods an operation may be configured with. Anything else is rejected as invalid configuration.</summary>
    public string[] AllowedHttpMethods { get; set; } = ["GET", "POST", "PUT", "PATCH", "DELETE"];

    /// <summary>URL schemes a destination base URL may use. Production should be <c>https</c> only.</summary>
    public string[] AllowedDestinationSchemes { get; set; } = ["https"];

    /// <summary>Upstream response headers relayed to the caller in addition to per-operation response header rules.</summary>
    public string[] DefaultResponseHeaderAllowlist { get; set; } =
        ["Content-Type", "Cache-Control", "ETag", "Last-Modified", "Expires", "Vary", "Content-Language", "Retry-After"];

    /// <summary>Identifies the proxy to upstreams.</summary>
    public string UserAgent { get; set; } = "EnterpriseSecureProxy/1.0";
}

/// <summary>Audit persistence policy. Bound from the <c>Audit</c> section. See DESIGN-NOTES.md.</summary>
public sealed class AuditOptions
{
    public const string SectionName = "Audit";

    /// <summary>
    /// <see cref="AuditPersistenceMode.Mandatory"/>: a durable record is written <b>before</b> forwarding; if the database
    /// is unavailable the request is rejected with 503 and never forwarded (fail closed).
    /// <see cref="AuditPersistenceMode.Buffered"/>: the final record is queued and written asynchronously.
    /// </summary>
    public AuditPersistenceMode ForwardingPolicy { get; set; } = AuditPersistenceMode.Mandatory;

    /// <summary>Policy for rejected requests (nothing reached the upstream, so best-effort is acceptable by default).</summary>
    public AuditPersistenceMode RejectionPolicy { get; set; } = AuditPersistenceMode.Buffered;

    [Range(100, 1_000_000)]
    public int BufferCapacity { get; set; } = 10_000;

    [Range(1, 5000)]
    public int FlushBatchSize { get; set; } = 200;

    [Range(50, 60_000)]
    public int FlushIntervalMilliseconds { get; set; } = 500;
}

public enum AuditPersistenceMode
{
    Mandatory = 0,
    Buffered = 1
}

/// <summary>Admin API protection. Bound from the <c>Admin</c> section. The key itself should come from user-secrets / environment.</summary>
public sealed class AdminOptions
{
    public const string SectionName = "Admin";

    public string HeaderName { get; set; } = "X-Admin-ApiKey";

    /// <summary>When empty the admin endpoints are disabled (404).</summary>
    public string? ApiKey { get; set; }

    /// <summary>Name recorded as <c>ChangedBy</c> in configuration history.</summary>
    public string PrincipalName { get; set; } = "admin-api-key";
}

/// <summary>Rate limiting, bounded concurrency, circuit breaking and retry behaviour. Bound from <c>Resilience</c>.</summary>
public sealed class ResilienceOptions
{
    public const string SectionName = "Resilience";

    public bool RateLimitEnabled { get; set; } = true;

    /// <summary>Requests per window per client address.</summary>
    [Range(1, int.MaxValue)]
    public int RateLimitPermitLimit { get; set; } = 100;

    [Range(1, 3600)]
    public int RateLimitWindowSeconds { get; set; } = 1;

    /// <summary>Admin API requests per client address per minute (brute-force protection for the admin key).</summary>
    [Range(1, int.MaxValue)]
    public int AdminRateLimitPermitPerMinute { get; set; } = 60;

    /// <summary>Maximum in-flight upstream requests across all destinations. Excess requests are rejected with 503 (never queued indefinitely).</summary>
    [Range(1, 100_000)]
    public int MaxConcurrentForwards { get; set; } = 200;

    /// <summary>Consecutive transport failures (timeouts / connection errors) per destination before the circuit opens.</summary>
    [Range(1, 1000)]
    public int CircuitBreakerFailureThreshold { get; set; } = 5;

    [Range(1, 3600)]
    public int CircuitBreakerBreakSeconds { get; set; } = 30;

    /// <summary>
    /// Retry once on a connection failure (no bytes of the response received) for <b>safe</b> methods only (GET/HEAD/OPTIONS).
    /// Timeouts and non-idempotent methods are never retried by the proxy.
    /// </summary>
    public bool RetrySafeMethodsOnConnectFailure { get; set; } = true;
}

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    /// <summary>Apply pending EF Core migrations on startup (convenient for dev; use pipelines in production).</summary>
    public bool MigrateOnStartup { get; set; } = true;

    /// <summary>Insert demo destinations/operations when the configuration tables are empty.</summary>
    public bool SeedDemoData { get; set; }
}
