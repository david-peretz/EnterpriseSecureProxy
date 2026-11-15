namespace SecureProxy.Api.Domain;

/// <summary>
/// Audit record of one execution attempt. Deliberately contains metadata only: no headers, no bodies,
/// no credentials, no key material (see DESIGN-NOTES.md, "Audit policy").
/// </summary>
public sealed class RequestLog
{
    public long Id { get; set; }

    public string CorrelationId { get; set; } = string.Empty;

    /// <summary>Operation key as supplied by the caller (truncated), even when it did not resolve.</summary>
    public string? OperationKey { get; set; }

    public Guid? OperationId { get; set; }
    public Guid? DestinationId { get; set; }
    public string? DestinationKey { get; set; }
    public string? HttpMethod { get; set; }

    public DateTime StartedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    public long? DurationMs { get; set; }

    /// <summary>True only when a request was actually sent to the upstream.</summary>
    public bool Forwarded { get; set; }

    public int? UpstreamStatusCode { get; set; }
    public int ProxyStatusCode { get; set; }

    public RequestOutcome Outcome { get; set; }

    /// <summary>Machine readable reason (e.g. <c>operation.unknown</c>). Null for successful forwards.</summary>
    public string? ReasonCode { get; set; }

    /// <summary>Short, non-sensitive human readable detail.</summary>
    public string? ReasonDetail { get; set; }

    public string? ClientAddress { get; set; }

    public long? RequestBytes { get; set; }
    public long? ResponseBytes { get; set; }
}

public enum RequestOutcome
{
    /// <summary>Record written before forwarding (mandatory audit policy); replaced by the final outcome.</summary>
    Forwarding = 0,
    /// <summary>Upstream responded (any HTTP status).</summary>
    Forwarded = 1,
    /// <summary>Rejected by validation or policy before reaching the upstream.</summary>
    Rejected = 2,
    UpstreamTimeout = 3,
    UpstreamUnreachable = 4,
    CallerCancelled = 5,
    ResponseTooLarge = 6,
    ProxyError = 7
}
