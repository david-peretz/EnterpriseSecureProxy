namespace SecureProxy.Api.Domain;

/// <summary>
/// Explicit header allow-list entry for an <see cref="Operation"/>. Only headers named here (plus the proxy's own
/// headers) are forwarded upstream or relayed back; hop-by-hop and credential headers can never be allow-listed.
/// </summary>
public sealed class HeaderRule
{
    public Guid Id { get; set; }

    public Guid OperationId { get; set; }
    public Operation Operation { get; set; } = null!;

    public string HeaderName { get; set; } = string.Empty;

    public HeaderDirection Direction { get; set; } = HeaderDirection.Request;
}

public enum HeaderDirection
{
    /// <summary>Caller → upstream.</summary>
    Request = 0,

    /// <summary>Upstream → caller.</summary>
    Response = 1
}
