namespace SecureProxy.Api.Domain;

/// <summary>
/// Append-only history of configuration changes made through the admin API.
/// <see cref="ChangesJson"/> holds a field-level before/after diff; secret references are recorded, secret values never exist in the model.
/// </summary>
public sealed class ConfigurationChange
{
    public long Id { get; set; }

    /// <summary>Entity type name, e.g. <c>Operation</c>.</summary>
    public string EntityType { get; set; } = string.Empty;

    public Guid EntityId { get; set; }

    /// <summary>Natural key of the entity at the time of the change (operation/destination key).</summary>
    public string EntityKey { get; set; } = string.Empty;

    public ConfigurationChangeAction Action { get; set; }

    /// <summary>Identity of the administrator (API key name) that made the change.</summary>
    public string ChangedBy { get; set; } = string.Empty;

    public DateTime ChangedAtUtc { get; set; }

    public string CorrelationId { get; set; } = string.Empty;

    /// <summary>JSON object: <c>{ "field": { "from": ..., "to": ... } }</c>.</summary>
    public string ChangesJson { get; set; } = "{}";
}

public enum ConfigurationChangeAction
{
    Created = 0,
    Updated = 1,
    Deleted = 2
}
