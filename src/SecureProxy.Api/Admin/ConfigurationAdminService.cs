using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Data;
using SecureProxy.Api.Domain;
using SecureProxy.Api.Proxy;

namespace SecureProxy.Api.Admin;

/// <summary>Thrown when an update carries a stale concurrency stamp (mapped to HTTP 409).</summary>
public sealed class ConcurrencyConflictException : Exception
{
    public ConcurrencyConflictException(string currentStamp) : base("The configuration was modified by someone else.")
    {
        CurrentStamp = currentStamp;
    }

    public string CurrentStamp { get; }
}

/// <summary>Thrown when the referenced configuration entity does not exist (mapped to HTTP 404).</summary>
public sealed class ConfigurationNotFoundException : Exception
{
    public ConfigurationNotFoundException(string message) : base(message)
    {
    }
}

/// <summary>Thrown when an administrative change would produce invalid configuration (mapped to HTTP 400).</summary>
public sealed class InvalidConfigurationChangeException : Exception
{
    public InvalidConfigurationChangeException(string message) : base(message)
    {
    }
}

public sealed record OperationAdminDto(
    Guid Id, string Key, string DestinationKey, string HttpMethod, string PathTemplate, bool IsEnabled,
    long MaxRequestBytes, long? MaxResponseBytes, int? TimeoutSeconds, bool RequiresEncryption, string? EncryptionProfileKey,
    bool AllowUnknownParameters, bool SupportsIdempotencyKey, DateTime UpdatedAtUtc, string ConcurrencyStamp);

public sealed record DestinationAdminDto(
    Guid Id, string Key, string Name, string BaseUrl, bool IsEnabled, int TimeoutSeconds, string? AllowedPorts,
    string AuthType, string? AuthHeaderName, string? AuthSecretReference, DateTime UpdatedAtUtc, string ConcurrencyStamp);

public sealed record ConfigurationChangeDto(long Id, string EntityType, Guid EntityId, string EntityKey, string Action, string ChangedBy, DateTime ChangedAtUtc, string CorrelationId, JsonElement Changes);

/// <summary>All members except <see cref="ConcurrencyStamp"/> are optional: only supplied members are changed.</summary>
public sealed record UpdateOperationRequest(
    bool? IsEnabled, string? HttpMethod, string? PathTemplate, long? MaxRequestBytes, long? MaxResponseBytes, int? TimeoutSeconds,
    bool? RequiresEncryption, bool? AllowUnknownParameters, bool? SupportsIdempotencyKey, string? ConcurrencyStamp);

public sealed record UpdateDestinationRequest(bool? IsEnabled, string? Name, string? BaseUrl, int? TimeoutSeconds, string? AllowedPorts, string? ConcurrencyStamp);

/// <summary>
/// Administrative configuration changes with optimistic concurrency and an append-only change history.
/// The expected concurrency stamp is checked explicitly (deterministic 409 for stale clients) <em>and</em> enforced by the
/// database through EF Core's concurrency token (409 for true races). Every successful change invalidates the local
/// operation cache so it takes effect immediately on this instance.
/// </summary>
public sealed class ConfigurationAdminService
{
    private static readonly string[] BodyMethods = ["POST", "PUT", "PATCH"];

    private readonly IDbContextFactory<ProxyDbContext> _contextFactory;
    private readonly IOperationCatalog _catalog;
    private readonly IOptionsMonitor<ProxyOptions> _proxyOptions;
    private readonly TimeProvider _time;
    private readonly ILogger<ConfigurationAdminService> _logger;

    public ConfigurationAdminService(IDbContextFactory<ProxyDbContext> contextFactory, IOperationCatalog catalog, IOptionsMonitor<ProxyOptions> proxyOptions, TimeProvider time, ILogger<ConfigurationAdminService> logger)
    {
        _contextFactory = contextFactory;
        _catalog = catalog;
        _proxyOptions = proxyOptions;
        _time = time;
        _logger = logger;
    }

    public async Task<IReadOnlyList<OperationAdminDto>> ListOperationsAsync(CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var operations = await db.Operations.AsNoTracking()
            .Include(o => o.Destination)
            .Include(o => o.EncryptionProfile)
            .OrderBy(o => o.Key)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return operations.Select(ToDto).ToArray();
    }

    public async Task<OperationAdminDto?> GetOperationAsync(string key, CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var operation = await db.Operations.AsNoTracking()
            .Include(o => o.Destination)
            .Include(o => o.EncryptionProfile)
            .SingleOrDefaultAsync(o => o.Key == key, cancellationToken).ConfigureAwait(false);
        return operation is null ? null : ToDto(operation);
    }

    public async Task<IReadOnlyList<DestinationAdminDto>> ListDestinationsAsync(CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var destinations = await db.Destinations.AsNoTracking().OrderBy(d => d.Key).ToListAsync(cancellationToken).ConfigureAwait(false);
        return destinations.Select(ToDto).ToArray();
    }

    public async Task<DestinationAdminDto?> GetDestinationAsync(string key, CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var destination = await db.Destinations.AsNoTracking().SingleOrDefaultAsync(d => d.Key == key, cancellationToken).ConfigureAwait(false);
        return destination is null ? null : ToDto(destination);
    }

    public async Task<OperationAdminDto> UpdateOperationAsync(string key, UpdateOperationRequest request, string expectedStamp, string changedBy, string correlationId, CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var operation = await db.Operations
            .Include(o => o.Destination)
            .Include(o => o.EncryptionProfile)
            .Include(o => o.ParameterRules)
            .SingleOrDefaultAsync(o => o.Key == key, cancellationToken).ConfigureAwait(false)
            ?? throw new ConfigurationNotFoundException($"Operation '{key}' does not exist.");

        EnsureStampMatches(operation.ConcurrencyStamp, expectedStamp);

        var changes = new Dictionary<string, object?>(StringComparer.Ordinal);
        var allowedMethods = _proxyOptions.CurrentValue.AllowedHttpMethods;

        if (request.IsEnabled is { } enabled)
        {
            Track(changes, nameof(Operation.IsEnabled), operation.IsEnabled, enabled, v => operation.IsEnabled = v);
        }

        if (request.HttpMethod is { } method)
        {
            method = method.Trim().ToUpperInvariant();
            if (!allowedMethods.Contains(method, StringComparer.Ordinal))
            {
                throw new InvalidConfigurationChangeException($"HTTP method '{method}' is not permitted. Allowed: {string.Join(", ", allowedMethods)}.");
            }

            if (!BodyMethods.Contains(method, StringComparer.Ordinal) && operation.ParameterRules.Any(r => r.Location == ParameterLocation.Body))
            {
                throw new InvalidConfigurationChangeException($"HTTP method '{method}' cannot carry a body, but the operation has body parameters.");
            }

            Track(changes, nameof(Operation.HttpMethod), operation.HttpMethod, method, v => operation.HttpMethod = v);
        }

        if (request.PathTemplate is { } template)
        {
            template = template.Trim().TrimStart('/');
            var placeholders = PlaceholderValues(template);
            var probe = UpstreamUriBuilder.Build(operation.Destination.BaseUrl, template, placeholders, [], null, null);
            if (!probe.Succeeded)
            {
                throw new InvalidConfigurationChangeException($"Path template is invalid: {probe.Error}");
            }

            var pathRules = operation.ParameterRules.Where(r => r.Location == ParameterLocation.Path).Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
            if (!pathRules.SetEquals(placeholders.Keys))
            {
                throw new InvalidConfigurationChangeException("Path template placeholders must match the operation's path parameter rules exactly.");
            }

            Track(changes, nameof(Operation.PathTemplate), operation.PathTemplate, template, v => operation.PathTemplate = v);
        }

        if (request.MaxRequestBytes is { } maxRequest)
        {
            if (maxRequest is < 1 or > 64L * 1024 * 1024)
            {
                throw new InvalidConfigurationChangeException("MaxRequestBytes must be between 1 and 67108864.");
            }

            Track(changes, nameof(Operation.MaxRequestBytes), operation.MaxRequestBytes, maxRequest, v => operation.MaxRequestBytes = v);
        }

        if (request.MaxResponseBytes is { } maxResponse)
        {
            if (maxResponse < 1)
            {
                throw new InvalidConfigurationChangeException("MaxResponseBytes must be positive.");
            }

            Track(changes, nameof(Operation.MaxResponseBytes), operation.MaxResponseBytes, maxResponse, v => operation.MaxResponseBytes = v);
        }

        if (request.TimeoutSeconds is { } timeout)
        {
            if (timeout < 1 || timeout > _proxyOptions.CurrentValue.MaxTimeoutSeconds)
            {
                throw new InvalidConfigurationChangeException($"TimeoutSeconds must be between 1 and {_proxyOptions.CurrentValue.MaxTimeoutSeconds}.");
            }

            Track(changes, nameof(Operation.TimeoutSeconds), operation.TimeoutSeconds, timeout, v => operation.TimeoutSeconds = v);
        }

        if (request.RequiresEncryption is { } requiresEncryption)
        {
            if (requiresEncryption && operation.EncryptionProfileId is null)
            {
                throw new InvalidConfigurationChangeException("An encryption profile must be assigned before encryption can be required.");
            }

            Track(changes, nameof(Operation.RequiresEncryption), operation.RequiresEncryption, requiresEncryption, v => operation.RequiresEncryption = v);
        }

        if (request.AllowUnknownParameters is { } allowUnknown)
        {
            Track(changes, nameof(Operation.AllowUnknownParameters), operation.AllowUnknownParameters, allowUnknown, v => operation.AllowUnknownParameters = v);
        }

        if (request.SupportsIdempotencyKey is { } idempotency)
        {
            Track(changes, nameof(Operation.SupportsIdempotencyKey), operation.SupportsIdempotencyKey, idempotency, v => operation.SupportsIdempotencyKey = v);
        }

        await CommitAsync(db, changes, nameof(Operation), operation.Id, operation.Key, changedBy, correlationId,
            stamp => operation.ConcurrencyStamp = stamp,
            () => operation.UpdatedAtUtc = _time.GetUtcNow().UtcDateTime,
            () => db.Operations.AsNoTracking().Where(o => o.Id == operation.Id).Select(o => o.ConcurrencyStamp).SingleAsync(CancellationToken.None),
            cancellationToken).ConfigureAwait(false);

        _catalog.Invalidate(operation.Key);
        return ToDto(operation);
    }

    public async Task<DestinationAdminDto> UpdateDestinationAsync(string key, UpdateDestinationRequest request, string expectedStamp, string changedBy, string correlationId, CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var destination = await db.Destinations.SingleOrDefaultAsync(d => d.Key == key, cancellationToken).ConfigureAwait(false)
            ?? throw new ConfigurationNotFoundException($"Destination '{key}' does not exist.");

        EnsureStampMatches(destination.ConcurrencyStamp, expectedStamp);

        var changes = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (request.IsEnabled is { } enabled)
        {
            Track(changes, nameof(Destination.IsEnabled), destination.IsEnabled, enabled, v => destination.IsEnabled = v);
        }

        if (request.Name is { } name)
        {
            name = name.Trim();
            if (name.Length is 0 or > 200)
            {
                throw new InvalidConfigurationChangeException("Name must be 1-200 characters.");
            }

            Track(changes, nameof(Destination.Name), destination.Name, name, v => destination.Name = v);
        }

        if (request.BaseUrl is { } baseUrl)
        {
            baseUrl = UpstreamUriBuilder.NormaliseBase(baseUrl);
            var probe = UpstreamUriBuilder.Build(baseUrl, string.Empty, new Dictionary<string, string>(), [], _proxyOptions.CurrentValue.AllowedDestinationSchemes, null);
            if (!probe.Succeeded)
            {
                throw new InvalidConfigurationChangeException($"Base URL is invalid: {probe.Error}");
            }

            Track(changes, nameof(Destination.BaseUrl), destination.BaseUrl, baseUrl, v => destination.BaseUrl = v);
        }

        if (request.TimeoutSeconds is { } timeout)
        {
            if (timeout < 1 || timeout > _proxyOptions.CurrentValue.MaxTimeoutSeconds)
            {
                throw new InvalidConfigurationChangeException($"TimeoutSeconds must be between 1 and {_proxyOptions.CurrentValue.MaxTimeoutSeconds}.");
            }

            Track(changes, nameof(Destination.TimeoutSeconds), destination.TimeoutSeconds, timeout, v => destination.TimeoutSeconds = v);
        }

        if (request.AllowedPorts is { } ports)
        {
            ports = ports.Trim();
            if (ports.Length > 0 && ports.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Any(p => !int.TryParse(p, out var port) || port is < 1 or > 65535))
            {
                throw new InvalidConfigurationChangeException("AllowedPorts must be a comma separated list of ports.");
            }

            Track(changes, nameof(Destination.AllowedPorts), destination.AllowedPorts, ports.Length == 0 ? null : ports, v => destination.AllowedPorts = v);
        }

        await CommitAsync(db, changes, nameof(Destination), destination.Id, destination.Key, changedBy, correlationId,
            stamp => destination.ConcurrencyStamp = stamp,
            () => destination.UpdatedAtUtc = _time.GetUtcNow().UtcDateTime,
            () => db.Destinations.AsNoTracking().Where(d => d.Id == destination.Id).Select(d => d.ConcurrencyStamp).SingleAsync(CancellationToken.None),
            cancellationToken).ConfigureAwait(false);

        // Destinations are shared by many operations: drop the whole cache rather than tracking dependants.
        _catalog.InvalidateAll();
        return ToDto(destination);
    }

    public async Task<IReadOnlyList<ConfigurationChangeDto>> GetHistoryAsync(string? entityType, string? entityKey, int take, CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        IQueryable<ConfigurationChange> query = db.ConfigurationChanges.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(entityType))
        {
            query = query.Where(c => c.EntityType == entityType);
        }

        if (!string.IsNullOrWhiteSpace(entityKey))
        {
            query = query.Where(c => c.EntityKey == entityKey);
        }

        var rows = await query.OrderByDescending(c => c.Id).Take(Math.Clamp(take, 1, 500)).ToListAsync(cancellationToken).ConfigureAwait(false);
        return rows.Select(c => new ConfigurationChangeDto(c.Id, c.EntityType, c.EntityId, c.EntityKey, c.Action.ToString(), c.ChangedBy, c.ChangedAtUtc, c.CorrelationId,
            JsonDocument.Parse(c.ChangesJson).RootElement.Clone())).ToArray();
    }

    private async Task CommitAsync(ProxyDbContext db, Dictionary<string, object?> changes, string entityType, Guid entityId, string entityKey, string changedBy, string correlationId,
        Action<string> setStamp, Action touch, Func<Task<string>> reloadStamp, CancellationToken cancellationToken)
    {
        if (changes.Count == 0)
        {
            return; // nothing changed: no new stamp, no history row
        }

        touch();
        setStamp(Guid.NewGuid().ToString("N"));
        db.ConfigurationChanges.Add(new ConfigurationChange
        {
            EntityType = entityType,
            EntityId = entityId,
            EntityKey = entityKey,
            Action = ConfigurationChangeAction.Updated,
            ChangedBy = changedBy,
            ChangedAtUtc = _time.GetUtcNow().UtcDateTime,
            CorrelationId = correlationId,
            ChangesJson = JsonSerializer.Serialize(changes)
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Lost the race between our read and write: report the stamp that is now current.
            var current = await reloadStamp().ConfigureAwait(false);
            _logger.LogInformation("Concurrency conflict updating {EntityType} {EntityKey}", entityType, entityKey);
            throw new ConcurrencyConflictException(current);
        }
    }

    private static void EnsureStampMatches(string currentStamp, string expectedStamp)
    {
        if (string.IsNullOrWhiteSpace(expectedStamp))
        {
            throw new InvalidConfigurationChangeException("A concurrency stamp is required (If-Match header or 'concurrencyStamp' member).");
        }

        if (!string.Equals(currentStamp, expectedStamp.Trim('"'), StringComparison.Ordinal))
        {
            throw new ConcurrencyConflictException(currentStamp);
        }
    }

    private static void Track<T>(Dictionary<string, object?> changes, string field, T current, T proposed, Action<T> apply)
    {
        if (EqualityComparer<T>.Default.Equals(current, proposed))
        {
            return;
        }

        changes[field] = new { from = current, to = proposed };
        apply(proposed);
    }

    private static Dictionary<string, string> PlaceholderValues(string template)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var segment in template.Split('/'))
        {
            if (segment.Length > 2 && segment[0] == '{' && segment[^1] == '}')
            {
                values[segment[1..^1]] = "probe";
            }
        }

        return values;
    }

    private static OperationAdminDto ToDto(Operation o) => new(
        o.Id, o.Key, o.Destination.Key, o.HttpMethod, o.PathTemplate, o.IsEnabled, o.MaxRequestBytes, o.MaxResponseBytes, o.TimeoutSeconds,
        o.RequiresEncryption, o.EncryptionProfile?.Key, o.AllowUnknownParameters, o.SupportsIdempotencyKey, o.UpdatedAtUtc, o.ConcurrencyStamp);

    private static DestinationAdminDto ToDto(Destination d) => new(
        d.Id, d.Key, d.Name, d.BaseUrl, d.IsEnabled, d.TimeoutSeconds, d.AllowedPorts, d.AuthType.ToString(), d.AuthHeaderName, d.AuthSecretReference, d.UpdatedAtUtc, d.ConcurrencyStamp);
}
