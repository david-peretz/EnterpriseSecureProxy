using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Data;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Proxy;

/// <summary>
/// Immutable snapshot of everything needed to execute one operation. Built once per cache entry, so a request that
/// started with a given configuration completes with that configuration even if an administrator changes it mid-flight.
/// </summary>
public sealed class ResolvedOperation
{
    public ResolvedOperation(Operation operation)
    {
        Operation = operation;
        Destination = operation.Destination;
        EncryptionProfile = operation.EncryptionProfile;
        ParameterRules = operation.ParameterRules.OrderBy(r => r.Name, StringComparer.Ordinal).ToArray();
        RequestHeaderAllowlist = new HashSet<string>(
            operation.HeaderRules.Where(h => h.Direction == HeaderDirection.Request).Select(h => h.HeaderName),
            StringComparer.OrdinalIgnoreCase);
        ResponseHeaderAllowlist = new HashSet<string>(
            operation.HeaderRules.Where(h => h.Direction == HeaderDirection.Response).Select(h => h.HeaderName),
            StringComparer.OrdinalIgnoreCase);
    }

    public Operation Operation { get; }
    public Destination Destination { get; }
    public EncryptionProfile? EncryptionProfile { get; }
    public IReadOnlyList<ParameterRule> ParameterRules { get; }
    public IReadOnlySet<string> RequestHeaderAllowlist { get; }
    public IReadOnlySet<string> ResponseHeaderAllowlist { get; }

    public string Key => Operation.Key;

    public TimeSpan EffectiveTimeout(int maxTimeoutSeconds)
    {
        var seconds = Operation.TimeoutSeconds ?? Destination.TimeoutSeconds;
        seconds = Math.Clamp(seconds, 1, Math.Max(1, maxTimeoutSeconds));
        return TimeSpan.FromSeconds(seconds);
    }
}

public interface IOperationCatalog
{
    /// <summary>Resolves an operation by key, including its destination, rules and encryption profile. Returns null when unknown.</summary>
    ValueTask<ResolvedOperation?> ResolveAsync(string operationKey, CancellationToken cancellationToken);

    /// <summary>Removes a single operation from the local cache (called after administrative changes).</summary>
    void Invalidate(string operationKey);

    /// <summary>Removes every cached operation (e.g. after a destination or encryption profile changes).</summary>
    void InvalidateAll();
}

/// <summary>
/// Caches resolved operations in memory with a short absolute TTL.
/// Consistency model (see DESIGN-NOTES.md): changes made through the admin API on this instance are visible immediately
/// (explicit invalidation); on other instances they become visible within <see cref="ProxyOptions.ConfigCacheSeconds"/>.
/// Misses are cached briefly as well so unknown keys cannot be used to hammer the database.
/// A load that started before an invalidation is never written to the cache (per-key epoch + global generation check),
/// so a concurrent request cannot resurrect stale configuration right after an administrator changed it.
/// </summary>
public sealed class OperationCatalog : IOperationCatalog
{
    private static readonly object NegativeEntry = new();

    private readonly IDbContextFactory<ProxyDbContext> _contextFactory;
    private readonly IMemoryCache _cache;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly ILogger<OperationCatalog> _logger;
    private readonly ConcurrentDictionary<string, int> _keyEpochs = new(StringComparer.Ordinal);

    // A generation counter lets InvalidateAll() be O(1) without enumerating IMemoryCache.
    private int _generation;

    public OperationCatalog(IDbContextFactory<ProxyDbContext> contextFactory, IMemoryCache cache, IOptionsMonitor<ProxyOptions> options, ILogger<OperationCatalog> logger)
    {
        _contextFactory = contextFactory;
        _cache = cache;
        _options = options;
        _logger = logger;
    }

    public async ValueTask<ResolvedOperation?> ResolveAsync(string operationKey, CancellationToken cancellationToken)
    {
        var generation = Volatile.Read(ref _generation);
        var epoch = CurrentEpoch(operationKey);
        var cacheKey = CacheKey(generation, operationKey);
        if (_cache.TryGetValue(cacheKey, out object? cached))
        {
            return ReferenceEquals(cached, NegativeEntry) ? null : (ResolvedOperation?)cached;
        }

        var resolved = await LoadAsync(operationKey, cancellationToken).ConfigureAwait(false);

        // Only cache if nothing was invalidated while we were loading; otherwise serve the value once and let the next
        // request load fresh configuration.
        if (Volatile.Read(ref _generation) == generation && CurrentEpoch(operationKey) == epoch)
        {
            var options = _options.CurrentValue;
            var ttl = resolved is null ? options.NegativeCacheSeconds : options.ConfigCacheSeconds;
            if (ttl > 0)
            {
                _cache.Set(cacheKey, resolved is null ? NegativeEntry : resolved, new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(ttl),
                    Size = 1
                });
            }
        }

        return resolved;
    }

    public void Invalidate(string operationKey)
    {
        _keyEpochs.AddOrUpdate(operationKey, 1, (_, epoch) => epoch + 1);
        _cache.Remove(CacheKey(Volatile.Read(ref _generation), operationKey));
    }

    public void InvalidateAll() => Interlocked.Increment(ref _generation);

    private int CurrentEpoch(string operationKey) => _keyEpochs.TryGetValue(operationKey, out var epoch) ? epoch : 0;

    private static string CacheKey(int generation, string operationKey) => $"op:{generation}:{operationKey}";

    private async Task<ResolvedOperation?> LoadAsync(string operationKey, CancellationToken cancellationToken)
    {
        await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

        var operation = await db.Operations
            .AsNoTracking()
            .AsSplitQuery()
            .Include(o => o.Destination)
            .Include(o => o.EncryptionProfile)
            .Include(o => o.ParameterRules)
            .Include(o => o.HeaderRules)
            .SingleOrDefaultAsync(o => o.Key == operationKey, cancellationToken)
            .ConfigureAwait(false);

        if (operation is null)
        {
            _logger.LogDebug("Operation {OperationKey} not found", operationKey);
            return null;
        }

        return new ResolvedOperation(operation);
    }
}
