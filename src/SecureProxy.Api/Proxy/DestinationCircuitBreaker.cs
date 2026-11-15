using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;

namespace SecureProxy.Api.Proxy;

public interface IDestinationCircuitBreaker
{
    /// <summary>
    /// Asks permission to call the destination. Returns <c>false</c> when the circuit is open and the request must be
    /// rejected without being attempted. When it returns <c>true</c> the caller <b>must</b> finish with exactly one of
    /// <see cref="RecordSuccess"/>, <see cref="RecordFailure"/> or <see cref="Release"/> so a half-open probe slot is never leaked.
    /// </summary>
    bool TryEnter(Guid destinationId);

    void RecordSuccess(Guid destinationId);

    /// <summary>Records a transport-level failure (timeout, connection failure). HTTP error responses are <b>not</b> failures.</summary>
    void RecordFailure(Guid destinationId);

    /// <summary>The call was not made or its outcome is unknown (caller cancelled, no slot, audit unavailable): releases the probe without judging the destination.</summary>
    void Release(Guid destinationId);
}

/// <summary>
/// Minimal per-destination circuit breaker: closed → open after N consecutive transport failures → half-open after the
/// break period, admitting a single probe. A probe that is never reported back expires after the break period, so a
/// leaked slot can never latch the circuit open permanently. Intentionally dependency free; Polly /
/// Microsoft.Extensions.Http.Resilience would be the production choice and plug into the same <see cref="IDestinationCircuitBreaker"/> seam.
/// </summary>
public sealed class DestinationCircuitBreaker : IDestinationCircuitBreaker
{
    private sealed class State
    {
        public int ConsecutiveFailures;
        public long OpenedAtTicks;
        public long ProbeStartedTicks; // 0 = no probe in flight
    }

    private readonly ConcurrentDictionary<Guid, State> _states = new();
    private readonly IOptionsMonitor<ResilienceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<DestinationCircuitBreaker> _logger;

    public DestinationCircuitBreaker(IOptionsMonitor<ResilienceOptions> options, TimeProvider timeProvider, ILogger<DestinationCircuitBreaker> logger)
    {
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public bool TryEnter(Guid destinationId)
    {
        if (!_states.TryGetValue(destinationId, out var state))
        {
            return true; // never failed: closed
        }

        var openedAt = Interlocked.Read(ref state.OpenedAtTicks);
        if (openedAt == 0)
        {
            return true; // closed
        }

        var now = _timeProvider.GetUtcNow().UtcTicks;
        var breakTicks = TimeSpan.FromSeconds(_options.CurrentValue.CircuitBreakerBreakSeconds).Ticks;
        if (now - openedAt < breakTicks)
        {
            return false; // open
        }

        // Half-open: admit exactly one probe. A probe older than the break period is considered lost and replaced.
        var probeStarted = Interlocked.Read(ref state.ProbeStartedTicks);
        if (probeStarted != 0 && now - probeStarted < breakTicks)
        {
            return false;
        }

        return Interlocked.CompareExchange(ref state.ProbeStartedTicks, now, probeStarted) == probeStarted;
    }

    public void RecordSuccess(Guid destinationId)
    {
        if (_states.TryGetValue(destinationId, out var state))
        {
            var wasOpen = Interlocked.Exchange(ref state.OpenedAtTicks, 0) != 0;
            Interlocked.Exchange(ref state.ConsecutiveFailures, 0);
            Interlocked.Exchange(ref state.ProbeStartedTicks, 0);
            if (wasOpen)
            {
                _logger.LogInformation("Circuit for destination {DestinationId} closed after successful probe", destinationId);
            }
        }
    }

    public void RecordFailure(Guid destinationId)
    {
        var state = _states.GetOrAdd(destinationId, _ => new State());
        var failures = Interlocked.Increment(ref state.ConsecutiveFailures);
        Interlocked.Exchange(ref state.ProbeStartedTicks, 0);
        if (failures >= _options.CurrentValue.CircuitBreakerFailureThreshold)
        {
            var now = _timeProvider.GetUtcNow().UtcTicks;
            if (Interlocked.Exchange(ref state.OpenedAtTicks, now) == 0)
            {
                _logger.LogWarning("Circuit for destination {DestinationId} opened after {Failures} consecutive transport failures", destinationId, failures);
            }
        }
    }

    public void Release(Guid destinationId)
    {
        if (_states.TryGetValue(destinationId, out var state))
        {
            Interlocked.Exchange(ref state.ProbeStartedTicks, 0);
        }
    }
}

/// <summary>Bounded concurrency for upstream calls: when the limit is reached requests fail fast (503) instead of queueing.</summary>
public sealed class ForwardingConcurrencyLimiter : IDisposable
{
    private readonly SemaphoreSlim _semaphore;

    public ForwardingConcurrencyLimiter(IOptions<ResilienceOptions> options)
    {
        var limit = Math.Max(1, options.Value.MaxConcurrentForwards);
        _semaphore = new SemaphoreSlim(limit, limit);
    }

    public int Available => _semaphore.CurrentCount;

    /// <summary>Tries to acquire a slot, waiting at most a very short time. Returns a releaser or null when saturated.</summary>
    public async ValueTask<IDisposable?> TryAcquireAsync(CancellationToken cancellationToken)
    {
        if (await _semaphore.WaitAsync(TimeSpan.FromMilliseconds(50), cancellationToken).ConfigureAwait(false))
        {
            return new Releaser(_semaphore);
        }

        return null;
    }

    public void Dispose() => _semaphore.Dispose();

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                semaphore.Release();
            }
        }
    }
}
