using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Data;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Audit;

/// <summary>Thrown when the mandatory audit policy cannot persist a record; the executor turns it into 503 and does not forward.</summary>
public sealed class AuditUnavailableException : Exception
{
    public AuditUnavailableException(Exception inner) : base("The audit store is unavailable.", inner)
    {
    }
}

/// <summary>Handle returned by <see cref="IAuditRecorder.BeginForwardingAsync"/>; carries the pre-written row id when there is one.</summary>
public readonly record struct AuditTicket(long? PersistedId);

public interface IAuditRecorder
{
    /// <summary>
    /// Called immediately before a request is sent upstream. Under <see cref="AuditPersistenceMode.Mandatory"/> the record
    /// is written synchronously (outcome <see cref="RequestOutcome.Forwarding"/>); failure throws <see cref="AuditUnavailableException"/>.
    /// Under <see cref="AuditPersistenceMode.Buffered"/> nothing is written yet.
    /// </summary>
    Task<AuditTicket> BeginForwardingAsync(RequestLog entry, CancellationToken cancellationToken);

    /// <summary>Records the final outcome of a forwarded request (updates the pre-written row or enqueues the record).</summary>
    ValueTask CompleteForwardingAsync(AuditTicket ticket, RequestLog entry);

    /// <summary>Records a request that never reached the upstream (validation/policy rejection, proxy failure).</summary>
    ValueTask RecordRejectionAsync(RequestLog entry);
}

/// <summary>Bounded in-memory queue drained by <see cref="BufferedAuditWriter"/>.</summary>
public interface IAuditBuffer
{
    /// <summary>Enqueues a record; returns false (and counts a drop) when the buffer is full.</summary>
    bool TryEnqueue(RequestLog entry);

    /// <summary>Writes everything currently queued. Used by the background writer and by tests for determinism.</summary>
    Task FlushAsync(CancellationToken cancellationToken);

    long DroppedCount { get; }
}

public sealed class AuditBuffer : IAuditBuffer
{
    private readonly Channel<RequestLog> _channel;
    private readonly IDbContextFactory<ProxyDbContext> _contextFactory;
    private readonly IOptionsMonitor<AuditOptions> _options;
    private readonly ILogger<AuditBuffer> _logger;
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private long _dropped;

    public AuditBuffer(IDbContextFactory<ProxyDbContext> contextFactory, IOptions<AuditOptions> initialOptions, IOptionsMonitor<AuditOptions> options, ILogger<AuditBuffer> logger)
    {
        _contextFactory = contextFactory;
        _options = options;
        _logger = logger;
        _channel = Channel.CreateBounded<RequestLog>(new BoundedChannelOptions(Math.Max(100, initialOptions.Value.BufferCapacity))
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = false,
            SingleWriter = false
        });
    }

    public long DroppedCount => Interlocked.Read(ref _dropped);

    public bool TryEnqueue(RequestLog entry)
    {
        if (_channel.Writer.TryWrite(entry))
        {
            return true;
        }

        var dropped = Interlocked.Increment(ref _dropped);
        if (dropped == 1 || dropped % 1000 == 0)
        {
            _logger.LogError("Audit buffer full; {Dropped} audit records dropped so far (correlation {CorrelationId})", dropped, entry.CorrelationId);
        }

        return false;
    }

    public async Task FlushAsync(CancellationToken cancellationToken)
    {
        await _flushLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var batchSize = Math.Max(1, _options.CurrentValue.FlushBatchSize);
            while (true)
            {
                var batch = new List<RequestLog>(batchSize);
                while (batch.Count < batchSize && _channel.Reader.TryRead(out var item))
                {
                    batch.Add(item);
                }

                if (batch.Count == 0)
                {
                    return;
                }

                await WriteBatchAsync(batch, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _flushLock.Release();
        }
    }

    private async Task WriteBatchAsync(List<RequestLog> batch, CancellationToken cancellationToken)
    {
        const int maxAttempts = 3;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
                db.RequestLogs.AddRange(batch);
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException && attempt < maxAttempts)
            {
                _logger.LogWarning(ex, "Audit batch write failed (attempt {Attempt}/{Max}); retrying", attempt, maxAttempts);
                await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Interlocked.Add(ref _dropped, batch.Count);
                _logger.LogError(ex, "Audit batch of {Count} records dropped after {Max} failed attempts", batch.Count, maxAttempts);
                return;
            }
        }
    }
}

/// <summary>Periodically flushes the <see cref="IAuditBuffer"/>; flushes once more on graceful shutdown.</summary>
public sealed class BufferedAuditWriter : BackgroundService
{
    private readonly IAuditBuffer _buffer;
    private readonly IOptionsMonitor<AuditOptions> _options;
    private readonly ILogger<BufferedAuditWriter> _logger;

    public BufferedAuditWriter(IAuditBuffer buffer, IOptionsMonitor<AuditOptions> options, ILogger<BufferedAuditWriter> logger)
    {
        _buffer = buffer;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(_options.CurrentValue.FlushIntervalMilliseconds), stoppingToken).ConfigureAwait(false);
                await _buffer.FlushAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while flushing audit buffer");
            }
        }

        // Final best-effort flush with its own short deadline so shutdown is never blocked by a dead database.
        using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await _buffer.FlushAsync(shutdownCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Final audit flush did not complete; {Dropped} records dropped in total", _buffer.DroppedCount);
        }
    }
}

/// <summary>
/// Implements the documented audit policy:
/// forwarded executions are audited <b>mandatorily</b> by default (durable "Forwarding" row before the upstream call,
/// updated afterwards), rejections are audited <b>buffered/best-effort</b> by default. Both policies are configurable.
/// </summary>
public sealed class AuditRecorder : IAuditRecorder
{
    private readonly IDbContextFactory<ProxyDbContext> _contextFactory;
    private readonly IAuditBuffer _buffer;
    private readonly IOptionsMonitor<AuditOptions> _options;
    private readonly ILogger<AuditRecorder> _logger;

    public AuditRecorder(IDbContextFactory<ProxyDbContext> contextFactory, IAuditBuffer buffer, IOptionsMonitor<AuditOptions> options, ILogger<AuditRecorder> logger)
    {
        _contextFactory = contextFactory;
        _buffer = buffer;
        _options = options;
        _logger = logger;
    }

    public async Task<AuditTicket> BeginForwardingAsync(RequestLog entry, CancellationToken cancellationToken)
    {
        if (_options.CurrentValue.ForwardingPolicy != AuditPersistenceMode.Mandatory)
        {
            return new AuditTicket(null);
        }

        entry.Outcome = RequestOutcome.Forwarding;
        try
        {
            // Deliberately not tied to the caller's cancellation: a durable "we are about to forward" record matters more
            // than reacting instantly to a disconnect at this exact moment.
            await using var db = await _contextFactory.CreateDbContextAsync(CancellationToken.None).ConfigureAwait(false);
            db.RequestLogs.Add(entry);
            await db.SaveChangesAsync(CancellationToken.None).ConfigureAwait(false);
            return new AuditTicket(entry.Id);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Mandatory audit record could not be written; request {CorrelationId} will not be forwarded", entry.CorrelationId);
            throw new AuditUnavailableException(ex);
        }
    }

    public async ValueTask CompleteForwardingAsync(AuditTicket ticket, RequestLog entry)
    {
        if (ticket.PersistedId is not { } id)
        {
            _buffer.TryEnqueue(entry);
            return;
        }

        try
        {
            await using var db = await _contextFactory.CreateDbContextAsync(CancellationToken.None).ConfigureAwait(false);
            entry.Id = id;
            db.RequestLogs.Update(entry);
            await db.SaveChangesAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The "Forwarding" row already proves the attempt happened; losing the final status is logged, not fatal.
            _logger.LogError(ex, "Audit completion update failed for request {CorrelationId} (row {RowId})", entry.CorrelationId, id);
        }
    }

    public async ValueTask RecordRejectionAsync(RequestLog entry)
    {
        if (entry.Id != 0)
        {
            // A durable row already exists for this request (mandatory "Forwarding" record): finish it instead of inserting a duplicate.
            await CompleteForwardingAsync(new AuditTicket(entry.Id), entry).ConfigureAwait(false);
            return;
        }

        if (_options.CurrentValue.RejectionPolicy == AuditPersistenceMode.Mandatory)
        {
            try
            {
                await using var db = await _contextFactory.CreateDbContextAsync(CancellationToken.None).ConfigureAwait(false);
                db.RequestLogs.Add(entry);
                await db.SaveChangesAsync(CancellationToken.None).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Nothing reached the upstream, so the caller still gets its rejection; fall back to the buffer.
                _logger.LogError(ex, "Mandatory rejection audit failed for {CorrelationId}; falling back to buffer", entry.CorrelationId);
            }
        }

        _buffer.TryEnqueue(entry);
    }
}
