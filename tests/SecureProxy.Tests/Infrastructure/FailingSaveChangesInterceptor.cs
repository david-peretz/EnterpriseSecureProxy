using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace SecureProxy.Tests.Infrastructure;

/// <summary>Simulates an unreachable database for <b>reads</b> (configuration resolution) when armed.</summary>
public sealed class FailingReadInterceptor : DbCommandInterceptor
{
    public bool FailReads { get; set; }

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
    {
        ThrowIfArmed();
        return base.ReaderExecuting(command, eventData, result);
    }

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        ThrowIfArmed();
        return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }

    private void ThrowIfArmed()
    {
        if (FailReads)
        {
            throw new InvalidOperationException("Simulated database outage (read).");
        }
    }
}

/// <summary>
/// Lets a test simulate "SQL Server is unavailable" for writes only: when armed, every SaveChanges fails with a
/// <see cref="DbUpdateException"/>, which is what a dead connection surfaces as to the audit code.
/// Reads keep working so configuration resolution is unaffected.
/// </summary>
public sealed class FailingSaveChangesInterceptor : SaveChangesInterceptor
{
    public bool FailWrites { get; set; }

    public int FailedAttempts { get; private set; }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        ThrowIfArmed();
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        ThrowIfArmed();
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private void ThrowIfArmed()
    {
        if (FailWrites)
        {
            FailedAttempts++;
            throw new DbUpdateException("Simulated database outage.", new IOException("connection reset (simulated)"));
        }
    }
}
