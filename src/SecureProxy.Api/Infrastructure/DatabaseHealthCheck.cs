using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using SecureProxy.Api.Data;

namespace SecureProxy.Api.Infrastructure;

/// <summary>Reports whether the configuration/audit database can be reached. Degraded rather than failed: the proxy keeps serving cached configuration.</summary>
public sealed class DatabaseHealthCheck : IHealthCheck
{
    private readonly IDbContextFactory<ProxyDbContext> _contextFactory;

    public DatabaseHealthCheck(IDbContextFactory<ProxyDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var db = await _contextFactory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await db.Database.CanConnectAsync(cancellationToken).ConfigureAwait(false)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Degraded("Database not reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Degraded("Database check failed.", ex);
        }
    }
}
