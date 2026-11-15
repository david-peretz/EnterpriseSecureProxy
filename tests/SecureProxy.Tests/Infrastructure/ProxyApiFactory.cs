using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureProxy.Api.Audit;
using SecureProxy.Api.Data;
using SecureProxy.Api.Proxy;

namespace SecureProxy.Tests.Infrastructure;

/// <summary>
/// Boots the real application in-process with three substitutions:
/// (1) SQL Server is replaced by a private SQLite database file (relational semantics, including concurrency tokens),
/// (2) the upstream <see cref="HttpClient"/> talks to the <see cref="RecordingHandler"/> mock destination,
/// (3) secrets and admin key are supplied through in-memory configuration.
/// Everything else - middleware, controllers, executor, audit, rate limiting - is the production code path.
/// </summary>
public class ProxyApiFactory : WebApplicationFactory<Program>
{
    public const string AdminApiKey = "test-admin-key";
    public const string CrmUpstreamApiKey = "crm-upstream-secret-42";

    private readonly string _databasePath = Path.Combine(Path.GetTempPath(), $"secureproxy-tests-{Guid.NewGuid():N}.db");

    public RecordingHandler Upstream { get; } = new();

    public FailingSaveChangesInterceptor AuditFailure { get; } = new();

    public FailingReadInterceptor ReadFailure { get; } = new();

    /// <summary>Extra configuration a derived factory (or test) wants to layer on top of the defaults.</summary>
    protected virtual IDictionary<string, string?> AdditionalConfiguration => new Dictionary<string, string?>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            var settings = new Dictionary<string, string?>
            {
                ["ConnectionStrings:ProxyDb"] = "Server=unused;Database=unused;",
                ["Database:MigrateOnStartup"] = "false",
                ["Database:SeedDemoData"] = "false",
                ["Proxy:AllowedDestinationSchemes:0"] = "https",
                ["Proxy:AllowedDestinationSchemes:1"] = "http",
                ["Proxy:ConfigCacheSeconds"] = "30",
                ["Proxy:NegativeCacheSeconds"] = "0",
                ["Resilience:RateLimitEnabled"] = "false",
                ["Resilience:CircuitBreakerFailureThreshold"] = "100",
                ["Audit:ForwardingPolicy"] = "Mandatory",
                ["Audit:RejectionPolicy"] = "Buffered",
                ["Audit:FlushIntervalMilliseconds"] = "100",
                ["Admin:ApiKey"] = AdminApiKey,
                ["Secrets:test-key-v1"] = TestSeed.TestKeyBase64,
                ["Secrets:crm-api-key"] = CrmUpstreamApiKey
            };
            foreach (var (key, value) in AdditionalConfiguration)
            {
                settings[key] = value;
            }

            configuration.AddInMemoryCollection(settings);
        });

        builder.ConfigureServices(services =>
        {
            // Swap the SQL Server registration for SQLite (file based so several connections can share it).
            foreach (var descriptor in services.Where(d =>
                         d.ServiceType == typeof(DbContextOptions<ProxyDbContext>) ||
                         d.ServiceType == typeof(DbContextOptions) ||
                         d.ServiceType == typeof(IDbContextFactory<ProxyDbContext>) ||
                         d.ServiceType == typeof(ProxyDbContext)).ToList())
            {
                services.Remove(descriptor);
            }

            var connectionString = new SqliteConnectionStringBuilder { DataSource = _databasePath, Pooling = false }.ToString();
            services.AddDbContextFactory<ProxyDbContext>(options => options.UseSqlite(connectionString).AddInterceptors(AuditFailure, ReadFailure));

            // Point the upstream HttpClient at the mock destination.
            services.AddHttpClient(UpstreamClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Upstream);
        });
    }

    protected override IHost CreateHost(IHostBuilder builder)
    {
        var host = base.CreateHost(builder);
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ProxyDbContext>();
        db.Database.EnsureCreated();
        TestSeed.Seed(db);
        return host;
    }

    /// <summary>Boots the host (and seeds the database) eagerly so tests can arm failure simulations safely.</summary>
    public void EnsureStarted() => _ = Services;

    public HttpClient CreateProxyClient()
    {
        var client = CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        return client;
    }

    public HttpClient CreateAdminClient()
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-ApiKey", AdminApiKey);
        return client;
    }

    public ProxyDbContext CreateDbContext() => Services.GetRequiredService<IDbContextFactory<ProxyDbContext>>().CreateDbContext();

    /// <summary>Drops cached configuration after a test changed rows directly in the database.</summary>
    public void InvalidateConfiguration() => Services.GetRequiredService<IOperationCatalog>().InvalidateAll();

    /// <summary>Writes queued (buffered) audit records so a test can assert on them deterministically.</summary>
    public Task FlushAuditAsync() => Services.GetRequiredService<IAuditBuffer>().FlushAsync(CancellationToken.None);

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            Upstream.Dispose();
            SqliteConnection.ClearAllPools();
            try
            {
                File.Delete(_databasePath);
            }
            catch (IOException)
            {
                // best effort cleanup of the temp database
            }
        }
    }
}
