using System.Net;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureProxy.Api.Admin;
using SecureProxy.Api.Audit;
using SecureProxy.Api.Configuration;
using SecureProxy.Api.Controllers;
using SecureProxy.Api.Data;
using SecureProxy.Api.Infrastructure;
using SecureProxy.Api.Proxy;
using SecureProxy.Api.Security;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------------------------------------------------
// Logging: structured, with scopes (correlation id) on every line. JSON in non-development environments.
// ---------------------------------------------------------------------------------------------------------------------
builder.Logging.ClearProviders();
if (builder.Environment.IsDevelopment())
{
    builder.Logging.AddSimpleConsole(o =>
    {
        o.IncludeScopes = true;
        o.TimestampFormat = "HH:mm:ss.fff ";
    });
}
else
{
    builder.Logging.AddJsonConsole(o => o.IncludeScopes = true);
}

// ---------------------------------------------------------------------------------------------------------------------
// Options (validated at startup so a mis-configured proxy never starts)
// ---------------------------------------------------------------------------------------------------------------------
builder.Services.AddOptions<ProxyOptions>().Bind(builder.Configuration.GetSection(ProxyOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<AuditOptions>().Bind(builder.Configuration.GetSection(AuditOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<AdminOptions>().Bind(builder.Configuration.GetSection(AdminOptions.SectionName));
builder.Services.AddOptions<ResilienceOptions>().Bind(builder.Configuration.GetSection(ResilienceOptions.SectionName)).ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<DatabaseOptions>().Bind(builder.Configuration.GetSection(DatabaseOptions.SectionName));

// ---------------------------------------------------------------------------------------------------------------------
// Persistence: SQL Server through EF Core. The factory is used by singletons (catalog, audit); the scoped context the
// factory registration also provides is used by request scoped code.
// ---------------------------------------------------------------------------------------------------------------------
var connectionString = builder.Configuration.GetConnectionString("ProxyDb")
    ?? throw new InvalidOperationException("ConnectionStrings:ProxyDb is not configured.");
builder.Services.AddDbContextFactory<ProxyDbContext>(options =>
    options.UseSqlServer(connectionString, sql => sql.EnableRetryOnFailure(maxRetryCount: 3, maxRetryDelay: TimeSpan.FromSeconds(2), errorNumbersToAdd: null)));

// ---------------------------------------------------------------------------------------------------------------------
// Proxy pipeline services
// ---------------------------------------------------------------------------------------------------------------------
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<ISecretSource, ConfigurationSecretSource>();
builder.Services.AddSingleton<IPayloadDecryptor, AesGcmPayloadDecryptor>();
builder.Services.AddSingleton<IEnvelopeReader, EnvelopeReader>();
builder.Services.AddSingleton<IOperationCatalog, OperationCatalog>();
builder.Services.AddSingleton<IParameterValidator, ParameterValidator>();
builder.Services.AddSingleton<IDestinationCircuitBreaker, DestinationCircuitBreaker>();
builder.Services.AddSingleton<ForwardingConcurrencyLimiter>();
builder.Services.AddSingleton<IUpstreamClient, UpstreamClient>();
builder.Services.AddSingleton<IAuditBuffer, AuditBuffer>();
builder.Services.AddSingleton<IAuditRecorder, AuditRecorder>();
builder.Services.AddHostedService<BufferedAuditWriter>();
builder.Services.AddSingleton<ProxyExecutor>();
builder.Services.AddSingleton<ConfigurationAdminService>();
builder.Services.AddSingleton<AdminApiKeyFilter>();

// One long-lived HttpClient for all upstream calls (IHttpClientFactory + SocketsHttpHandler connection pooling).
// Timeouts are enforced per request by UpstreamClient, so the client level timeout is disabled.
builder.Services.AddHttpClient(UpstreamClient.HttpClientName, client =>
    {
        client.Timeout = Timeout.InfiniteTimeSpan;
        client.DefaultRequestVersion = HttpVersion.Version11;
        client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,          // a redirect could point outside the configured destination
        UseCookies = false,                 // no shared cookie jar between callers
        AutomaticDecompression = DecompressionMethods.None,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
        ConnectTimeout = TimeSpan.FromSeconds(10),
        MaxResponseHeadersLength = 64,      // KB
        MaxConnectionsPerServer = 512
    })
    .SetHandlerLifetime(Timeout.InfiniteTimeSpan);

// ---------------------------------------------------------------------------------------------------------------------
// Rate limiting (per client address, fixed window). Bounded concurrency and circuit breaking live in the executor.
// ---------------------------------------------------------------------------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(RateLimitPolicies.PerClient, context =>
    {
        var resilience = context.RequestServices.GetRequiredService<IOptionsMonitor<ResilienceOptions>>().CurrentValue;
        if (!resilience.RateLimitEnabled)
        {
            return RateLimitPartition.GetNoLimiter("disabled");
        }

        var partitionKey = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = resilience.RateLimitPermitLimit,
            Window = TimeSpan.FromSeconds(resilience.RateLimitWindowSeconds),
            QueueLimit = 0,
            AutoReplenishment = true
        });
    });
    options.AddPolicy(RateLimitPolicies.Admin, context =>
    {
        var resilience = context.RequestServices.GetRequiredService<IOptionsMonitor<ResilienceOptions>>().CurrentValue;
        if (!resilience.RateLimitEnabled)
        {
            return RateLimitPartition.GetNoLimiter("disabled");
        }

        var partitionKey = "admin:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = resilience.AdminRateLimitPermitPerMinute,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        });
    });
    options.OnRejected = async (context, cancellationToken) =>
    {
        var correlationId = CorrelationIdMiddleware.Get(context.HttpContext);
        await context.HttpContext.WriteProblemAsync(
            new ProxyRejection(StatusCodes.Status429TooManyRequests, ProxyErrorCodes.RateLimited, "Too many requests."), correlationId);
    };
});

builder.Services.AddControllers().AddJsonOptions(o =>
{
    o.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull);
builder.Services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database");

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.Limits.MaxRequestBodySize = builder.Configuration.GetSection(ProxyOptions.SectionName).GetValue<long?>(nameof(ProxyOptions.MaxEnvelopeBytes)) ?? 1024 * 1024;
    kestrel.Limits.MaxRequestHeadersTotalSize = 64 * 1024;
});

var app = builder.Build();

// ---------------------------------------------------------------------------------------------------------------------
// Database startup work (migrations / demo seed) - skipped in tests which provision their own database.
// ---------------------------------------------------------------------------------------------------------------------
var databaseOptions = app.Services.GetRequiredService<IOptions<DatabaseOptions>>().Value;
if (databaseOptions.MigrateOnStartup || databaseOptions.SeedDemoData)
{
    await using var scope = app.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<ProxyDbContext>();
    if (databaseOptions.MigrateOnStartup && db.Database.IsSqlServer())
    {
        await db.Database.MigrateAsync();
    }

    if (databaseOptions.SeedDemoData)
    {
        await DemoDataSeeder.SeedAsync(db, scope.ServiceProvider.GetRequiredService<TimeProvider>(), CancellationToken.None);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------------------------------------------------
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseExceptionHandler(errorApp => errorApp.Run(async context =>
{
    // Last line of defence for anything outside the executor (admin API, infrastructure). Never leaks exception details.
    await context.WriteProblemAsync(
        new ProxyRejection(StatusCodes.Status500InternalServerError, ProxyErrorCodes.InternalError, "The proxy could not process the request."),
        CorrelationIdMiddleware.Get(context));
}));
app.UseRateLimiter();
app.MapControllers();
app.MapHealthChecks("/health");

app.Run();

/// <summary>Exposed so integration tests can bootstrap the application with <c>WebApplicationFactory&lt;Program&gt;</c>.</summary>
public partial class Program
{
}
