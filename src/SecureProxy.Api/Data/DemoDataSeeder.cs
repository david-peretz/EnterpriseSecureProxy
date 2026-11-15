using Microsoft.EntityFrameworkCore;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Data;

/// <summary>
/// Inserts a small, self-contained demo configuration when the configuration tables are empty
/// (enabled with <c>Database:SeedDemoData=true</c>). The demo destination is httpbin.org so a reviewer can exercise the
/// proxy end-to-end without standing up an upstream. Key material for the encrypted demo operation is read from the
/// <c>Secrets:demo-orders-v1</c> configuration value (see README.md).
/// </summary>
public static class DemoDataSeeder
{
    public static async Task SeedAsync(ProxyDbContext db, TimeProvider time, CancellationToken cancellationToken)
    {
        if (await db.Destinations.AnyAsync(cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var now = time.GetUtcNow().UtcDateTime;

        var httpbin = new Destination
        {
            Id = Guid.NewGuid(),
            Key = "httpbin",
            Name = "httpbin.org echo service",
            BaseUrl = "https://httpbin.org/",
            IsEnabled = true,
            TimeoutSeconds = 15,
            AllowedPorts = "443",
            AuthType = UpstreamAuthType.None,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        var profile = new EncryptionProfile
        {
            Id = Guid.NewGuid(),
            Key = "demo-orders-v1",
            Algorithm = EncryptionAlgorithms.Aes256Gcm,
            KeyReference = "cfg:demo-orders-v1",
            KeyVersion = 1,
            IsEnabled = true,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        var echoGet = new Operation
        {
            Id = Guid.NewGuid(),
            Key = "echo.get",
            Destination = httpbin,
            HttpMethod = "GET",
            PathTemplate = "anything/{resourceId}",
            IsEnabled = true,
            MaxRequestBytes = 64 * 1024,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            ParameterRules =
            {
                new ParameterRule { Id = Guid.NewGuid(), Name = "resourceId", Location = ParameterLocation.Path, IsRequired = true, DataType = ParameterDataType.String, MaxLength = 64, Pattern = "[A-Za-z0-9-]+" },
                new ParameterRule { Id = Guid.NewGuid(), Name = "verbose", Location = ParameterLocation.Query, IsRequired = false, DataType = ParameterDataType.Boolean }
            },
            HeaderRules =
            {
                new HeaderRule { Id = Guid.NewGuid(), HeaderName = "X-Tenant-Id", Direction = HeaderDirection.Request }
            }
        };

        var echoPost = new Operation
        {
            Id = Guid.NewGuid(),
            Key = "echo.post",
            Destination = httpbin,
            HttpMethod = "POST",
            PathTemplate = "anything/orders",
            IsEnabled = true,
            MaxRequestBytes = 64 * 1024,
            SupportsIdempotencyKey = true,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            ParameterRules =
            {
                new ParameterRule { Id = Guid.NewGuid(), Name = "customerId", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Guid },
                new ParameterRule { Id = Guid.NewGuid(), Name = "amount", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Number, MinValue = 0.01m, MaxValue = 1_000_000m },
                new ParameterRule { Id = Guid.NewGuid(), Name = "note", Location = ParameterLocation.Body, IsRequired = false, DataType = ParameterDataType.String, MaxLength = 200 }
            }
        };

        var echoSecure = new Operation
        {
            Id = Guid.NewGuid(),
            Key = "echo.secure",
            Destination = httpbin,
            HttpMethod = "POST",
            PathTemplate = "anything/secure-orders",
            IsEnabled = true,
            MaxRequestBytes = 64 * 1024,
            RequiresEncryption = true,
            EncryptionProfile = profile,
            CreatedAtUtc = now,
            UpdatedAtUtc = now,
            ParameterRules =
            {
                new ParameterRule { Id = Guid.NewGuid(), Name = "customerId", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Guid },
                new ParameterRule { Id = Guid.NewGuid(), Name = "amount", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Number, MinValue = 0.01m }
            }
        };

        var disabled = new Operation
        {
            Id = Guid.NewGuid(),
            Key = "echo.disabled",
            Destination = httpbin,
            HttpMethod = "GET",
            PathTemplate = "anything/disabled",
            IsEnabled = false,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };

        db.Destinations.Add(httpbin);
        db.EncryptionProfiles.Add(profile);
        db.Operations.AddRange(echoGet, echoPost, echoSecure, disabled);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
