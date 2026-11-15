using SecureProxy.Api.Data;
using SecureProxy.Api.Domain;

namespace SecureProxy.Tests.Infrastructure;

/// <summary>Deterministic configuration used by every integration test.</summary>
public static class TestSeed
{
    public const string CrmBaseUrl = "http://crm.test/api/";
    public const string CrmKey = "crm";
    public const string LegacyKey = "legacy";

    /// <summary>Base64 of 32 bytes, matches the <c>Secrets:test-key-v1</c> configuration value injected by the factory.</summary>
    public const string TestKeyBase64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    public static void Seed(ProxyDbContext db)
    {
        var now = new DateTime(2026, 11, 8, 12, 0, 0, DateTimeKind.Utc);

        var crm = new Destination
        {
            Id = Guid.NewGuid(), Key = CrmKey, Name = "CRM", BaseUrl = CrmBaseUrl, IsEnabled = true, TimeoutSeconds = 5,
            AuthType = UpstreamAuthType.ApiKeyHeader, AuthHeaderName = "X-Upstream-Key", AuthSecretReference = "cfg:crm-api-key",
            CreatedAtUtc = now, UpdatedAtUtc = now
        };
        var legacy = new Destination
        {
            Id = Guid.NewGuid(), Key = LegacyKey, Name = "Legacy (disabled)", BaseUrl = "http://legacy.test/", IsEnabled = false, TimeoutSeconds = 5,
            CreatedAtUtc = now, UpdatedAtUtc = now
        };
        var profile = new EncryptionProfile
        {
            Id = Guid.NewGuid(), Key = "test-v1", Algorithm = EncryptionAlgorithms.Aes256Gcm, KeyReference = "cfg:test-key-v1", KeyVersion = 1, IsEnabled = true,
            CreatedAtUtc = now, UpdatedAtUtc = now
        };

        var operations = new List<Operation>
        {
            new()
            {
                Id = Guid.NewGuid(), Key = "customer.get", Destination = crm, HttpMethod = "GET", PathTemplate = "customers/{customerId}", IsEnabled = true,
                CreatedAtUtc = now, UpdatedAtUtc = now,
                ParameterRules =
                {
                    new ParameterRule { Id = Guid.NewGuid(), Name = "customerId", Location = ParameterLocation.Path, IsRequired = true, DataType = ParameterDataType.String, MaxLength = 64 },
                    new ParameterRule { Id = Guid.NewGuid(), Name = "include", Location = ParameterLocation.Query, IsRequired = false, DataType = ParameterDataType.String, AllowedValues = "orders,profile" }
                },
                HeaderRules =
                {
                    new HeaderRule { Id = Guid.NewGuid(), HeaderName = "X-Tenant-Id", Direction = HeaderDirection.Request },
                    new HeaderRule { Id = Guid.NewGuid(), HeaderName = "X-RateLimit-Remaining", Direction = HeaderDirection.Response }
                }
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "customer.search", Destination = crm, HttpMethod = "GET", PathTemplate = "customers", IsEnabled = true,
                CreatedAtUtc = now, UpdatedAtUtc = now,
                ParameterRules =
                {
                    new ParameterRule { Id = Guid.NewGuid(), Name = "q", Location = ParameterLocation.Query, IsRequired = true, DataType = ParameterDataType.String, MaxLength = 50 },
                    new ParameterRule { Id = Guid.NewGuid(), Name = "limit", Location = ParameterLocation.Query, IsRequired = false, DataType = ParameterDataType.Integer, MinValue = 1, MaxValue = 100 }
                }
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "order.create", Destination = crm, HttpMethod = "POST", PathTemplate = "orders", IsEnabled = true,
                MaxRequestBytes = 1024, SupportsIdempotencyKey = true, CreatedAtUtc = now, UpdatedAtUtc = now,
                ParameterRules =
                {
                    new ParameterRule { Id = Guid.NewGuid(), Name = "customerId", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Guid },
                    new ParameterRule { Id = Guid.NewGuid(), Name = "amount", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Number, MinValue = 0.01m, MaxValue = 1_000_000m },
                    new ParameterRule { Id = Guid.NewGuid(), Name = "note", Location = ParameterLocation.Body, IsRequired = false, DataType = ParameterDataType.String, MaxLength = 200 }
                }
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "order.bulk", Destination = crm, HttpMethod = "POST", PathTemplate = "orders/bulk", IsEnabled = true,
                MaxRequestBytes = 512, AllowUnknownParameters = true, CreatedAtUtc = now, UpdatedAtUtc = now,
                ParameterRules =
                {
                    new ParameterRule { Id = Guid.NewGuid(), Name = "batchId", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.String, MaxLength = 50 }
                }
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "order.secure", Destination = crm, HttpMethod = "POST", PathTemplate = "secure/orders", IsEnabled = true,
                RequiresEncryption = true, EncryptionProfile = profile, CreatedAtUtc = now, UpdatedAtUtc = now,
                ParameterRules =
                {
                    new ParameterRule { Id = Guid.NewGuid(), Name = "customerId", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Guid },
                    new ParameterRule { Id = Guid.NewGuid(), Name = "amount", Location = ParameterLocation.Body, IsRequired = true, DataType = ParameterDataType.Number, MinValue = 0.01m }
                }
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "customer.disabled", Destination = crm, HttpMethod = "GET", PathTemplate = "customers/disabled", IsEnabled = false,
                CreatedAtUtc = now, UpdatedAtUtc = now
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "legacy.get", Destination = legacy, HttpMethod = "GET", PathTemplate = "records", IsEnabled = true,
                CreatedAtUtc = now, UpdatedAtUtc = now
            },
            new()
            {
                // Deliberately corrupt configuration: the method is not in the proxy's allow-list.
                Id = Guid.NewGuid(), Key = "bad.method", Destination = crm, HttpMethod = "TRACE", PathTemplate = "anything", IsEnabled = true,
                CreatedAtUtc = now, UpdatedAtUtc = now
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "slow.get", Destination = crm, HttpMethod = "GET", PathTemplate = "slow", IsEnabled = true, TimeoutSeconds = 1,
                CreatedAtUtc = now, UpdatedAtUtc = now
            },
            new()
            {
                Id = Guid.NewGuid(), Key = "report.get", Destination = crm, HttpMethod = "GET", PathTemplate = "reports/latest", IsEnabled = true, MaxResponseBytes = 1024,
                CreatedAtUtc = now, UpdatedAtUtc = now
            }
        };

        db.Destinations.AddRange(crm, legacy);
        db.EncryptionProfiles.Add(profile);
        db.Operations.AddRange(operations);
        db.SaveChanges();
    }
}
