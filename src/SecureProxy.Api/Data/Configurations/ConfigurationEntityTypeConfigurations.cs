using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Data.Configurations;

public sealed class DestinationConfiguration : IEntityTypeConfiguration<Destination>
{
    public void Configure(EntityTypeBuilder<Destination> b)
    {
        b.ToTable("Destinations");
        b.HasKey(x => x.Id);
        b.Property(x => x.Key).HasMaxLength(100).IsRequired();
        b.HasIndex(x => x.Key).IsUnique();
        b.Property(x => x.Name).HasMaxLength(200).IsRequired();
        b.Property(x => x.BaseUrl).HasMaxLength(2000).IsRequired();
        b.Property(x => x.AllowedPorts).HasMaxLength(200);
        b.Property(x => x.AuthType).HasConversion<string>().HasMaxLength(30);
        b.Property(x => x.AuthHeaderName).HasMaxLength(100);
        b.Property(x => x.AuthSecretReference).HasMaxLength(300);
        b.Property(x => x.ConcurrencyStamp).HasMaxLength(64).IsRequired().IsConcurrencyToken();
        b.HasMany(x => x.Operations).WithOne(x => x.Destination).HasForeignKey(x => x.DestinationId).OnDelete(DeleteBehavior.Restrict);
    }
}

public sealed class OperationConfiguration : IEntityTypeConfiguration<Operation>
{
    public void Configure(EntityTypeBuilder<Operation> b)
    {
        b.ToTable("Operations");
        b.HasKey(x => x.Id);
        b.Property(x => x.Key).HasMaxLength(200).IsRequired();
        b.HasIndex(x => x.Key).IsUnique();
        b.Property(x => x.HttpMethod).HasMaxLength(10).IsRequired();
        b.Property(x => x.PathTemplate).HasMaxLength(2000).IsRequired();
        b.Property(x => x.ConcurrencyStamp).HasMaxLength(64).IsRequired().IsConcurrencyToken();
        b.HasOne(x => x.EncryptionProfile).WithMany().HasForeignKey(x => x.EncryptionProfileId).OnDelete(DeleteBehavior.Restrict);
        b.HasMany(x => x.ParameterRules).WithOne(x => x.Operation).HasForeignKey(x => x.OperationId).OnDelete(DeleteBehavior.Cascade);
        b.HasMany(x => x.HeaderRules).WithOne(x => x.Operation).HasForeignKey(x => x.OperationId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ParameterRuleConfiguration : IEntityTypeConfiguration<ParameterRule>
{
    public void Configure(EntityTypeBuilder<ParameterRule> b)
    {
        b.ToTable("ParameterRules");
        b.HasKey(x => x.Id);
        b.Property(x => x.Name).HasMaxLength(100).IsRequired();
        b.Property(x => x.Location).HasConversion<string>().HasMaxLength(10);
        b.Property(x => x.DataType).HasConversion<string>().HasMaxLength(20);
        b.Property(x => x.MinValue).HasPrecision(28, 8);
        b.Property(x => x.MaxValue).HasPrecision(28, 8);
        b.Property(x => x.Pattern).HasMaxLength(500);
        b.Property(x => x.AllowedValues).HasMaxLength(2000);
        b.HasIndex(x => new { x.OperationId, x.Name }).IsUnique();
    }
}

public sealed class HeaderRuleConfiguration : IEntityTypeConfiguration<HeaderRule>
{
    public void Configure(EntityTypeBuilder<HeaderRule> b)
    {
        b.ToTable("HeaderRules");
        b.HasKey(x => x.Id);
        b.Property(x => x.HeaderName).HasMaxLength(100).IsRequired();
        b.Property(x => x.Direction).HasConversion<string>().HasMaxLength(10);
        b.HasIndex(x => new { x.OperationId, x.HeaderName, x.Direction }).IsUnique();
    }
}

public sealed class EncryptionProfileConfiguration : IEntityTypeConfiguration<EncryptionProfile>
{
    public void Configure(EntityTypeBuilder<EncryptionProfile> b)
    {
        b.ToTable("EncryptionProfiles");
        b.HasKey(x => x.Id);
        b.Property(x => x.Key).HasMaxLength(100).IsRequired();
        b.HasIndex(x => x.Key).IsUnique();
        b.Property(x => x.Algorithm).HasMaxLength(30).IsRequired();
        b.Property(x => x.KeyReference).HasMaxLength(300).IsRequired();
        b.Property(x => x.ConcurrencyStamp).HasMaxLength(64).IsRequired().IsConcurrencyToken();
    }
}

public sealed class RequestLogConfiguration : IEntityTypeConfiguration<RequestLog>
{
    public void Configure(EntityTypeBuilder<RequestLog> b)
    {
        b.ToTable("RequestLogs");
        b.HasKey(x => x.Id);
        b.Property(x => x.CorrelationId).HasMaxLength(64).IsRequired();
        b.Property(x => x.OperationKey).HasMaxLength(200);
        b.Property(x => x.DestinationKey).HasMaxLength(100);
        b.Property(x => x.HttpMethod).HasMaxLength(10);
        b.Property(x => x.Outcome).HasConversion<string>().HasMaxLength(30);
        b.Property(x => x.ReasonCode).HasMaxLength(100);
        b.Property(x => x.ReasonDetail).HasMaxLength(500);
        b.Property(x => x.ClientAddress).HasMaxLength(64);
        b.HasIndex(x => x.CorrelationId);
        b.HasIndex(x => x.StartedAtUtc);
        b.HasIndex(x => new { x.OperationKey, x.StartedAtUtc });
    }
}

public sealed class ConfigurationChangeConfiguration : IEntityTypeConfiguration<ConfigurationChange>
{
    public void Configure(EntityTypeBuilder<ConfigurationChange> b)
    {
        b.ToTable("ConfigurationChanges");
        b.HasKey(x => x.Id);
        b.Property(x => x.EntityType).HasMaxLength(50).IsRequired();
        b.Property(x => x.EntityKey).HasMaxLength(200).IsRequired();
        b.Property(x => x.Action).HasConversion<string>().HasMaxLength(20);
        b.Property(x => x.ChangedBy).HasMaxLength(200).IsRequired();
        b.Property(x => x.CorrelationId).HasMaxLength(64).IsRequired();
        b.Property(x => x.ChangesJson).IsRequired();
        b.HasIndex(x => new { x.EntityType, x.EntityId, x.ChangedAtUtc });
    }
}
