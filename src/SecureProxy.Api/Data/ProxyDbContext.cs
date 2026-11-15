using Microsoft.EntityFrameworkCore;
using SecureProxy.Api.Domain;

namespace SecureProxy.Api.Data;

public sealed class ProxyDbContext : DbContext
{
    public ProxyDbContext(DbContextOptions<ProxyDbContext> options) : base(options)
    {
    }

    public DbSet<Destination> Destinations => Set<Destination>();
    public DbSet<Operation> Operations => Set<Operation>();
    public DbSet<ParameterRule> ParameterRules => Set<ParameterRule>();
    public DbSet<HeaderRule> HeaderRules => Set<HeaderRule>();
    public DbSet<EncryptionProfile> EncryptionProfiles => Set<EncryptionProfile>();
    public DbSet<RequestLog> RequestLogs => Set<RequestLog>();
    public DbSet<ConfigurationChange> ConfigurationChanges => Set<ConfigurationChange>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ProxyDbContext).Assembly);
    }
}
