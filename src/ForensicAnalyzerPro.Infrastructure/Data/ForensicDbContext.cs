using System.Linq;
using System.Text.Json;
using ForensicAnalyzerPro.Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace ForensicAnalyzerPro.Infrastructure.Data;

public class ForensicDbContext : DbContext
{
    private const string ConnectionString = "Data Source=forensic_analyzer.db";

    public DbSet<TimelineEvent> TimelineEvents => Set<TimelineEvent>();
    public DbSet<Evidence> EvidenceItems => Set<Evidence>();
    public DbSet<ForensicCase> Cases => Set<ForensicCase>();
    public DbSet<IOC> IOCs => Set<IOC>();
    public DbSet<YaraRule> YaraRules => Set<YaraRule>();
    public DbSet<ScanResult> ScanResults => Set<ScanResult>();
    public DbSet<ScanSession> ScanSessions => Set<ScanSession>();

    public ForensicDbContext() { }

    public ForensicDbContext(DbContextOptions<ForensicDbContext> options) : base(options) { }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlite(ConnectionString);
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        var stringListComparer = new ValueComparer<List<string>>(
            (a, b) => a != null && b != null && a.SequenceEqual(b),
            c => c.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())),
            c => c.ToList());

        var dictComparer = new ValueComparer<Dictionary<string, string>>(
            (a, b) => a != null && b != null && a.Count == b.Count && !a.Except(b).Any(),
            c => c.Aggregate(0, (hash, kvp) => HashCode.Combine(hash, kvp.Key.GetHashCode(), kvp.Value.GetHashCode())),
            c => new Dictionary<string, string>(c));

        modelBuilder.Entity<TimelineEvent>(entity =>
        {
            entity.ToTable("TimelineEvents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.SourceName).IsRequired().HasMaxLength(200);
            entity.Property(e => e.EventType).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Description).IsRequired().HasMaxLength(2000);
            entity.Property(e => e.FilePath).HasMaxLength(1000);
            entity.Property(e => e.User).HasMaxLength(100);
            entity.Property(e => e.Hash).HasMaxLength(128);
            entity.Property(e => e.Metadata)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, jsonOptions) ?? new Dictionary<string, string>())
                .Metadata.SetValueComparer(dictComparer);
            entity.Property(e => e.Tags)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>())
                .Metadata.SetValueComparer(stringListComparer);
        });

        modelBuilder.Entity<Evidence>(entity =>
        {
            entity.ToTable("Evidence");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(256);
            entity.Property(e => e.Description).HasMaxLength(2000);
            entity.Property(e => e.SourcePath).IsRequired().HasMaxLength(1000);
            entity.Property(e => e.OriginalPath).HasMaxLength(1000);
            entity.Property(e => e.SHA256).HasMaxLength(64);
            entity.Property(e => e.MD5).HasMaxLength(32);
            entity.Property(e => e.CollectedBy).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Notes).HasMaxLength(4000);
            entity.Property(e => e.ChainOfCustody).HasMaxLength(8000);
            entity.Property(e => e.Tags)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>())
                .Metadata.SetValueComparer(stringListComparer);
        });

        modelBuilder.Entity<ForensicCase>(entity =>
        {
            entity.ToTable("Cases");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.CaseNumber).IsRequired().HasMaxLength(50);
            entity.Property(e => e.Title).IsRequired().HasMaxLength(200);
            entity.Property(e => e.Description).HasMaxLength(4000);
            entity.Property(e => e.CreatedBy).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Assignee).HasMaxLength(100);
            entity.Property(e => e.Tags)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>())
                .Metadata.SetValueComparer(stringListComparer);

            entity.HasMany(e => e.EvidenceList)
                .WithOne()
                .HasForeignKey(e => e.CaseId);

            entity.HasMany(e => e.Events)
                .WithOne()
                .HasForeignKey(e => e.CaseId);
        });

        modelBuilder.Entity<IOC>(entity =>
        {
            entity.ToTable("IOCs");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(256);
            entity.Property(e => e.Value).IsRequired().HasMaxLength(2000);
            entity.Property(e => e.Type).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Description).HasMaxLength(2000);
            entity.Property(e => e.CreatedBy).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Tags)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>())
                .Metadata.SetValueComparer(stringListComparer);
        });

        modelBuilder.Entity<YaraRule>(entity =>
        {
            entity.ToTable("YaraRules");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(256);
            entity.Property(e => e.Description).HasMaxLength(2000);
            entity.Property(e => e.RuleContent).IsRequired();
            entity.Property(e => e.Category).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Author).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Tags)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<string>>(v, jsonOptions) ?? new List<string>())
                .Metadata.SetValueComparer(stringListComparer);
        });

        modelBuilder.Entity<ScanResult>(entity =>
        {
            entity.ToTable("ScanResults");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.ScanName).IsRequired().HasMaxLength(256);
            entity.Property(e => e.ErrorMessage).HasMaxLength(4000);

            entity.HasMany(e => e.Events)
                .WithOne()
                .HasForeignKey(e => e.CaseId)
                .IsRequired(false);

            entity.HasMany(e => e.EvidenceList)
                .WithOne()
                .HasForeignKey(e => e.CaseId)
                .IsRequired(false);
        });

        modelBuilder.Entity<ScanSession>(entity =>
        {
            entity.ToTable("ScanSessions");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(12);
            entity.Property(e => e.Pin).IsRequired().HasMaxLength(16);
            entity.HasIndex(e => e.Pin).IsUnique();
            entity.Property(e => e.Status).IsRequired().HasMaxLength(20);
            entity.Property(e => e.ScanType).HasMaxLength(100);
            entity.Property(e => e.DownloadToken).HasMaxLength(64);
            entity.Property(e => e.HostName).HasMaxLength(256);
            entity.Property(e => e.UserName).HasMaxLength(256);
            entity.Property(e => e.ScannerVersion).HasMaxLength(50);
            entity.Property(e => e.WebhookUrl).HasMaxLength(2000);
            entity.Property(e => e.ResultChannelId).HasMaxLength(32);
            entity.Property(e => e.DiscordGuildId).HasMaxLength(32);
            entity.Property(e => e.DiscordUserId).HasMaxLength(32);
            entity.Property(e => e.ErrorMessage).HasMaxLength(2000);
        });
    }
}
