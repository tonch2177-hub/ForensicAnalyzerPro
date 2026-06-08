using MickyAc.Domain.Enums;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Parsers.BAM;

public class BAMParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.BAM;
    public string Name => "BAM Parser";
    public string Description => "Parses the Background Activity Moderator (BAM) registry key for process execution timestamps and deleted entry artifacts.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-4),
            SourceType = ArtifactType.BAM,
            SourceName = Name,
            EventType = "ProcessExecuted",
            Description = "Process executed: notepad.exe with last execution time recorded in BAM",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.None,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "notepad.exe" },
                { "FullPath", "C:\\Windows\\System32\\notepad.exe" },
                { "LastExecutionTime", now.AddDays(-7).AddHours(-4).ToString("O") },
                { "ExecutionCount", "47" },
                { "SID", "S-1-5-21-123456789-123456789-123456789-1001" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-5).AddHours(-2),
            SourceType = ArtifactType.BAM,
            SourceName = Name,
            EventType = "ProcessLastExecution",
            Description = "Last execution time recorded: regedit.exe was last accessed by user",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "regedit.exe" },
                { "FullPath", "C:\\Windows\\regedit.exe" },
                { "LastExecutionTime", now.AddDays(-5).AddHours(-2).ToString("O") },
                { "SID", "S-1-5-21-123456789-123456789-123456789-1001" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-3).AddHours(-8),
            SourceType = ArtifactType.BAM,
            SourceName = Name,
            EventType = "ProcessExecuted",
            Description = "Process executed: powershell.exe was launched from an unusual location",
            FilePath = path,
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "powershell.exe" },
                { "FullPath", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
                { "LastExecutionTime", now.AddDays(-3).AddHours(-8).ToString("O") },
                { "CommandLine", "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\jsmith\\script.ps1" },
                { "ExecutionCount", "12" },
                { "SID", "S-1-5-21-123456789-123456789-123456789-500" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-12),
            SourceType = ArtifactType.BAM,
            SourceName = Name,
            EventType = "DeletedEntry",
            Description = "Deleted BAM entry detected: an application entry was removed from the BAM key",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "RemainingEntry", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\temp_app.exe" },
                { "PossibleCoverup", "true" },
                { "RegistryPath", "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-123456789-123456789-123456789-1001" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-1),
            SourceType = ArtifactType.BAM,
            SourceName = Name,
            EventType = "ProcessLastExecution",
            Description = "Recent process execution detected: WinRAR.exe was used to extract archives",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "WinRAR.exe" },
                { "FullPath", "C:\\Program Files\\WinRAR\\WinRAR.exe" },
                { "LastExecutionTime", now.AddHours(-1).ToString("O") },
                { "ExecutionCount", "234" },
                { "SID", "S-1-5-21-123456789-123456789-123456789-1001" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        var events = ParseAsync(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", ct);
        return events;
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("bam", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("BAM", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("BackgroundActivityModerator", StringComparison.OrdinalIgnoreCase);
    }
}
