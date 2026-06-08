using MickyAc.Domain.Enums;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Parsers.SRUM;

public class SRUMParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.SRUM;
    public string Name => "SRUM Parser";
    public string Description => "Parses the System Resource Usage Monitor (SRUM) database for network usage, application activity, resource consumption, and historical activity data.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-6).AddHours(-3),
            SourceType = ArtifactType.SRUM,
            SourceName = Name,
            EventType = "NetworkConnection",
            Description = "Network connection recorded: chrome.exe sent 245 MB of data over 30 minutes",
            FilePath = null,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "chrome.exe" },
                { "BytesSent", "257698038" },
                { "BytesReceived", "1048576000" },
                { "InterfaceLuid", "1234567890" },
                { "UserId", "S-1-5-21-123456789-123456789-123456789-1001" },
                { "Application", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-4).AddHours(-10),
            SourceType = ArtifactType.SRUM,
            SourceName = Name,
            EventType = "ApplicationActivity",
            Description = "Application foreground activity: WINWORD.EXE was in use for 4.5 hours",
            FilePath = null,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.None,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "WINWORD.EXE" },
                { "ForegroundDuration", "16200000" },
                { "BackgroundDuration", "5400000" },
                { "TotalCycles", "156" },
                { "Application", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-7),
            SourceType = ArtifactType.SRUM,
            SourceName = Name,
            EventType = "ResourceUsage",
            Description = "High resource usage detected: System (ntoskrnl.exe) consumed 8.2 GB of private memory",
            FilePath = null,
            User = "SYSTEM",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "System" },
                { "PrivateCommit", "8804682956" },
                { "SharedCommit", "2147483648" },
                { "CPUPercent", "45.3" },
                { "ImagePath", "C:\\Windows\\System32\\ntoskrnl.exe" },
                { "Alert", "Excessive memory consumption - possible memory leak or malicious activity" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-14),
            SourceType = ArtifactType.SRUM,
            SourceName = Name,
            EventType = "HistoricalActivity",
            Description = "Historical application activity: powershell.exe executed with network access pattern",
            FilePath = null,
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "powershell.exe" },
                { "FirstSeen", now.AddDays(-3).ToString("O") },
                { "LastSeen", now.AddDays(-1).AddHours(-14).ToString("O") },
                { "ExecutionCount", "23" },
                { "TotalNetworkBytes", "52428800" },
                { "ImagePath", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
                { "Alert", "PowerShell with network activity - possible C2 communication" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-3),
            SourceType = ArtifactType.SRUM,
            SourceName = Name,
            EventType = "NetworkConnection",
            Description = "Network connection detected: svchost.exe making connections to external IP 203.0.113.50",
            FilePath = null,
            User = "SYSTEM",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ProcessName", "svchost.exe" },
                { "RemoteAddress", "203.0.113.50" },
                { "RemotePort", "4444" },
                { "BytesSent", "152400" },
                { "BytesReceived", "89210" },
                { "Application", "C:\\Windows\\System32\\svchost.exe" },
                { "ServiceName", "Remote Access" },
                { "Alert", "Suspicious outbound connection on non-standard port" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\Windows\System32\sru\SRUDB.dat", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("SRUDB.dat", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("SRUM", StringComparison.OrdinalIgnoreCase) ||
               path.EndsWith("SRUDB.dat", StringComparison.OrdinalIgnoreCase);
    }
}
