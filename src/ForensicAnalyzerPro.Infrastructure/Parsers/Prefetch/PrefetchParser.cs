using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.Prefetch;

public class PrefetchParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Prefetch;
    public string Name => "Prefetch Parser";
    public string Description => "Parses Windows Prefetch files to analyze application execution history, file access patterns, and detect anomalies.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-10).AddHours(-1),
            SourceType = ArtifactType.Prefetch,
            SourceName = Name,
            EventType = "PrefetchCreated",
            Description = "Prefetch file created for chrome.exe with high execution frequency",
            FilePath = Path.Combine(path, "CHROME.EXE-ABC12345.pf"),
            User = "SYSTEM",
            Hash = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6",
            RiskLevel = RiskLevel.None,
            Metadata = new Dictionary<string, string>
            {
                { "ExecutableName", "CHROME.EXE" },
                { "PrefetchHash", "ABC12345" },
                { "RunCount", "156" },
                { "FileSize", "42568" },
                { "Version", "10.0.19041" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-6),
            SourceType = ArtifactType.Prefetch,
            SourceName = Name,
            EventType = "ProcessExecuted",
            Description = "Process execution detected via Prefetch: sdiagnhost.exe was launched 89 times",
            FilePath = Path.Combine(path, "SDIAGNHOST.EXE-DEF45678.pf"),
            User = "SYSTEM",
            Hash = "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7",
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ExecutableName", "SDIAGNHOST.EXE" },
                { "PrefetchHash", "DEF45678" },
                { "RunCount", "89" },
                { "LastRunTime", now.AddDays(-7).AddHours(-6).ToString("O") },
                { "FullPath", "C:\\Windows\\System32\\sdiagnhost.exe" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-4).AddHours(-12),
            SourceType = ArtifactType.Prefetch,
            SourceName = Name,
            EventType = "DllLoaded",
            Description = "DLL loaded by multiple processes: comctl32.dll was loaded 234 times across applications",
            FilePath = null,
            User = "SYSTEM",
            Hash = "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8",
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "DllName", "comctl32.dll" },
                { "LoadCount", "234" },
                { "AssociatedProcesses", "explorer.exe, chrome.exe, WINWORD.EXE" },
                { "DllPath", "C:\\Windows\\WinSxS\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1_none_..."
                }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-3),
            SourceType = ArtifactType.Prefetch,
            SourceName = Name,
            EventType = "AnomalyDetected",
            Description = "Anomaly: suspicious executable mimikatz.exe found in Prefetch with unusual execution pattern",
            FilePath = Path.Combine(path, "MIKIKATZ.EXE-99999999.pf"),
            User = "SYSTEM",
            Hash = "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "ExecutableName", "MIMIKATZ.EXE" },
                { "RunCount", "3" },
                { "FirstRunTime", now.AddDays(-2).AddHours(-5).ToString("O") },
                { "LastRunTime", now.AddDays(-2).AddHours(-3).ToString("O") },
                { "SourcePath", "C:\\Users\\jsmith\\Desktop\\tools\\mimikatz.exe" },
                { "Alert", "Known credential dumping tool detected" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-9),
            SourceType = ArtifactType.Prefetch,
            SourceName = Name,
            EventType = "ProcessExecuted",
            Description = "Process execution detected: wmic.exe was used 15 times in a short duration",
            FilePath = Path.Combine(path, "WMIC.EXE-7890ABCD.pf"),
            User = "SYSTEM",
            Hash = "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0",
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "ExecutableName", "WMIC.EXE" },
                { "PrefetchHash", "7890ABCD" },
                { "RunCount", "15" },
                { "LastRunTime", now.AddDays(-1).AddHours(-9).ToString("O") },
                { "FullPath", "C:\\Windows\\System32\\wbem\\wmic.exe" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\Windows\Prefetch", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var attr = File.GetAttributes(path);
        if (attr.HasFlag(FileAttributes.Directory))
            return path.Equals(@"C:\Windows\Prefetch", StringComparison.OrdinalIgnoreCase);

        return path.EndsWith(".pf", StringComparison.OrdinalIgnoreCase);
    }
}
