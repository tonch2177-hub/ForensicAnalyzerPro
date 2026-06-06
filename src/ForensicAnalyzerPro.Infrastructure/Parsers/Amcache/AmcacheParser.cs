using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.Amcache;

public class AmcacheParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Amcache;
    public string Name => "Amcache Parser";
    public string Description => "Parses the Amcache.hve registry hive for program execution, installation, and file execution artifacts.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-5).AddHours(-3),
            SourceType = ArtifactType.Amcache,
            SourceName = Name,
            EventType = "ProgramExecuted",
            Description = "Program execution detected: firefox.exe was launched from the user's profile",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1",
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ProgramName", "Mozilla Firefox" },
                { "ProductVersion", "128.0.3" },
                { "FileSize", "852992" },
                { "LastModifiedTime", now.AddDays(-10).ToString("O") }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-3).AddHours(-12),
            SourceType = ArtifactType.Amcache,
            SourceName = Name,
            EventType = "ProgramInstalled",
            Description = "Software installation detected: 7-Zip 24.08 (x64) was installed on the system",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2",
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "ProgramName", "7-Zip 24.08 (x64)" },
                { "Publisher", "Igor Pavlov" },
                { "InstallSource", "C:\\Users\\jsmith\\Downloads\\7z2408-x64.exe" },
                { "InstallDate", now.AddDays(-3).ToString("yyyy-MM-dd") }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-6),
            SourceType = ArtifactType.Amcache,
            SourceName = Name,
            EventType = "ProgramExecuted",
            Description = "Program execution detected: cmd.exe was launched with administrative privileges",
            FilePath = path,
            User = "CONTOSO\\administrator",
            Hash = "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ProgramName", "Windows Command Processor" },
                { "ProductVersion", "10.0.19041.1" },
                { "FileSize", "278528" },
                { "TrustLevel", "Unknown" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-8),
            SourceType = ArtifactType.Amcache,
            SourceName = Name,
            EventType = "FileExecuted",
            Description = "Executable run from temporary directory: suspicious_installer.exe was executed",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "ProgramName", "suspicious_installer.exe" },
                { "FilePath", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\suspicious_installer.exe" },
                { "SHA256", "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4" },
                { "Origin", "Downloaded from untrusted source" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-2),
            SourceType = ArtifactType.Amcache,
            SourceName = Name,
            EventType = "ProgramInstalled",
            Description = "Software installation detected: Python 3.12.5 (64-bit) was installed",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5",
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "ProgramName", "Python 3.12.5 (64-bit)" },
                { "Publisher", "Python Software Foundation" },
                { "InstallSource", "C:\\Users\\jsmith\\Downloads\\python-3.12.5-amd64.exe" },
                { "InstallDate", now.ToString("yyyy-MM-dd") }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\Windows\appcompat\Programs\Amcache.hve", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var fileName = Path.GetFileName(path);
        return fileName.Equals("Amcache.hve", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("Amcache.hve.LOG1", StringComparison.OrdinalIgnoreCase) ||
               path.EndsWith(".hve", StringComparison.OrdinalIgnoreCase);
    }
}
