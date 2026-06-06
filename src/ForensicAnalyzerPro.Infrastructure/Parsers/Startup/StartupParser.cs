using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.Startup;

public class StartupParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Startup;
    public string Name => "Startup Parser";
    public string Description => "Parses Windows startup locations including startup folders and registry autoruns to identify persistence mechanisms.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-60).AddHours(-4),
            SourceType = ArtifactType.Startup,
            SourceName = Name,
            EventType = "StartupEntry",
            Description = "Shortcut added to startup folder pointing to executable in user's temp directory",
            FilePath = Path.Combine(path, "SystemHelper.lnk"),
            User = "CONTOSO\\jsmith",
            Hash = "D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ShortcutName", "SystemHelper.lnk" },
                { "TargetPath", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\syshelper.exe" },
                { "Arguments", "-silent -persist" },
                { "WorkingDirectory", "C:\\Users\\jsmith\\AppData\\Local\\Temp" },
                { "Hotkey", "None" },
                { "WindowStyle", "Minimized" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-30).AddHours(-12),
            SourceType = ArtifactType.Startup,
            SourceName = Name,
            EventType = "RegistryAutorun",
            Description = "Registry Run key entry added to launch DLL side-loading executable",
            FilePath = path,
            User = "CONTOSO\\administrator",
            Hash = "E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
                { "ValueName", "WindowsSecurity" },
                { "ValueData", "rundll32.exe C:\\Windows\\Tasks\\security.dll,InitializeSecurity" },
                { "Scope", "Machine" },
                { "AddedBy", "CONTOSO\\administrator" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-14).AddHours(-8),
            SourceType = ArtifactType.Startup,
            SourceName = Name,
            EventType = "FolderEntry",
            Description = "Executable file placed in All Users startup folder for system-wide persistence",
            FilePath = Path.Combine(path, "MonitorService.exe"),
            User = "CONTOSO\\administrator",
            Hash = "F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "FilePath", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\MonitorService.exe" },
                { "FileSize", "123904" },
                { "CreationTime", now.AddDays(-14).AddHours(-8).ToString("O") },
                { "ModificationTime", now.AddDays(-14).AddHours(-8).ToString("O") },
                { "SigningStatus", "Unsigned" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-3),
            SourceType = ArtifactType.Startup,
            SourceName = Name,
            EventType = "SuspiciousStartup",
            Description = "Suspicious VBS script placed in startup with obfuscated content and network connections",
            FilePath = Path.Combine(path, "Redirect.vbs"),
            User = "CONTOSO\\jsmith",
            Hash = "A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "FilePath", "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Redirect.vbs" },
                { "FileSize", "2048" },
                { "Obfuscation", "Base64 encoded strings detected" },
                { "NetworkIndicators", "POST to http://10.0.0.5/collect" },
                { "DetectionBasis", "AMSI flagged suspicious script content" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-18),
            SourceType = ArtifactType.Startup,
            SourceName = Name,
            EventType = "RegistryAutorun",
            Description = "User-specific RunOnce key added for one-time persistence execution",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5",
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
                { "ValueName", "UpgradeNotifier" },
                { "ValueData", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\upgrade_notifier.exe" },
                { "Scope", "User" },
                { "Expiration", "Executed once then deleted" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-5),
            SourceType = ArtifactType.Startup,
            SourceName = Name,
            EventType = "StartupEntry",
            Description = "Recently added startup shortcut mimicking legitimate Windows component name",
            FilePath = Path.Combine(path, "WindowsUpdate.lnk"),
            User = "CONTOSO\\jsmith",
            Hash = "C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ShortcutName", "WindowsUpdate.lnk" },
                { "TargetPath", "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Update\\wuaudt.exe" },
                { "Arguments", "/checknow /silent" },
                { "IconLocation", "C:\\Windows\\System32\\wucltux.dll,0" },
                { "CreationTime", now.AddHours(-5).ToString("O") }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\StartUp"), ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var attr = File.GetAttributes(path);
        if (attr.HasFlag(FileAttributes.Directory))
            return path.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
                   path.Contains("Start Menu", StringComparison.OrdinalIgnoreCase);

        return path.Contains("Startup", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("autorun", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Start Menu", StringComparison.OrdinalIgnoreCase) ||
               path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
    }
}
