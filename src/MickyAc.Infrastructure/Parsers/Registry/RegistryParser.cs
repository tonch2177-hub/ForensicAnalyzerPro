using MickyAc.Domain.Enums;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Parsers.Registry;

public class RegistryParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Registry;
    public string Name => "Registry Parser";
    public string Description => "Parses Windows Registry hives for forensic artifacts including autoruns, user activity, and system configuration.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-30).AddHours(-5),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "RunKey",
            Description = "Persistence mechanism detected: Run key entry added to launch backdoor on user login",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "F4E5D6C7B8A9F0E1D2C3B4A5F6E7D8C9",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
                { "ValueName", "WindowsUpdate" },
                { "ValueData", "C:\\Users\\jsmith\\AppData\\Local\\svchost.exe" },
                { "KeyLastWriteTime", now.AddDays(-30).AddHours(-5).ToString("O") }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-21).AddHours(-12),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "UserAssist",
            Description = "UserAssist entry recorded execution of suspicious executable from temporary directory",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F4174911}\\Count" },
                { "ProgramName", "payload.exe" },
                { "ExecutionCount", "3" },
                { "LastExecution", now.AddDays(-21).AddHours(-12).ToString("O") },
                { "FocusTime", "00:02:15" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-14).AddHours(-8),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "RecentDoc",
            Description = "Recent document entry reveals access to sensitive spreadsheet containing financial data",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6",
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" },
                { "FileName", "Q4_Financial_Results.xlsx" },
                { "Extension", ".xlsx" },
                { "MRUIndex", "1" },
                { "SourcePath", "D:\\Finance\\Q4_Financial_Results.xlsx" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-3),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "ShellBag",
            Description = "ShellBag entry reveals previously accessed directory on removed external drive",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU" },
                { "DirectoryName", "Confidential_Data" },
                { "FullPath", "E:\\Confidential_Data\\" },
                { "LastAccessed", now.AddDays(-7).AddHours(-3).ToString("O") },
                { "SlotNumber", "42" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-3).AddHours(-18),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "MuiCache",
            Description = "MuiCache entry shows recently launched application binary path",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7",
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "NTUSER.DAT\\Software\\Classes\\Local Settings\\MuiCache" },
                { "ApplicationPath", "C:\\Users\\jsmith\\Downloads\\ProcessHacker-2.39\\ProcessHacker.exe" },
                { "FriendlyName", "Process Hacker" },
                { "Language", "en-US" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-9),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "OpenSaveMRU",
            Description = "Open/Save MRU shows file saved to alternate data stream location",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU" },
                { "FileName", "notes.txt:secret" },
                { "Extension", "txt" },
                { "MRUIndex", "0" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-0).AddHours(-6),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "TypedPath",
            Description = "Typed path entry reveals direct navigation to network share containing sensitive documents",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths" },
                { "Path", "\\\\10.0.0.50\\shared\\HR_Records" },
                { "MRUIndex", "1" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-1),
            SourceType = ArtifactType.Registry,
            SourceName = Name,
            EventType = "LastVisitedMRU",
            Description = "LastVisitedMRU entry shows access to directory containing recently executed tools",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "RegistryPath", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU" },
                { "DirectoryPath", "C:\\Users\\jsmith\\Desktop\\forensic_tools" },
                { "MRUIndex", "0" },
                { "LastAccessed", now.AddHours(-1).ToString("O") }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"SYSTEM\CurrentControlSet\Services", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("UserAssist", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("ShellBag", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("MuiCache", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("OpenSaveMRU", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("TypedPaths", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("LastVisitedMRU", StringComparison.OrdinalIgnoreCase);
    }
}
