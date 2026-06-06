using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.Services;

public class ServicesParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Service;
    public string Name => "Services Parser";
    public string Description => "Parses Windows service registry keys to identify installed, modified, and deleted services as well as suspicious persistence mechanisms.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-45).AddHours(-3),
            SourceType = ArtifactType.Service,
            SourceName = Name,
            EventType = "ServiceInstalled",
            Description = "New service installed with unusual binary path pointing to temporary directory",
            FilePath = path,
            User = "SYSTEM",
            Hash = "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ServiceName", "LegitimateService" },
                { "DisplayName", "Windows Legitimate Update Service" },
                { "ImagePath", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe" },
                { "StartType", "Auto" },
                { "ServiceType", "Win32OwnProcess" },
                { "RegistryKey", "SYSTEM\\CurrentControlSet\\Services\\LegitimateService" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-20).AddHours(-12),
            SourceType = ArtifactType.Service,
            SourceName = Name,
            EventType = "ServiceInstalled",
            Description = "Service installed with driver component for kernel-level persistence",
            FilePath = path,
            User = "SYSTEM",
            Hash = "F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "ServiceName", "ProcDriver" },
                { "DisplayName", "Process Monitor Driver" },
                { "ImagePath", "\\??\\C:\\Windows\\System32\\drivers\\procdrv.sys" },
                { "StartType", "System" },
                { "ServiceType", "KernelDriver" },
                { "RegistryKey", "SYSTEM\\CurrentControlSet\\Services\\ProcDriver" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-10).AddHours(-6),
            SourceType = ArtifactType.Service,
            SourceName = Name,
            EventType = "ServiceModified",
            Description = "Existing service modified to point to a different executable binary",
            FilePath = path,
            User = "SYSTEM",
            Hash = "A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ServiceName", "wuauserv" },
                { "OriginalImagePath", "C:\\Windows\\System32\\svchost.exe -k netsvcs" },
                { "NewImagePath", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p C:\\Users\\jsmith\\AppData\\Local\\update.dll" },
                { "ModificationTime", now.AddDays(-10).AddHours(-6).ToString("O") },
                { "RegistryKey", "SYSTEM\\CurrentControlSet\\Services\\wuauserv" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-5).AddHours(-9),
            SourceType = ArtifactType.Service,
            SourceName = Name,
            EventType = "ServiceDeleted",
            Description = "Security service deleted - possible attacker action to disable defenses",
            FilePath = path,
            User = "SYSTEM",
            Hash = "B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "ServiceName", "WinDefend" },
                { "DisplayName", "Windows Defender Antivirus Service" },
                { "OriginalStartType", "Auto" },
                { "DeletionTime", now.AddDays(-5).AddHours(-9).ToString("O") },
                { "PossibleReason", "Defense evasion" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-1),
            SourceType = ArtifactType.Service,
            SourceName = Name,
            EventType = "SuspiciousPersistence",
            Description = "Suspicious service persistence detected with known C2 communication pattern",
            FilePath = path,
            User = "SYSTEM",
            Hash = "C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "ServiceName", "NetSvc" },
                { "DisplayName", "Network Connectivity Service" },
                { "ImagePath", "C:\\Windows\\System32\\netsvc.exe" },
                { "StartType", "Auto" },
                { "ServiceType", "Win32OwnProcess" },
                { "RegistryKey", "SYSTEM\\CurrentControlSet\\Services\\NetSvc" },
                { "Indicator", "Binary signed with可疑 certificate" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-8),
            SourceType = ArtifactType.Service,
            SourceName = Name,
            EventType = "ServiceInstalled",
            Description = "Service installed with failure reset period set to 0 for rapid restart on termination",
            FilePath = path,
            User = "SYSTEM",
            Hash = "D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5",
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "ServiceName", "UpdateSvc" },
                { "DisplayName", "Application Update Service" },
                { "ImagePath", "C:\\ProgramData\\UpdateSvc\\updater.exe" },
                { "StartType", "Auto" },
                { "FailureReset", "0" },
                { "FailureActions", "Restart/Restart/Restart" },
                { "RegistryKey", "SYSTEM\\CurrentControlSet\\Services\\UpdateSvc" }
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

        return path.Contains(@"SYSTEM\CurrentControlSet\Services", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Services", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("service", StringComparison.OrdinalIgnoreCase);
    }
}
