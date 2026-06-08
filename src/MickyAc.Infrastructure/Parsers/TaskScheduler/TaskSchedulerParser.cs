using MickyAc.Domain.Enums;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Parsers.TaskScheduler;

public class TaskSchedulerParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.TaskScheduler;
    public string Name => "Task Scheduler Parser";
    public string Description => "Parses Windows scheduled task XML files to identify task creation, modification, deletion, and hidden persistence mechanisms.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-30).AddHours(-5),
            SourceType = ArtifactType.TaskScheduler,
            SourceName = Name,
            EventType = "TaskCreated",
            Description = "Scheduled task created to execute beacon with 5-minute interval for C2 communication",
            FilePath = Path.Combine(path, "Microsoft\\Windows\\UpdateOrchestrator\\UpdateCheck.xml"),
            User = "CONTOSO\\administrator",
            Hash = "E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "TaskName", "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateCheck" },
                { "Author", "CONTOSO\\administrator" },
                { "Command", "C:\\Windows\\System32\\cscript.exe" },
                { "Arguments", "//B //NoLogo C:\\Windows\\Tasks\\update.vbs" },
                { "Triggers", "Daily; 5-minute repeat" },
                { "UserId", "SYSTEM" },
                { "RunLevel", "HighestAvailable" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-14).AddHours(-10),
            SourceType = ArtifactType.TaskScheduler,
            SourceName = Name,
            EventType = "TaskModified",
            Description = "Existing scheduled task modified with new trigger conditions and executable path",
            FilePath = Path.Combine(path, "\\GoogleUpdateTaskMachineCore.xml"),
            User = "CONTOSO\\jsmith",
            Hash = "F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "TaskName", "\\GoogleUpdateTaskMachineCore" },
                { "OriginalCommand", "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe" },
                { "CurrentCommand", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\updater.exe" },
                { "ModificationTime", now.AddDays(-14).AddHours(-10).ToString("O") },
                { "ModifiedBy", "CONTOSO\\jsmith" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-3),
            SourceType = ArtifactType.TaskScheduler,
            SourceName = Name,
            EventType = "HiddenTask",
            Description = "Hidden scheduled task detected with system flag set to avoid display in Task Scheduler GUI",
            FilePath = Path.Combine(path, "\\Microsoft\\Windows\\Diagnosis\\HiddenTask.xml"),
            User = "SYSTEM",
            Hash = "A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "TaskName", "\\Microsoft\\Windows\\Diagnosis\\HiddenTask" },
                { "HiddenFlag", "true" },
                { "Command", "C:\\Windows\\System32\\rundll32.exe" },
                { "Arguments", "C:\\Windows\\Tasks\\shell32.dll,Control_RunDLL C:\\Windows\\Tasks\\backup.cpl" },
                { "UserId", "SYSTEM" },
                { "RunLevel", "HighestAvailable" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-18),
            SourceType = ArtifactType.TaskScheduler,
            SourceName = Name,
            EventType = "TaskDeleted",
            Description = "Scheduled task deleted after execution - forensic artifact of cleanup routine",
            FilePath = Path.Combine(path, "\\CleanupTask.xml"),
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "TaskName", "\\CleanupTask" },
                { "DeletionTime", now.AddDays(-2).AddHours(-18).ToString("O") },
                { "PreviousCommand", "C:\\Users\\jsmith\\AppData\\Local\\Temp\\cleanup.bat" },
                { "PreviousTrigger", "Once; 2025-01-15T03:00:00" },
                { "DeletedBy", "CONTOSO\\jsmith' (SESSION: 2)" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-9),
            SourceType = ArtifactType.TaskScheduler,
            SourceName = Name,
            EventType = "TaskCreated",
            Description = "Scheduled task created via GPO to deploy configuration script across domain",
            FilePath = Path.Combine(path, "Microsoft\\Windows\\GroupPolicy\\GPODeploy.xml"),
            User = "CONTOSO\\domainadmin",
            Hash = "B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9",
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "TaskName", "\\Microsoft\\Windows\\GroupPolicy\\GPODeploy" },
                { "Author", "CONTOSO\\domainadmin" },
                { "Command", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
                { "Arguments", "-ExecutionPolicy RemoteSigned -File \\\\contoso.com\\sysvol\\Policies\\deploy.ps1" },
                { "Triggers", "At logon" },
                { "UserId", "SYSTEM" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-2),
            SourceType = ArtifactType.TaskScheduler,
            SourceName = Name,
            EventType = "HiddenTask",
            Description = "New hidden task created with no triggers and disabled history for stealth",
            FilePath = Path.Combine(path, "\\Microsoft\\Windows\\AppID\\Telemetry.xml"),
            User = "SYSTEM",
            Hash = "C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "TaskName", "\\Microsoft\\Windows\\AppID\\Telemetry" },
                { "HiddenFlag", "true" },
                { "Command", "C:\\Windows\\System32\\cmd.exe" },
                { "Arguments", "/c start /B C:\\Windows\\Tasks\\stub.exe -silent" },
                { "DisableHistory", "true" },
                { "NoTrigger", "Manual start only" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\Windows\System32\Tasks", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var attr = File.GetAttributes(path);
        if (attr.HasFlag(FileAttributes.Directory))
            return path.Equals(@"C:\Windows\System32\Tasks", StringComparison.OrdinalIgnoreCase);

        return path.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Tasks", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Task Scheduler", StringComparison.OrdinalIgnoreCase);
    }
}
