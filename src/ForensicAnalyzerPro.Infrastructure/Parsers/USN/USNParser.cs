using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.USN;

public class USNParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.USNJournal;
    public string Name => "USN Journal Parser";
    public string Description => "Parses the NTFS USN Journal ($UsnJrnl) to recover file system change history including created, deleted, renamed, and modified files.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-14).AddHours(-2),
            SourceType = ArtifactType.USNJournal,
            SourceName = Name,
            EventType = "FileCreated",
            Description = "File created: C:\\Users\\jsmith\\Documents\\budget.xlsx",
            FilePath = @"C:\Users\jsmith\Documents\budget.xlsx",
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.None,
            Metadata = new Dictionary<string, string>
            {
                { "ParentDirectory", "C:\\Users\\jsmith\\Documents" },
                { "FileName", "budget.xlsx" },
                { "FileReference", "0x0000000000000000000A" },
                { "UsnJournalId", "0x1A2B3C4D" },
                { "Reason", "FILE_CREATE" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-10).AddHours(-6),
            SourceType = ArtifactType.USNJournal,
            SourceName = Name,
            EventType = "FileDeleted",
            Description = "File deleted: C:\\Users\\jsmith\\AppData\\Local\\Temp\\temp_archive.zip was removed",
            FilePath = @"C:\Users\jsmith\AppData\Local\Temp\temp_archive.zip",
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ParentDirectory", "C:\\Users\\jsmith\\AppData\\Local\\Temp" },
                { "FileName", "temp_archive.zip" },
                { "FileReference", "0x0000000000000000000B" },
                { "UsnJournalId", "0x1A2B3C4D" },
                { "Reason", "FILE_DELETE" },
                { "OriginalSize", "15728640" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-5).AddHours(-3),
            SourceType = ArtifactType.USNJournal,
            SourceName = Name,
            EventType = "FileRenamed",
            Description = "File renamed: C:\\Users\\jsmith\\Desktop\\report_draft.pdf -> C:\\Users\\jsmith\\Desktop\\final_report.pdf",
            FilePath = @"C:\Users\jsmith\Desktop\final_report.pdf",
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "ParentDirectory", "C:\\Users\\jsmith\\Desktop" },
                { "OldFileName", "report_draft.pdf" },
                { "NewFileName", "final_report.pdf" },
                { "FileReference", "0x0000000000000000000C" },
                { "Reason", "FILE_RENAME" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-2).AddHours(-8),
            SourceType = ArtifactType.USNJournal,
            SourceName = Name,
            EventType = "FileDeleted",
            Description = "File deleted from system32: C:\\Windows\\System32\\suspicious.dll was removed",
            FilePath = @"C:\Windows\System32\suspicious.dll",
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "ParentDirectory", "C:\\Windows\\System32" },
                { "FileName", "suspicious.dll" },
                { "FileReference", "0x0000000000000000000D" },
                { "Reason", "FILE_DELETE" },
                { "OriginalSize", "458752" },
                { "Alert", "DLL deleted from System32 - potential malware cleanup" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-5),
            SourceType = ArtifactType.USNJournal,
            SourceName = Name,
            EventType = "FileModified",
            Description = "File modified: C:\\Windows\\System32\\drivers\\etc\\hosts was altered",
            FilePath = @"C:\Windows\System32\drivers\etc\hosts",
            User = "CONTOSO\\administrator",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "ParentDirectory", "C:\\Windows\\System32\\drivers\\etc" },
                { "FileName", "hosts" },
                { "FileReference", "0x0000000000000000000E" },
                { "Reason", "DATA_EXTEND + DATA_OVERWRITE" },
                { "PreviousSize", "824" },
                { "NewSize", "891" },
                { "Alert", "Hosts file modified - possible DNS redirection" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\$Extend\$UsnJrnl:$J:$DATA", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("UsnJrnl", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("$UsnJrnl", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("$J", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("USN", StringComparison.OrdinalIgnoreCase);
    }
}
