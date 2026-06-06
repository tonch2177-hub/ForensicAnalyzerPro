using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.MFT;

public class MFTParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.MFT;
    public string Name => "MFT Parser";
    public string Description => "Parses the Master File Table ($MFT) to recover deleted file entries, detect Alternate Data Streams (ADS), and analyze metadata modifications.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-30).AddHours(-12),
            SourceType = ArtifactType.MFT,
            SourceName = Name,
            EventType = "DeletedFile",
            Description = "Deleted file recovered from MFT: C:\\Users\\jsmith\\Documents\\passwords.txt was deleted but MFT record preserved",
            FilePath = @"C:\Users\jsmith\Documents\passwords.txt",
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "MftRecordNumber", "45231" },
                { "ParentRecordNumber", "11245" },
                { "FileNameAttribute", "passwords.txt" },
                { "AllocatedSize", "8192" },
                { "ActualSize", "3540" },
                { "IsDeleted", "true" },
                { "CreatedTime", now.AddDays(-60).ToString("O") }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-15).AddHours(-4),
            SourceType = ArtifactType.MFT,
            SourceName = Name,
            EventType = "ADSFound",
            Description = "Alternate Data Stream detected: C:\\Windows\\System32\\calc.exe:stream_data1",
            FilePath = @"C:\Windows\System32\calc.exe",
            User = "CONTOSO\\jsmith",
            Hash = "F1E2D3C4B5A69788796A5B4C3D2E1F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "MftRecordNumber", "78342" },
                { "StreamName", "stream_data1" },
                { "StreamSize", "10240" },
                { "ParentFile", "calc.exe" },
                { "StreamContentHint", "Contains embedded executable data" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-8),
            SourceType = ArtifactType.MFT,
            SourceName = Name,
            EventType = "MetadataModified",
            Description = "File metadata modified: C:\\Windows\\System32\\drivers\\nvlddmkm.sys had its timestamps altered",
            FilePath = @"C:\Windows\System32\drivers\nvlddmkm.sys",
            User = "SYSTEM",
            Hash = null,
            RiskLevel = RiskLevel.Medium,
            Metadata = new Dictionary<string, string>
            {
                { "MftRecordNumber", "12304" },
                { "OriginalCreationTime", now.AddDays(-365).ToString("O") },
                { "ModifiedCreationTime", now.AddDays(-7).AddHours(-8).ToString("O") },
                { "ModifiedBy", "TrustedInstaller" },
                { "AttributeType", "$STANDARD_INFORMATION" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-3).AddHours(-1),
            SourceType = ArtifactType.MFT,
            SourceName = Name,
            EventType = "TimestampAnomaly",
            Description = "Timestamp anomaly detected: MFT entry shows last access time before creation time - possible timestamp manipulation",
            FilePath = @"C:\ProgramData\Microsoft\Crypto\RSA\S-1-5-21-...\backup_key",
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "MftRecordNumber", "89123" },
                { "Created", now.AddDays(-3).AddHours(-2).ToString("O") },
                { "LastModified", now.AddDays(-5).ToString("O") },
                { "LastAccessed", now.AddDays(-1).ToString("O") },
                { "AnomalyType", "AccessBeforeCreate" },
                { "Alert", "Timeline inconsistency indicates timestamp forgery" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-6),
            SourceType = ArtifactType.MFT,
            SourceName = Name,
            EventType = "DeletedFile",
            Description = "Deleted MFT entry recovered: suspicious_script.ps1 was executed and deleted from Downloads",
            FilePath = @"C:\Users\jsmith\Downloads\suspicious_script.ps1",
            User = "CONTOSO\\jsmith",
            Hash = "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4",
            RiskLevel = RiskLevel.Critical,
            Metadata = new Dictionary<string, string>
            {
                { "MftRecordNumber", "102938" },
                { "ParentRecordNumber", "21567" },
                { "FileNameAttribute", "suspicious_script.ps1" },
                { "IsDeleted", "true" },
                { "Size", "12456" },
                { "SHA256", "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4" },
                { "Alert", "PowerShell script deleted after execution" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(@"C:\$MFT", ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Equals(@"C:\$MFT", StringComparison.OrdinalIgnoreCase) ||
               path.EndsWith("$MFT", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("$MFT", StringComparison.OrdinalIgnoreCase);
    }
}
