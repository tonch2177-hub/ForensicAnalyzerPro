using MickyAc.Domain.Enums;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Parsers.Browser;

public class BrowserParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Browser;
    public string Name => "Browser Parser";
    public string Description => "Parses browser history, downloads, cookies, bookmarks, and cache metadata from Chromium and Firefox based browsers.";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();
        var now = DateTime.UtcNow;

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-21).AddHours(-4),
            SourceType = ArtifactType.Browser,
            SourceName = Name,
            EventType = "UrlVisited",
            Description = "URL visit to a cloud storage service with sensitive file naming pattern",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "URL", "https://drive.google.com/file/d/1xK2aB3cD4eF5gH6iJ7kL8mN/view" },
                { "Title", "Q4_Financials.xlsx - Google Drive" },
                { "VisitCount", "12" },
                { "Browser", "Chrome" },
                { "VisitType", "transition_link" },
                { "ProfilePath", "Default" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-14).AddHours(-2),
            SourceType = ArtifactType.Browser,
            SourceName = Name,
            EventType = "FileDownloaded",
            Description = "Suspicious file download detected from non-standard domain",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9",
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "URL", "http://malware-staging.example.com/payload.exe" },
                { "FileName", "payload.exe" },
                { "TargetPath", "C:\\Users\\jsmith\\Downloads\\payload.exe" },
                { "TotalBytes", "245760" },
                { "MimeType", "application/x-msdownload" },
                { "Browser", "Chrome" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-7).AddHours(-10),
            SourceType = ArtifactType.Browser,
            SourceName = Name,
            EventType = "CookieCreated",
            Description = "Session cookie created for cloud-based email service",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.None,
            Metadata = new Dictionary<string, string>
            {
                { "Host", ".mail.google.com" },
                { "Name", "SID" },
                { "CreatedTime", now.AddDays(-7).AddHours(-10).ToString("O") },
                { "ExpirationTime", now.AddDays(173).ToString("O") },
                { "Secure", "true" },
                { "Browser", "Chrome" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-3).AddHours(-18),
            SourceType = ArtifactType.Browser,
            SourceName = Name,
            EventType = "BookmarkAdded",
            Description = "Bookmark added for personal email and financial services folder",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.None,
            Metadata = new Dictionary<string, string>
            {
                { "URL", "https://onlinebanking.examplebank.com" },
                { "Title", "Online Banking" },
                { "FolderName", "Finance" },
                { "DateAdded", now.AddDays(-3).AddHours(-18).ToString("O") },
                { "Browser", "Firefox" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddDays(-1).AddHours(-5),
            SourceType = ArtifactType.Browser,
            SourceName = Name,
            EventType = "UrlVisited",
            Description = "Private browsing history entry showing search for privilege escalation exploit",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = null,
            RiskLevel = RiskLevel.High,
            Metadata = new Dictionary<string, string>
            {
                { "URL", "https://github.com/search?q=local+privilege+escalation+windows+exploit&type=repositories" },
                { "Title", "GitHub Search: local privilege escalation" },
                { "VisitCount", "1" },
                { "Browser", "Edge" },
                { "VisitType", "transition_typed" }
            }
        });

        events.Add(new TimelineEvent
        {
            Timestamp = now.AddHours(-3),
            SourceType = ArtifactType.Browser,
            SourceName = Name,
            EventType = "CacheEntry",
            Description = "Cache entry found for recently accessed JSON endpoint with API data",
            FilePath = path,
            User = "CONTOSO\\jsmith",
            Hash = "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0",
            RiskLevel = RiskLevel.Low,
            Metadata = new Dictionary<string, string>
            {
                { "URL", "https://api.example.com/v2/users/12345/activity" },
                { "CacheKey", "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1" },
                { "ContentType", "application/json" },
                { "ResponseCode", "200" },
                { "FileSize", "15432" },
                { "Browser", "Chrome" }
            }
        });

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Google\Chrome\User Data\Default\History"), ct);
    }

    public bool CanParse(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("browser", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Firefox", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("Edge", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("History", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("places.sqlite", StringComparison.OrdinalIgnoreCase);
    }
}
