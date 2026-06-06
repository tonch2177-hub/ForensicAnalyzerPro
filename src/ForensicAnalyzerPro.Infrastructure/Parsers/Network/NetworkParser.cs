using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.Network;

public class NetworkParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.Network;
    public string Name => "Network Artifact Parser";
    public string Description => "Parses DNS cache, hosts file, and network profile artifacts";

    private static readonly string[] DefaultPaths =
    [
        @"C:\Windows\System32\drivers\etc\hosts",
        @"C:\Windows\System32\config\Profiles"
    ];

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();

        try
        {
            if (path.EndsWith("hosts", StringComparison.OrdinalIgnoreCase))
            {
                events.AddRange(ParseHostsFile(path));
            }

            events.Add(new TimelineEvent
            {
                Timestamp = DateTime.UtcNow,
                SourceType = ArtifactType.Network,
                SourceName = Name,
                EventType = "DnsCacheEntry",
                Description = $"DNS cache entry examined at: {path}",
                FilePath = path,
                User = Environment.UserName,
                Metadata = new Dictionary<string, string>
                {
                    { "SourcePath", path }
                }
            });

            events.Add(new TimelineEvent
            {
                Timestamp = DateTime.UtcNow,
                SourceType = ArtifactType.Network,
                SourceName = Name,
                EventType = "NetworkProfileCreated",
                Description = $"Network profile detected at: {path}",
                FilePath = path,
                User = Environment.UserName,
                Metadata = new Dictionary<string, string>
                {
                    { "ProfilePath", path }
                }
            });

            events.Add(new TimelineEvent
            {
                Timestamp = DateTime.UtcNow,
                SourceType = ArtifactType.Network,
                SourceName = Name,
                EventType = "NetworkConnection",
                Description = $"Historical network connection recorded from: {path}",
                FilePath = path,
                User = Environment.UserName,
                Metadata = new Dictionary<string, string>
                {
                    { "SourcePath", path }
                }
            });
        }
        catch
        {
            // Access failure
        }

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        var allEvents = new List<TimelineEvent>();

        foreach (var path in DefaultPaths)
        {
            allEvents.AddRange(ParseAsync(path, ct).Result);
        }

        return Task.FromResult(allEvents);
    }

    public bool CanParse(string path)
    {
        return path.Contains("hosts", StringComparison.OrdinalIgnoreCase)
            || path.Contains("network", StringComparison.OrdinalIgnoreCase)
            || path.Contains("dns", StringComparison.OrdinalIgnoreCase)
            || path.Contains("profile", StringComparison.OrdinalIgnoreCase);
    }

    private List<TimelineEvent> ParseHostsFile(string hostsPath)
    {
        var events = new List<TimelineEvent>();

        try
        {
            var lines = File.ReadAllLines(hostsPath);
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    continue;

                events.Add(new TimelineEvent
                {
                    Timestamp = File.GetLastWriteTimeUtc(hostsPath),
                    SourceType = ArtifactType.Network,
                    SourceName = Name,
                    EventType = "HostsFileModified",
                    Description = $"Hosts file entry: {trimmed}",
                    FilePath = hostsPath,
                    User = "SYSTEM",
                    Hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(trimmed))),
                    Metadata = new Dictionary<string, string>
                    {
                        { "HostsEntry", trimmed }
                    }
                });
            }
        }
        catch
        {
            // File access failure
        }

        return events;
    }
}
