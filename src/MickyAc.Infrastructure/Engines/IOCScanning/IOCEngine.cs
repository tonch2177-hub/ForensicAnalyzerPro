using System.Text.RegularExpressions;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Engines.IOCScanning;

public class IOCEngine : IIOCEngine
{
    public Task<List<TimelineEvent>> ScanForIoCsAsync(List<TimelineEvent> events, List<IOC> iocs)
    {
        var activeIocs = iocs.Where(i => i.IsActive).ToList();

        foreach (var evt in events)
        {
            foreach (var ioc in activeIocs)
            {
                var matched = ioc.Type.ToLowerInvariant() switch
                {
                    "hash" => MatchHashAsync(evt.Hash ?? string.Empty, new List<IOC> { ioc }).Result,
                    "domain" => MatchDomainAsync(evt.Description ?? string.Empty, new List<IOC> { ioc }).Result,
                    "filename" => MatchFileNameAsync(evt.FilePath ?? string.Empty, new List<IOC> { ioc }).Result,
                    "regex" => MatchRegexAsync(evt.Description ?? string.Empty, ioc.Value).Result,
                    _ => false
                };

                if (matched)
                {
                    evt.RiskLevel = ioc.RiskLevel;
                    evt.Metadata["MatchedIOC"] = ioc.Name;
                    evt.Metadata["MatchedIOCValue"] = ioc.Value;
                    evt.Metadata["MatchedIOCOperation"] = ioc.Type;
                    break;
                }
            }
        }

        return Task.FromResult(events);
    }

    public Task<bool> MatchHashAsync(string hash, List<IOC> iocs)
    {
        var match = iocs
            .Where(i => string.Equals(i.Type, "Hash", StringComparison.OrdinalIgnoreCase))
            .Any(i => string.Equals(hash, i.Value, StringComparison.OrdinalIgnoreCase));

        return Task.FromResult(match);
    }

    public Task<bool> MatchDomainAsync(string domain, List<IOC> iocs)
    {
        var match = iocs
            .Where(i => string.Equals(i.Type, "Domain", StringComparison.OrdinalIgnoreCase))
            .Any(i => domain.Contains(i.Value, StringComparison.OrdinalIgnoreCase));

        return Task.FromResult(match);
    }

    public Task<bool> MatchFileNameAsync(string fileName, List<IOC> iocs)
    {
        var match = iocs
            .Where(i => string.Equals(i.Type, "FileName", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(i.Type, "Filename", StringComparison.OrdinalIgnoreCase))
            .Any(i => string.Equals(
                Path.GetFileName(fileName),
                i.Value,
                StringComparison.OrdinalIgnoreCase));

        return Task.FromResult(match);
    }

    public Task<bool> MatchRegexAsync(string content, string pattern)
    {
        try
        {
            return Task.FromResult(Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)));
        }
        catch (RegexMatchTimeoutException)
        {
            return Task.FromResult(false);
        }
    }
}
