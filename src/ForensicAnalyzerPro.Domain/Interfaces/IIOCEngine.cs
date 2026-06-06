using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Domain.Interfaces;

public interface IIOCEngine
{
    Task<List<TimelineEvent>> ScanForIoCsAsync(List<TimelineEvent> events, List<IOC> iocs);
    Task<bool> MatchHashAsync(string hash, List<IOC> iocs);
    Task<bool> MatchDomainAsync(string domain, List<IOC> iocs);
    Task<bool> MatchFileNameAsync(string fileName, List<IOC> iocs);
    Task<bool> MatchRegexAsync(string content, string pattern);
}
