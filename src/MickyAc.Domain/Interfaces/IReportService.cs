using MickyAc.Domain.Models;

namespace MickyAc.Domain.Interfaces;

public interface IReportService
{
    Task<string> GenerateExecutiveReportAsync(ForensicCase caseData, DashboardSummary summary);
    Task<string> GenerateTechnicalReportAsync(List<TimelineEvent> events, List<Evidence> evidence);
    Task<string> GenerateTimelineReportAsync(List<TimelineEvent> events);
    Task<string> GenerateIOCReportAsync(List<IOC> iocs, List<TimelineEvent> matches);
    Task<byte[]> ExportToPdfAsync(string htmlContent);
    Task<string> ExportToCsvAsync<T>(List<T> items);
    Task<string> ExportToJsonAsync<T>(T data);
}
