using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Domain.Interfaces;

public interface ITimelineEngine
{
    Task<List<TimelineEvent>> BuildTimelineAsync(List<List<TimelineEvent>> eventSources);
    Task<List<TimelineEvent>> FilterByDateAsync(List<TimelineEvent> events, DateTime start, DateTime end);
    Task<List<TimelineEvent>> FilterByTypeAsync(List<TimelineEvent> events, string type);
    Task<List<TimelineEvent>> SearchAsync(List<TimelineEvent> events, string query);
    Task<List<IGrouping<DateTime, TimelineEvent>>> GroupByDateAsync(List<TimelineEvent> events);
    Task<List<TimelineEvent>> CorrelateEventsAsync(List<TimelineEvent> events);
}
