using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.Engines.Timeline;

public class TimelineEngine : ITimelineEngine
{
    public Task<List<TimelineEvent>> BuildTimelineAsync(List<List<TimelineEvent>> eventSources)
    {
        var merged = eventSources
            .SelectMany(x => x)
            .GroupBy(e => e.Id)
            .Select(g => g.First())
            .OrderBy(e => e.Timestamp)
            .ToList();

        var correlated = CorrelateInternal(merged);

        return Task.FromResult(correlated);
    }

    public Task<List<TimelineEvent>> FilterByDateAsync(List<TimelineEvent> events, DateTime start, DateTime end)
    {
        var filtered = events
            .Where(e => e.Timestamp >= start && e.Timestamp <= end)
            .ToList();

        return Task.FromResult(filtered);
    }

    public Task<List<TimelineEvent>> FilterByTypeAsync(List<TimelineEvent> events, string type)
    {
        var filtered = events
            .Where(e => string.Equals(e.EventType, type, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return Task.FromResult(filtered);
    }

    public Task<List<TimelineEvent>> SearchAsync(List<TimelineEvent> events, string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return Task.FromResult(events);

        var q = query.Trim();
        var results = events
            .Where(e =>
                (e.Description?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.FilePath?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.EventType?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.User?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false))
            .ToList();

        return Task.FromResult(results);
    }

    public Task<List<IGrouping<DateTime, TimelineEvent>>> GroupByDateAsync(List<TimelineEvent> events)
    {
        var grouped = events
            .GroupBy(e => e.Timestamp.Date)
            .OrderBy(g => g.Key)
            .ToList();

        return Task.FromResult<List<IGrouping<DateTime, TimelineEvent>>>(grouped);
    }

    public Task<List<TimelineEvent>> CorrelateEventsAsync(List<TimelineEvent> events)
    {
        var correlated = CorrelateInternal(events);
        return Task.FromResult(correlated);
    }

    private static List<TimelineEvent> CorrelateInternal(List<TimelineEvent> events)
    {
        if (events.Count < 2)
            return events;

        var sorted = events.OrderBy(e => e.Timestamp).ToList();
        var result = new List<TimelineEvent>();
        var processed = new HashSet<string>();

        for (var i = 0; i < sorted.Count; i++)
        {
            if (processed.Contains(sorted[i].Id))
                continue;

            var group = new List<TimelineEvent> { sorted[i] };
            processed.Add(sorted[i].Id);

            for (var j = i + 1; j < sorted.Count; j++)
            {
                if (processed.Contains(sorted[j].Id))
                    continue;

                var diff = (sorted[j].Timestamp - sorted[i].Timestamp).TotalSeconds;
                if (diff <= 5)
                {
                    group.Add(sorted[j]);
                    processed.Add(sorted[j].Id);
                }
                else
                {
                    break;
                }
            }

            if (group.Count > 1)
            {
                foreach (var evt in group)
                {
                    evt.Metadata["CorrelatedWith"] = string.Join(", ", group
                        .Where(g => g.Id != evt.Id)
                        .Select(g => $"{g.EventType}[{g.Id}]"));
                }
            }

            result.AddRange(group);
        }

        return result.OrderBy(e => e.Timestamp).ToList();
    }
}
