using MickyAc.Domain.Enums;

namespace MickyAc.Domain.Models;

public class TimelineEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; set; }
    public ArtifactType SourceType { get; set; }
    public string SourceName { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public string? User { get; set; }
    public string? Hash { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.None;
    public Dictionary<string, string> Metadata { get; set; } = new();
    public string? CaseId { get; set; }
    public bool IsFavorite { get; set; }
    public List<string> Tags { get; set; } = new();
}
