using MickyAc.Domain.Enums;

namespace MickyAc.Domain.Models;

public class ForensicCase
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string CaseNumber { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; } = RiskLevel.None;
    public CaseStatus Status { get; set; } = CaseStatus.Open;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ClosedAt { get; set; }
    public string CreatedBy { get; set; } = string.Empty;
    public string? Assignee { get; set; }
    public List<string> Tags { get; set; } = new();
    public List<Evidence> EvidenceList { get; set; } = new();
    public List<TimelineEvent> Events { get; set; } = new();
}
