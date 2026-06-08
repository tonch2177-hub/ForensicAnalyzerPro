using MickyAc.Domain.Enums;

namespace MickyAc.Domain.Models;

public class ScanResult
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string ScanName { get; set; } = string.Empty;
    public ArtifactType ArtifactType { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Pending;
    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public int TotalItems { get; set; }
    public int NewItems { get; set; }
    public int IoCsDetected { get; set; }
    public List<TimelineEvent> Events { get; set; } = new();
    public List<Evidence> EvidenceList { get; set; } = new();
    public string? ErrorMessage { get; set; }
    public string? CaseId { get; set; }
}
