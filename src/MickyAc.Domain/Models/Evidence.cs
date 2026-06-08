using MickyAc.Domain.Enums;

namespace MickyAc.Domain.Models;

public class Evidence
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ArtifactType SourceType { get; set; }
    public string SourcePath { get; set; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public string SHA256 { get; set; } = string.Empty;
    public string MD5 { get; set; } = string.Empty;
    public long Size { get; set; }
    public DateTime CollectedAt { get; set; } = DateTime.UtcNow;
    public string CollectedBy { get; set; } = string.Empty;
    public string? CaseId { get; set; }
    public string? Notes { get; set; }
    public bool IsFavorite { get; set; }
    public List<string> Tags { get; set; } = new();
    public string? ChainOfCustody { get; set; }
}
