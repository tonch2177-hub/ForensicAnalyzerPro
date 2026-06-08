using MickyAc.Domain.Enums;

namespace MickyAc.Domain.Models;

public class IOC
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string? Description { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Medium;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string CreatedBy { get; set; } = string.Empty;
    public List<string> Tags { get; set; } = new();
}
