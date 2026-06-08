namespace MickyAc.Domain.Models;

public class YaraRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string RuleContent { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string Author { get; set; } = string.Empty;
    public DateTime? LastModified { get; set; }
    public List<string> Tags { get; set; } = new();
}
