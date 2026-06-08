using MickyAc.Domain.Models;

namespace MickyAc.Domain.Interfaces;

public interface IYARAEngine
{
    Task LoadRulesAsync(string rulesPath);
    Task LoadRuleAsync(YaraRule rule);
    Task<List<YaraMatch>> ScanFileAsync(string filePath);
    Task<List<YaraMatch>> ScanDirectoryAsync(string directoryPath, string pattern = "*.*");
}

public class YaraMatch
{
    public string Rule { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> Tags { get; set; } = new();
    public byte[]? Data { get; set; }
}
