using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Domain.Interfaces;

public interface IForensicParser
{
    ArtifactType ArtifactType { get; }
    string Name { get; }
    string Description { get; }
    Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default);
    Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default);
    bool CanParse(string path);
}
