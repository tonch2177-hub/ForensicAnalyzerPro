using MickyAc.Domain.Enums;
using MickyAc.Domain.Models;

namespace MickyAc.Domain.Interfaces;

public interface IForensicParser
{
    ArtifactType ArtifactType { get; }
    string Name { get; }
    string Description { get; }
    Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default);
    Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default);
    bool CanParse(string path);
}
