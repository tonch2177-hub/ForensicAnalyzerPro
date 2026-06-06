using ForensicAnalyzerPro.Domain.Enums;

namespace ForensicAnalyzerPro.Application.DTOs;

public class ScanOptions
{
    public List<ArtifactType> SelectedModules { get; set; } = new();
    public string? CustomPath { get; set; }
    public string? CaseId { get; set; }
    public bool DeepScan { get; set; }
    public bool IncludeDeletedFiles { get; set; }
    public bool IncludeADS { get; set; }
    public int MaxThreads { get; set; } = Environment.ProcessorCount;
}
