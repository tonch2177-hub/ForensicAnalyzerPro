namespace MickyAc.Application.DTOs;

public class ExportOptions
{
    public string OutputPath { get; set; } = string.Empty;
    public bool IncludeMetadata { get; set; } = true;
    public bool IncludeTimestamps { get; set; } = true;
    public bool IncludeHashes { get; set; } = true;
    public string Format { get; set; } = "JSON";
}
