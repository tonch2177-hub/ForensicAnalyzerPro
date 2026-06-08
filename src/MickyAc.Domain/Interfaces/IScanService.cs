using MickyAc.Domain.Enums;
using MickyAc.Domain.Models;

namespace MickyAc.Domain.Interfaces;

public interface IScanService
{
    Task<ScanResult> StartScanAsync(ArtifactType type, string? path = null, string? caseId = null);
    Task<ScanResult> StartFullScanAsync(string? caseId = null);
    Task CancelScanAsync(string scanId);
    Task<List<ScanResult>> GetScanHistoryAsync();
    event EventHandler<ScanResult>? ScanCompleted;
    event EventHandler<ScanProgressEventArgs>? ScanProgress;
}

public class ScanProgressEventArgs : EventArgs
{
    public string ScanId { get; set; } = string.Empty;
    public int Current { get; set; }
    public int Total { get; set; }
    public string Message { get; set; } = string.Empty;
    public double Percentage => Total > 0 ? (double)Current / Total * 100 : 0;
}
