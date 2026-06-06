using ForensicAnalyzerPro.Application.DTOs;
using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;
using Microsoft.Extensions.Logging;

namespace ForensicAnalyzerPro.Application.Services;

public class ScanCoordinatorService : IScanCoordinatorService
{
    private readonly IEnumerable<IForensicParser> _parsers;
    private readonly IEvidenceManager _evidenceManager;
    private readonly ITimelineEngine _timelineEngine;
    private readonly IIOCEngine _iocEngine;
    private readonly ILogger<ScanCoordinatorService> _logger;
    private readonly Dictionary<string, CancellationTokenSource> _activeScans = new();

    public ScanCoordinatorService(
        IEnumerable<IForensicParser> parsers,
        IEvidenceManager evidenceManager,
        ITimelineEngine timelineEngine,
        IIOCEngine iocEngine,
        ILogger<ScanCoordinatorService> logger)
    {
        _parsers = parsers;
        _evidenceManager = evidenceManager;
        _timelineEngine = timelineEngine;
        _iocEngine = iocEngine;
        _logger = logger;
    }

    public async Task<ScanResult> RunScanAsync(ScanOptions options, IProgress<ScanProgress>? progress = null)
    {
        var scanId = Guid.NewGuid().ToString();
        var cts = new CancellationTokenSource();
        _activeScans[scanId] = cts;

        var result = new ScanResult
        {
            Id = scanId,
            ScanName = $"Scan_{DateTime.Now:yyyyMMdd_HHmmss}",
            Status = ScanStatus.Running,
            StartedAt = DateTime.UtcNow,
            CaseId = options.CaseId
        };

        try
        {
            var selectedParsers = options.SelectedModules.Count > 0
                ? _parsers.Where(p => options.SelectedModules.Contains(p.ArtifactType))
                : _parsers;

            var allEvents = new List<TimelineEvent>();
            var modules = selectedParsers.ToList();
            result.TotalItems = modules.Count;

            for (int i = 0; i < modules.Count; i++)
            {
                cts.Token.ThrowIfCancellationRequested();

                var parser = modules[i];
                _logger.LogInformation("Starting {ParserName} scan...", parser.Name);

                progress?.Report(new ScanProgress
                {
                    ScanId = scanId,
                    Current = i + 1,
                    Total = modules.Count,
                    Message = $"Scanning {parser.Name}..."
                });

                try
                {
                    var events = options.CustomPath != null && parser.CanParse(options.CustomPath)
                        ? await parser.ParseAsync(options.CustomPath, cts.Token)
                        : await parser.ParseAsync(cts.Token);

                    allEvents.AddRange(events);

                    foreach (var evt in events)
                    {
                        if (!string.IsNullOrEmpty(evt.FilePath) && File.Exists(evt.FilePath))
                        {
                            var evidence = await _evidenceManager.CollectEvidenceAsync(
                                evt.FilePath, evt.EventType, evt.Description);
                            result.EvidenceList.Add(evidence);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error scanning {ParserName}", parser.Name);
                }
            }

            var timeline = await _timelineEngine.BuildTimelineAsync(new List<List<TimelineEvent>> { allEvents });
            result.Events = timeline.OrderBy(e => e.Timestamp).ToList();
            result.NewItems = result.Events.Count;
            result.Status = ScanStatus.Completed;
            result.CompletedAt = DateTime.UtcNow;

            _logger.LogInformation("Scan {ScanId} completed. Found {Count} events.", scanId, result.NewItems);
        }
        catch (OperationCanceledException)
        {
            result.Status = ScanStatus.Cancelled;
            _logger.LogWarning("Scan {ScanId} was cancelled.", scanId);
        }
        catch (Exception ex)
        {
            result.Status = ScanStatus.Failed;
            result.ErrorMessage = ex.Message;
            _logger.LogError(ex, "Scan {ScanId} failed.", scanId);
        }
        finally
        {
            _activeScans.Remove(scanId);
        }

        return result;
    }

    public void CancelScan(string scanId)
    {
        if (_activeScans.TryGetValue(scanId, out var cts))
        {
            cts.Cancel();
        }
    }

    public async Task<ScanResult> RunFullScanAsync(string? caseId = null)
    {
        return await RunScanAsync(new ScanOptions
        {
            SelectedModules = Enum.GetValues<ArtifactType>().ToList(),
            CaseId = caseId,
            DeepScan = true
        });
    }
}

public interface IScanCoordinatorService
{
    Task<ScanResult> RunScanAsync(ScanOptions options, IProgress<ScanProgress>? progress = null);
    void CancelScan(string scanId);
    Task<ScanResult> RunFullScanAsync(string? caseId = null);
}

public class ScanProgress
{
    public string ScanId { get; set; } = string.Empty;
    public int Current { get; set; }
    public int Total { get; set; }
    public string Message { get; set; } = string.Empty;
    public double Percentage => Total > 0 ? (double)Current / Total * 100 : 0;
}
