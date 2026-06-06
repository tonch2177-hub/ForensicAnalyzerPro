using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ForensicAnalyzerPro.Application.DTOs;
using ForensicAnalyzerPro.Application.Services;
using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Models;
using ForensicAnalyzerPro.WPF.Models;
using ForensicAnalyzerPro.WPF.Services;
using ILogger = Serilog.ILogger;

namespace ForensicAnalyzerPro.WPF.ViewModels;

public enum ScannerState
{
    PinEntry,
    Scanning,
    Complete
}

public partial class ScannerViewModel : ObservableObject
{
    private readonly IScanCoordinatorService _scanCoordinator;
    private readonly IServiceScanner _serviceScanner;
    private readonly ApiService _api;
    private readonly ConfigService _config;
    private readonly ILogger _logger;

    [ObservableProperty]
    private ScannerState _currentState = ScannerState.PinEntry;

    [ObservableProperty]
    private string _pin = string.Empty;

    [ObservableProperty]
    private string _errorMessage = string.Empty;

    [ObservableProperty]
    private bool _hasError;

    [ObservableProperty]
    private string _currentArtifactName = string.Empty;

    [ObservableProperty]
    private int _scanProgress;

    [ObservableProperty]
    private string _scanPercentage = "0%";

    [ObservableProperty]
    private string _estimatedTime = string.Empty;

    [ObservableProperty]
    private int _totalItems;

    [ObservableProperty]
    private string _sessionId = string.Empty;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private string _closeCountdown = string.Empty;

    private string _sessionPin = string.Empty;
    private DateTime _scanStartTime;
    private CancellationTokenSource? _scanCts;

    private static readonly string[] ArtifactNames =
    {
        "Scanning Processes...", "Scanning Drivers...", "Scanning Services...",
        "Scanning Prefetch...", "Scanning ShimCache...", "Scanning AmCache...",
        "Scanning BAM...", "Scanning UserAssist...", "Scanning Shellbags...",
        "Scanning JumpLists...", "Scanning LNK Files...",
        "Scanning Network Connections...", "Scanning IOCs...",
        "Collecting Evidence...", "Uploading Results..."
    };

    public ScannerViewModel(
        IScanCoordinatorService scanCoordinator,
        IServiceScanner serviceScanner,
        ApiService api,
        ConfigService config,
        ILogger logger)
    {
        _scanCoordinator = scanCoordinator;
        _serviceScanner = serviceScanner;
        _api = api;
        _config = config;
        _logger = logger;
    }

    partial void OnPinChanged(string value)
    {
        if (HasError && value.Length > 0)
        {
            HasError = false;
            ErrorMessage = string.Empty;
        }
        if (!string.IsNullOrEmpty(StatusMessage))
            StatusMessage = string.Empty;
    }

    [RelayCommand]
    private async Task StartScan()
    {
        var rawPin = Pin.Trim();

        if (string.IsNullOrEmpty(rawPin))
        {
            ErrorMessage = "Enter a PIN";
            HasError = true;
            return;
        }

        var cfg = _config.Load();
        if (string.IsNullOrWhiteSpace(cfg.ApiUrl))
        {
            ErrorMessage = "config.json missing apiUrl — create config.json with { \"apiUrl\": \"https://...\" }";
            HasError = true;
            return;
        }

        HasError = false;
        StatusMessage = "Validating PIN...";

        var validation = await _api.ValidatePinAsync(rawPin);

        if (!validation.IsValid)
        {
            ErrorMessage = validation.ErrorMessage;
            HasError = true;
            return;
        }

        _sessionPin = rawPin;
        SessionId = validation.SessionId;
        StatusMessage = "PIN Validated — Starting Scan";
        CurrentState = ScannerState.Scanning;

        _scanCts = new CancellationTokenSource();
        await ExecuteScanAsync(validation.ScanType);
    }

    private async Task ExecuteScanAsync(string scanType)
    {
        _scanStartTime = DateTime.Now;
        var totalArtifacts = ArtifactNames.Length;

        try
        {
            for (int i = 0; i < totalArtifacts; i++)
            {
                if (_scanCts?.IsCancellationRequested == true) break;

                CurrentArtifactName = ArtifactNames[i];
                var progress = (int)((double)(i + 1) / totalArtifacts * 100);
                ScanProgress = progress;
                ScanPercentage = $"{progress}%";

                var elapsed = DateTime.Now - _scanStartTime;
                if (i > 0)
                {
                    var avgPerItem = elapsed.TotalSeconds / (i + 1);
                    var remaining = (int)(avgPerItem * (totalArtifacts - i - 1));
                    EstimatedTime = remaining > 60
                        ? $"Estimated: {remaining / 60}m {remaining % 60}s"
                        : $"Estimated: {remaining}s";
                }
                else
                {
                    EstimatedTime = "Calculating...";
                }

                if (i < totalArtifacts - 1)
                {
                    await Task.Delay(800, _scanCts?.Token ?? CancellationToken.None);
                }
            }

            var options = new ScanOptions
            {
                SelectedModules = new List<ArtifactType>(Enum.GetValues<ArtifactType>()),
                DeepScan = true
            };

            var progressReporter = new Progress<ScanProgress>(p =>
            {
                var artifactIdx = Math.Clamp((int)(p.Percentage / 100 * totalArtifacts), 0, totalArtifacts - 1);
                CurrentArtifactName = ArtifactNames[artifactIdx];
                ScanProgress = (int)p.Percentage;
                ScanPercentage = $"{p.Percentage:F0}%";
                TotalItems = p.Current;
            });

            CurrentArtifactName = "Scanning system artifacts...";
            var result = await _scanCoordinator.RunScanAsync(options, progressReporter);
            TotalItems = result.TotalItems;

            CurrentArtifactName = "Uploading Results...";
            ScanProgress = 95;
            ScanPercentage = "95%";

            await UploadResultsAsync(result);

            ScanProgress = 100;
            ScanPercentage = "100%";
            CurrentArtifactName = "Complete";

            CurrentState = ScannerState.Complete;
            _ = AutoCloseAsync();
        }
        catch (OperationCanceledException)
        {
            CurrentState = ScannerState.PinEntry;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Scan execution failed");
            ErrorMessage = $"Scan failed: {ex.Message}";
            HasError = true;
            CurrentState = ScannerState.PinEntry;
        }
    }

    private async Task UploadResultsAsync(ScanResult result)
    {
        var payload = new
        {
            sessionId = SessionId,
            pin = _sessionPin,
            scanType = "Full System Scan",
            startedAt = _scanStartTime,
            completedAt = DateTime.UtcNow,
            totalItems = result.TotalItems,
            iocsDetected = result.IoCsDetected,
            status = result.Status.ToString(),
            hostname = Environment.MachineName,
            username = Environment.UserName
        };

        var success = await _api.UploadScanAsync(payload);
        if (!success)
            _logger.Warning("Failed to upload scan results to {Url}", _config.Load().ApiUrl);
    }

    private async Task AutoCloseAsync()
    {
        for (int i = 5; i > 0; i--)
        {
            CloseCountdown = $"Closing in {i}s";
            await Task.Delay(1000);
        }

        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            System.Windows.Application.Current.Shutdown();
        });
    }

    public void Cancel()
    {
        _scanCts?.Cancel();
    }
}
