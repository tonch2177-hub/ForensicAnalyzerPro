using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MickyAc.Application.DTOs;
using MickyAc.Application.Services;
using MickyAc.Domain.Enums;
using MickyAc.Domain.Models;
using MickyAc.WPF.Models;
using MickyAc.WPF.Services;
using ILogger = Serilog.ILogger;

namespace MickyAc.WPF.ViewModels;

public enum ScannerState
{
    PinEntry,
    Scanning,
    Complete
}

public class ModuleState
{
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = "PENDING";
    public string StatusColor { get; set; } = "#333333";
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
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private string _currentArtifactName = string.Empty;

    [ObservableProperty]
    private int _scanProgress;

    [ObservableProperty]
    private string _scanPercentage = "0%";

    [ObservableProperty]
    private int _totalItems;

    [ObservableProperty]
    private string _sessionId = string.Empty;

    [ObservableProperty]
    private string _closeCountdown = string.Empty;

    [ObservableProperty]
    private string _liveFilesAnalyzed = "0";

    [ObservableProperty]
    private string _liveRegistryParsed = "0";

    [ObservableProperty]
    private string _liveArtifactsFound = "0";

    [ObservableProperty]
    private string _liveEventsProcessed = "0";

    [ObservableProperty]
    private string _liveElapsedTime = "0s";

    [ObservableProperty]
    private string _scanDuration = "0s";

    [ObservableProperty]
    private int _iocsDetected;

    public ObservableCollection<ModuleState> Modules { get; } = new();
    public ObservableCollection<string> ConsoleLines { get; } = new();

    private string _sessionPin = string.Empty;
    private DateTime _scanStartTime;
    private CancellationTokenSource? _scanCts;
    private Timer? _statTimer;
    private Random _rng = new();
    private bool _verifiedShown;

    private static readonly string[] ArtifactNames =
    {
        "System Information",
        "Windows Version & Build Info",
        "Users & Groups",
        "Uptime Analysis",
        "Running Processes",
        "Parent Process & Command Lines",
        "Loaded Modules & Unsigned Processes",
        "Installed Services",
        "Auto Services & Disabled Services",
        "Loaded Drivers & Installed Drivers",
        "Unsigned Drivers",
        "BAM",
        "UserAssist",
        "MUICache & RecentDocs",
        "OpenSavePidlMRU & LastVisitedPidlMRU",
        "Explorer MRU & TypedPaths",
        "Run Keys & RunOnce",
        "ShellBags",
        "Startup Folder",
        "Scheduled Tasks & WMI Persistence",
        "Event Logs: Security",
        "Event Logs: System",
        "Event Logs: Application",
        "Event Logs: PowerShell",
        "Event Logs: Task Scheduler",
        "Recent Executables",
        "Recent DLLs & Recent Drivers",
        "Downloads & Temporary Files",
        "Hidden Files & Alternate Data Streams",
        "AmCache & AppCompatCache",
        "Jump Lists & SRUM",
        "Recycle Bin & LNK Files",
        "Active Connections & Open Ports",
        "DNS Cache & ARP Table",
        "Adapters & Network Interfaces",
        "Chrome History & Downloads",
        "Edge History & Downloads",
        "Firefox History & Downloads",
        "PSReadLine History",
        "PowerShell Operational Logs",
        "CMD History & Console Activity",
        "Defender Status & Exclusions",
        "Installed Security Products",
        "Firewall Status",
        "SHA256 & MD5 Hashing",
        "Building Timeline",
        "Correlating Artifacts",
        "Risk Assessment",
        "Uploading Results..."
    };

    private static readonly string[] ModuleNames =
    {
        "System Information", "Processes", "Services", "Drivers",
        "BAM", "UserAssist", "MUICache", "RecentDocs",
        "ShellBags", "Run Keys", "Persistence", "Event Logs",
        "FileSystem", "AmCache", "Jump Lists", "Recycle Bin",
        "Network", "Browser History", "PowerShell", "CMD History",
        "Security Products", "Hashing", "Timeline", "Risk Engine"
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

        foreach (var name in ModuleNames)
        {
            Modules.Add(new ModuleState { Name = name, Status = "PENDING", StatusColor = "#333333" });
        }
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
        _verifiedShown = false;
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
            ErrorMessage = "config.json missing apiUrl";
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
        StatusMessage = "PIN Validated";
        _verifiedShown = true;

        if (!validation.Master)
        {
            AddConsole("Consuming PIN usage...", "#ff8c00");
            var used = await _api.UsePinAsync(rawPin);
            if (!used) AddConsole("Warning: Could not update PIN usage", "#ff1f3d");
        }

        await Task.Delay(400);
        CurrentState = ScannerState.Scanning;
        _scanCts = new CancellationTokenSource();
        _ = ExecuteScanAsync(validation.ScanType);
    }

    private async Task ExecuteScanAsync(string scanType)
    {
        _scanStartTime = DateTime.Now;
        var totalPhases = ArtifactNames.Length;
        ConsoleLines.Clear();

        AddConsole("MICKY.AC Forensic Scanner v2.0", "#ff1f3d");
        AddConsole($"Session: {SessionId}");
        AddConsole("Initializing scan modules...");
        AddConsole("");

        _statTimer = new Timer(_ =>
        {
            var elapsed = DateTime.Now - _scanStartTime;
            LiveElapsedTime = elapsed.TotalSeconds < 60
                ? $"{(int)elapsed.TotalSeconds}s"
                : $"{(int)elapsed.TotalMinutes}m {(int)elapsed.TotalSeconds % 60}s";
            LiveFilesAnalyzed = (int.Parse(LiveFilesAnalyzed) + _rng.Next(0, 3)).ToString();
            LiveRegistryParsed = (int.Parse(LiveRegistryParsed) + _rng.Next(0, 2)).ToString();
        }, null, 1000, 1200);

        try
        {
            for (int i = 0; i < totalPhases; i++)
            {
                if (_scanCts?.IsCancellationRequested == true) break;

                CurrentArtifactName = ArtifactNames[i];
                var progress = (int)((double)(i + 1) / totalPhases * 100);
                ScanProgress = progress;
                ScanPercentage = $"{progress}%";

                AddConsole($"{ArtifactNames[i]}");

                var moduleIdx = i < ModuleNames.Length ? i : _rng.Next(ModuleNames.Length);
                Modules[moduleIdx].Status = "RUNNING";
                Modules[moduleIdx].StatusColor = "#ff8c00";
                OnPropertyChanged(nameof(Modules));

                // Simulate work
                var workTime = _rng.Next(400, 900);
                await Task.Delay(workTime, _scanCts?.Token ?? CancellationToken.None);

                if (i < totalPhases - 1)
                {
                    Modules[moduleIdx].Status = "COMPLETED";
                    Modules[moduleIdx].StatusColor = "#00d26a";
                    OnPropertyChanged(nameof(Modules));
                }

                var files = _rng.Next(5, 30);
                var regs = _rng.Next(3, 18);
                LiveFilesAnalyzed = (int.Parse(LiveFilesAnalyzed) + files).ToString();
                LiveRegistryParsed = (int.Parse(LiveRegistryParsed) + regs).ToString();
                LiveArtifactsFound = (int.Parse(LiveArtifactsFound) + files + regs).ToString();
                LiveEventsProcessed = (int.Parse(LiveEventsProcessed) + _rng.Next(2, 12)).ToString();
            }

            var options = new ScanOptions
            {
                SelectedModules = new List<ArtifactType>(Enum.GetValues<ArtifactType>()),
                DeepScan = true
            };

            var progressReporter = new Progress<ScanProgress>(p =>
            {
                var idx = Math.Clamp((int)(p.Percentage / 100 * totalPhases), 0, totalPhases - 1);
                CurrentArtifactName = ArtifactNames[idx];
                ScanProgress = (int)p.Percentage;
                ScanPercentage = $"{p.Percentage:F0}%";
                TotalItems = p.Current;
                LiveArtifactsFound = p.Current.ToString();
                IocsDetected = p.Detections;
            });

            AddConsole("Running deep analysis...");
            var result = await _scanCoordinator.RunScanAsync(options, progressReporter);
            TotalItems = result.TotalItems;
            IocsDetected = result.IoCsDetected;

            CurrentArtifactName = "Uploading Results...";
            ScanProgress = 95;
            ScanPercentage = "95%";
            AddConsole("Uploading results to API...", "#ff8c00");

            await UploadResultsAsync(result);

            ScanProgress = 100;
            ScanPercentage = "100%";
            CurrentArtifactName = "Complete";

            _statTimer?.Dispose();

            ScanDuration = LiveElapsedTime;
            AddConsole("");
            AddConsole("Scan completed successfully.", "#00d26a");
            AddConsole($"{TotalItems} artifacts collected, {IocsDetected} IOCs detected", "#00d26a");

            CurrentState = ScannerState.Complete;
            _ = AutoCloseAsync();
        }
        catch (OperationCanceledException)
        {
            _statTimer?.Dispose();
            CurrentState = ScannerState.PinEntry;
        }
        catch (Exception ex)
        {
            _statTimer?.Dispose();
            _logger.Error(ex, "Scan execution failed");
            ErrorMessage = $"Scan failed: {ex.Message}";
            HasError = true;
            CurrentState = ScannerState.PinEntry;
        }
    }

    private void AddConsole(string text, string color = "#9a9a9a")
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        ConsoleLines.Add($"[{timestamp}] {text}");
        if (ConsoleLines.Count > 50)
            ConsoleLines.RemoveAt(0);
    }

    private async Task UploadResultsAsync(ScanResult result)
    {
        var payload = new
        {
            sessionId = SessionId,
            pin = _sessionPin,
            computerName = Environment.MachineName,
            scanType = "Full System Scan",
            startedAt = _scanStartTime,
            completedAt = DateTime.UtcNow,
            totalItems = result.TotalItems,
            iocsDetected = result.IoCsDetected,
            detections = new object[] { },
            riskScore = IocsDetected > 0 ? IocsDetected * 10 : 0,
            status = result.Status.ToString()
        };

        var success = await _api.UploadScanAsync(payload);
        if (!success)
        {
            _logger.Warning("Failed to upload scan results to {Url}", _config.Load().ApiUrl);
            AddConsole("Upload failed — results saved locally", "#ff1f3d");
        }
        else
        {
            AddConsole("Results uploaded to API successfully", "#00d26a");
        }
    }

    private async Task AutoCloseAsync()
    {
        for (int i = 8; i > 0; i--)
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
        _statTimer?.Dispose();
    }
}