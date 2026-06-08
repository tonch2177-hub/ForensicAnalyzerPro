using System.Windows;
using MickyAc.Domain.Interfaces;
using MickyAc.Infrastructure.Data;
using MickyAc.Infrastructure.Engines;
using MickyAc.Infrastructure.Engines.IOCScanning;
using MickyAc.Infrastructure.Engines.Timeline;
using MickyAc.Infrastructure.EvidenceManagement;
using MickyAc.Infrastructure.Parsers.Amcache;
using MickyAc.Infrastructure.Parsers.BAM;
using MickyAc.Infrastructure.Parsers.Prefetch;
using MickyAc.Infrastructure.Parsers.USN;
using MickyAc.Infrastructure.Parsers.MFT;
using MickyAc.Infrastructure.Parsers.SRUM;
using MickyAc.Infrastructure.Parsers.EventLog;
using MickyAc.Infrastructure.Parsers.Registry;
using MickyAc.Infrastructure.Parsers.Browser;
using MickyAc.Infrastructure.Parsers.PowerShell;
using MickyAc.Infrastructure.Parsers.Services;
using MickyAc.Infrastructure.Parsers.TaskScheduler;
using MickyAc.Infrastructure.Parsers.Startup;
using MickyAc.Infrastructure.Parsers.USB;
using MickyAc.Infrastructure.Parsers.Network;
using MickyAc.Infrastructure.Reporting;
using MickyAc.Application.Services;
using MickyAc.WPF.Services;
using MickyAc.WPF.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Extensions.Logging;

namespace MickyAc.WPF;

public partial class App : System.Windows.Application
{
    public static IServiceProvider ServiceProvider { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.File("logs/forensic_.log", rollingInterval: RollingInterval.Day, retainedFileCountLimit: 31)
            .CreateLogger();

        var services = new ServiceCollection();

        services.AddDbContext<ForensicDbContext>(options =>
            options.UseSqlite("Data Source=forensic_analyzer.db"));

        services.AddSingleton<Serilog.ILogger>(Log.Logger);
        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddSerilog(dispose: true);
            builder.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);
            builder.AddFilter("Microsoft.EntityFrameworkCore.Infrastructure", LogLevel.Warning);
        });

        // Domain services
        services.AddSingleton<IEvidenceManager, EvidenceManager>();
        services.AddSingleton<ITimelineEngine, TimelineEngine>();
        services.AddSingleton<IIOCEngine, IOCEngine>();
        services.AddSingleton<IReportService, ReportGenerator>();
        services.AddSingleton<IYARAEngine, YARAEngine>();

        // All 15 parsers
        services.AddSingleton<IForensicParser, AmcacheParser>();
        services.AddSingleton<IForensicParser, BAMParser>();
        services.AddSingleton<IForensicParser, PrefetchParser>();
        services.AddSingleton<IForensicParser, USNParser>();
        services.AddSingleton<IForensicParser, MFTParser>();
        services.AddSingleton<IForensicParser, SRUMParser>();
        services.AddSingleton<IForensicParser, EventLogParser>();
        services.AddSingleton<IForensicParser, RegistryParser>();
        services.AddSingleton<IForensicParser, BrowserParser>();
        services.AddSingleton<IForensicParser, PowerShellParser>();
        services.AddSingleton<IForensicParser, ServicesParser>();
        services.AddSingleton<IForensicParser, TaskSchedulerParser>();
        services.AddSingleton<IForensicParser, StartupParser>();
        services.AddSingleton<IForensicParser, USBParser>();
        services.AddSingleton<IForensicParser, NetworkParser>();

        // Scanner infrastructure
        services.AddSingleton<IScanCoordinatorService, ScanCoordinatorService>();
        services.AddSingleton<IServiceScanner, ServiceScanner>();

        // Config & API
        services.AddSingleton<ConfigService>();
        services.AddSingleton<ApiService>();

        // Scanner ViewModel
        services.AddSingleton<ScannerViewModel>();
        services.AddSingleton<MainWindow>();

        ServiceProvider = services.BuildServiceProvider();

        using (var scope = ServiceProvider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ForensicDbContext>();
            db.Database.EnsureCreated();
        }

        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }
}
