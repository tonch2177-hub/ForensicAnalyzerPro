using System.Windows;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Infrastructure.Data;
using ForensicAnalyzerPro.Infrastructure.Engines;
using ForensicAnalyzerPro.Infrastructure.Engines.IOCScanning;
using ForensicAnalyzerPro.Infrastructure.Engines.Timeline;
using ForensicAnalyzerPro.Infrastructure.EvidenceManagement;
using ForensicAnalyzerPro.Infrastructure.Parsers.Amcache;
using ForensicAnalyzerPro.Infrastructure.Parsers.BAM;
using ForensicAnalyzerPro.Infrastructure.Parsers.Prefetch;
using ForensicAnalyzerPro.Infrastructure.Parsers.USN;
using ForensicAnalyzerPro.Infrastructure.Parsers.MFT;
using ForensicAnalyzerPro.Infrastructure.Parsers.SRUM;
using ForensicAnalyzerPro.Infrastructure.Parsers.EventLog;
using ForensicAnalyzerPro.Infrastructure.Parsers.Registry;
using ForensicAnalyzerPro.Infrastructure.Parsers.Browser;
using ForensicAnalyzerPro.Infrastructure.Parsers.PowerShell;
using ForensicAnalyzerPro.Infrastructure.Parsers.Services;
using ForensicAnalyzerPro.Infrastructure.Parsers.TaskScheduler;
using ForensicAnalyzerPro.Infrastructure.Parsers.Startup;
using ForensicAnalyzerPro.Infrastructure.Parsers.USB;
using ForensicAnalyzerPro.Infrastructure.Parsers.Network;
using ForensicAnalyzerPro.Infrastructure.Reporting;
using ForensicAnalyzerPro.Application.Services;
using ForensicAnalyzerPro.WPF.Services;
using ForensicAnalyzerPro.WPF.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Extensions.Logging;

namespace ForensicAnalyzerPro.WPF;

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
