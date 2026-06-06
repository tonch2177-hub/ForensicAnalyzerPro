using Serilog;

namespace ForensicAnalyzerPro.Infrastructure.Services;

public class LogService : IDisposable
{
    private readonly ILogger _logger;

    public LogService()
    {
        _logger = new LoggerConfiguration()
            .WriteTo.File(
                path: "logs/forensic_.log",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 31,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .Enrich.FromLogContext()
            .CreateLogger();
    }

    public void Debug(string message, params object?[] propertyValues)
    {
        _logger.Debug(message, propertyValues);
    }

    public void Info(string message, params object?[] propertyValues)
    {
        _logger.Information(message, propertyValues);
    }

    public void Warning(string message, params object?[] propertyValues)
    {
        _logger.Warning(message, propertyValues);
    }

    public void Error(string message, params object?[] propertyValues)
    {
        _logger.Error(message, propertyValues);
    }

    public void Error(Exception exception, string message, params object?[] propertyValues)
    {
        _logger.Error(exception, message, propertyValues);
    }

    public void Fatal(string message, params object?[] propertyValues)
    {
        _logger.Fatal(message, propertyValues);
    }

    public void Fatal(Exception exception, string message, params object?[] propertyValues)
    {
        _logger.Fatal(exception, message, propertyValues);
    }

    public void Dispose()
    {
        Log.CloseAndFlush();
        GC.SuppressFinalize(this);
    }
}
