using System.Diagnostics;
using System.Text.RegularExpressions;

namespace ForensicAnalyzerPro.WPF.Services;

public class StoppedServiceInfo
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string StartMode { get; set; } = string.Empty;
    public string ServiceType { get; set; } = string.Empty;
}

public interface IServiceScanner
{
    Task<List<StoppedServiceInfo>> DetectStoppedServicesAsync();
}

public class ServiceScanner : IServiceScanner
{
    private readonly Serilog.ILogger _logger;

    public ServiceScanner(Serilog.ILogger logger)
    {
        _logger = logger;
    }

    public async Task<List<StoppedServiceInfo>> DetectStoppedServicesAsync()
    {
        var services = new List<StoppedServiceInfo>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc",
                Arguments = "query state= inactive",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            services.AddRange(ParseScOutput(output));

            var psi2 = new ProcessStartInfo
            {
                FileName = "sc",
                Arguments = "query state= all",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            using var process2 = new Process { StartInfo = psi2 };
            process2.Start();
            var output2 = await process2.StandardOutput.ReadToEndAsync();
            await process2.WaitForExitAsync();

            var allServices = ParseScOutput(output2);
            var stoppedFromAll = allServices.Where(s =>
                s.Status.Contains("STOPPED", StringComparison.OrdinalIgnoreCase));

            foreach (var svc in stoppedFromAll)
            {
                if (!services.Any(s => s.Name == svc.Name))
                    services.Add(svc);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to detect stopped services");
        }

        return services;
    }

    public async Task<List<StoppedServiceInfo>> GetServiceDetailsAsync(List<string> serviceNames)
    {
        var result = new List<StoppedServiceInfo>();

        foreach (var name in serviceNames)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "sc",
                    Arguments = $"qc \"{name}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = psi };
                process.Start();
                var output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                var info = ParseServiceConfig(output, name);
                if (info != null)
                    result.Add(info);
            }
            catch { }
        }

        return result;
    }

    private static List<StoppedServiceInfo> ParseScOutput(string output)
    {
        var services = new List<StoppedServiceInfo>();
        var blocks = output.Split(new[] { "\r\n\r\n", "\n\n" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var block in blocks)
        {
            var nameMatch = Regex.Match(block, @"SERVICE_NAME:\s+(.+)");
            var displayMatch = Regex.Match(block, @"DISPLAY_NAME:\s+(.+)");
            var statusMatch = Regex.Match(block, @"STATE\s+:\s+\d+\s+(\w+)");
            var typeMatch = Regex.Match(block, @"TYPE\s+:\s+(.+)");

            if (nameMatch.Success)
            {
                services.Add(new StoppedServiceInfo
                {
                    Name = nameMatch.Groups[1].Value.Trim(),
                    DisplayName = displayMatch.Success ? displayMatch.Groups[1].Value.Trim() : "",
                    Status = statusMatch.Success ? statusMatch.Groups[1].Value.Trim() : "UNKNOWN",
                    ServiceType = typeMatch.Success ? typeMatch.Groups[1].Value.Trim() : ""
                });
            }
        }

        return services;
    }

    private static StoppedServiceInfo? ParseServiceConfig(string output, string serviceName)
    {
        var startMatch = Regex.Match(output, @"START_TYPE\s+:\s+\d+\s+(\w+)");
        if (!startMatch.Success) return null;

        var displayMatch = Regex.Match(output, @"DISPLAY_NAME:\s+(.+)");

        return new StoppedServiceInfo
        {
            Name = serviceName,
            DisplayName = displayMatch.Success ? displayMatch.Groups[1].Value.Trim() : "",
            Status = "STOPPED",
            StartMode = startMatch.Groups[1].Value.Trim()
        };
    }
}
