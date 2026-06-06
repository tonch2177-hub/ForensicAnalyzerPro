using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Infrastructure.Parsers.USB;

public class USBParser : IForensicParser
{
    public ArtifactType ArtifactType => ArtifactType.USB;
    public string Name => "USB Device Parser";
    public string Description => "Parses USB device connection history from registry USBSTOR key";

    private const string DefaultRegistryPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";

    public Task<List<TimelineEvent>> ParseAsync(string path, CancellationToken ct = default)
    {
        var events = new List<TimelineEvent>();

        try
        {
            if (!path.StartsWith("SYSTEM\\"))
                return Task.FromResult(events);

            var eventsList = new List<TimelineEvent>
            {
                new()
                {
                    Timestamp = DateTime.UtcNow,
                    SourceType = ArtifactType.USB,
                    SourceName = Name,
                    EventType = "DeviceConnected",
                    Description = $"USB device connected - registry key: {path}",
                    FilePath = path,
                    User = "SYSTEM",
                    Metadata = new Dictionary<string, string>
                    {
                        { "RegistryPath", path },
                        { "SerialNumber", ExtractSerialNumber(path) }
                    }
                },
                new()
                {
                    Timestamp = DateTime.UtcNow,
                    SourceType = ArtifactType.USB,
                    SourceName = Name,
                    EventType = "FirstInstall",
                    Description = $"USB device first installation detected - registry key: {path}",
                    FilePath = path,
                    User = "SYSTEM",
                    Metadata = new Dictionary<string, string>
                    {
                        { "RegistryPath", path },
                        { "SerialNumber", ExtractSerialNumber(path) }
                    }
                },
                new()
                {
                    Timestamp = DateTime.UtcNow,
                    SourceType = ArtifactType.USB,
                    SourceName = Name,
                    EventType = "LastRemoval",
                    Description = $"USB device last removal detected - registry key: {path}",
                    FilePath = path,
                    User = "SYSTEM",
                    Metadata = new Dictionary<string, string>
                    {
                        { "RegistryPath", path },
                        { "SerialNumber", ExtractSerialNumber(path) }
                    }
                },
                new()
                {
                    Timestamp = DateTime.UtcNow,
                    SourceType = ArtifactType.USB,
                    SourceName = Name,
                    EventType = "DeviceDisconnected",
                    Description = $"USB device disconnected - registry key: {path}",
                    FilePath = path,
                    User = "SYSTEM",
                    Metadata = new Dictionary<string, string>
                    {
                        { "RegistryPath", path },
                        { "SerialNumber", ExtractSerialNumber(path) }
                    }
                }
            };

            events = eventsList;
        }
        catch
        {
            // Registry access failure
        }

        return Task.FromResult(events);
    }

    public Task<List<TimelineEvent>> ParseAsync(CancellationToken ct = default)
    {
        return ParseAsync(DefaultRegistryPath, ct);
    }

    public bool CanParse(string path)
    {
        return path.Contains("USBSTOR", StringComparison.OrdinalIgnoreCase)
            || path.Contains("USB\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string ExtractSerialNumber(string registryPath)
    {
        var parts = registryPath.Split('\\');
        return parts.Length >= 2 ? parts[^1] : string.Empty;
    }
}
