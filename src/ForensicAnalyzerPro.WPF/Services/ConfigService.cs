using System.IO;
using System.Text.Json;
using ForensicAnalyzerPro.WPF.Models;

namespace ForensicAnalyzerPro.WPF.Services;

public class ConfigService
{
    private static readonly string ConfigPath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "config.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public AppConfig Load()
    {
        try
        {
            if (!File.Exists(ConfigPath))
            {
                var defaultConfig = new AppConfig
                {
                    ApiUrl = "http://localhost:3000",
                    DiscordWebhook = ""
                };
                Save(defaultConfig);
                return defaultConfig;
            }

            var json = File.ReadAllText(ConfigPath);
            return JsonSerializer.Deserialize<AppConfig>(json, JsonOpts) ?? new AppConfig();
        }
        catch
        {
            return new AppConfig();
        }
    }

    public void Save(AppConfig config)
    {
        var json = JsonSerializer.Serialize(config, JsonOpts);
        File.WriteAllText(ConfigPath, json);
    }
}
