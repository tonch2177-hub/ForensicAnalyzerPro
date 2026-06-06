using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using ForensicAnalyzerPro.WPF.Models;

namespace ForensicAnalyzerPro.WPF.Services;

public class ApiService
{
    private readonly HttpClient _http;
    private readonly ConfigService _config;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public ApiService(ConfigService config)
    {
        _config = config;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    private string BaseUrl => _config.Load().ApiUrl.TrimEnd('/');

    public async Task<PinValidationResult> ValidatePinAsync(string pin)
    {
        try
        {
            var url = $"{BaseUrl}/api/validate-pin";
            var response = await _http.PostAsJsonAsync(url, new { pin }, JsonOpts);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                return new PinValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"API Error ({response.StatusCode}): {errorBody}"
                };
            }

            var result = await response.Content.ReadFromJsonAsync<PinValidationResult>(JsonOpts);
            return result ?? new PinValidationResult { IsValid = false, ErrorMessage = "Empty response from API" };
        }
        catch (HttpRequestException ex)
        {
            return new PinValidationResult
            {
                IsValid = false,
                ErrorMessage = $"Connection failed: {ex.Message}"
            };
        }
        catch (TaskCanceledException)
        {
            return new PinValidationResult
            {
                IsValid = false,
                ErrorMessage = "API request timed out"
            };
        }
    }

    public async Task<bool> UploadScanAsync(object scanResult)
    {
        try
        {
            var url = $"{BaseUrl}/api/upload-scan";
            var response = await _http.PostAsJsonAsync(url, scanResult, JsonOpts);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}
