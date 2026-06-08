namespace MickyAc.WPF.Models;

public class PinValidationResult
{
    public bool IsValid { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public string ScanType { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public bool Master { get; set; }
}
