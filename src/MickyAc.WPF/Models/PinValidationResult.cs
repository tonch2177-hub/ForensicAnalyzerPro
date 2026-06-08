namespace MickyAc.WPF.Models;

public class PinValidationResult
{
    public bool IsValid { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public string ScanType { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public int RemainingUses { get; set; }
}
