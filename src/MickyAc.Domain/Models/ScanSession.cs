namespace MickyAc.Domain.Models;

public class ScanSession
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12].ToUpper();
    public string Pin { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";
    public string ScanType { get; set; } = string.Empty;
    public string DownloadToken { get; set; } = string.Empty;
    public string HostName { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string ScannerVersion { get; set; } = string.Empty;
    public string WebhookUrl { get; set; } = string.Empty;
    public string ResultChannelId { get; set; } = string.Empty;
    public string DiscordGuildId { get; set; } = string.Empty;
    public string DiscordUserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddHours(1);
    public DateTime? CompletedAt { get; set; }
    public int MaxUses { get; set; } = 1;
    public int CurrentUses { get; set; }
    public long? DownloadMessageId { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
}
