using System.Data;
using System.Reflection;
using System.Text;
using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Interfaces;
using ForensicAnalyzerPro.Domain.Models;
using Newtonsoft.Json;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace ForensicAnalyzerPro.Infrastructure.Reporting;

public class ReportGenerator : IReportService
{
    public Task<string> GenerateExecutiveReportAsync(ForensicCase caseData, DashboardSummary summary)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        sb.AppendLine("<title>Executive Report - ForensicAnalyzerPro</title>");
        sb.AppendLine("<style>body{font-family:Arial;margin:40px;color:#333}");
        sb.AppendLine("h1{color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:10px}");
        sb.AppendLine("h2{color:#283593;margin-top:30px}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;margin:10px 0 20px 0}");
        sb.AppendLine("th,td{border:1px solid #ddd;padding:10px;text-align:left}");
        sb.AppendLine("th{background-color:#1a237e;color:white}");
        sb.AppendLine("tr:nth-child(even){background-color:#f5f5f5}");
        sb.AppendLine(".risk-critical{color:#d32f2f;font-weight:bold}");
        sb.AppendLine(".risk-high{color:#f57c00;font-weight:bold}");
        sb.AppendLine(".risk-medium{color:#fbc02d}");
        sb.AppendLine(".risk-low{color:#388e3c}");
        sb.AppendLine(".risk-none{color:#9e9e9e}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Executive Report</h1>");
        sb.AppendLine($"<h2>Case: {caseData.Title}</h2>");
        sb.AppendLine($"<p><strong>Case Number:</strong> {caseData.CaseNumber}</p>");
        sb.AppendLine($"<p><strong>Status:</strong> {caseData.Status}</p>");
        sb.AppendLine($"<p><strong>Risk Level:</strong> <span class='risk-{caseData.RiskLevel.ToString().ToLower()}'>{caseData.RiskLevel}</span></p>");
        sb.AppendLine($"<p><strong>Created:</strong> {caseData.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC</p>");
        sb.AppendLine($"<p><strong>Created By:</strong> {caseData.CreatedBy}</p>");
        sb.AppendLine($"<p>{caseData.Description}</p>");

        sb.AppendLine("<h2>Summary Statistics</h2>");
        sb.AppendLine("<table>");
        sb.AppendLine("<tr><th>Metric</th><th>Value</th></tr>");
        sb.AppendLine($"<tr><td>Total Artifacts</td><td>{summary.TotalArtifacts}</td></tr>");
        sb.AppendLine($"<tr><td>Total Evidence Items</td><td>{summary.TotalEvidence}</td></tr>");
        sb.AppendLine($"<tr><td>Total Cases</td><td>{summary.TotalCases}</td></tr>");
        sb.AppendLine($"<tr><td>Total IOCs</td><td>{summary.TotalIoCs}</td></tr>");
        sb.AppendLine($"<tr><td>High Risk IOCs</td><td>{summary.HighRiskIoCs}</td></tr>");
        sb.AppendLine($"<tr><td>Recent Events</td><td>{summary.RecentEvents}</td></tr>");
        sb.AppendLine($"<tr><td>Scans Completed</td><td>{summary.ScansCompleted}</td></tr>");
        sb.AppendLine($"<tr><td>Scans Running</td><td>{summary.ScansRunning}</td></tr>");
        sb.AppendLine("</table>");

        if (summary.RiskDistribution.Count > 0)
        {
            sb.AppendLine("<h2>Risk Distribution</h2>");
            sb.AppendLine("<table><tr><th>Level</th><th>Count</th></tr>");
            foreach (var rd in summary.RiskDistribution)
                sb.AppendLine($"<tr><td>{rd.Level}</td><td>{rd.Count}</td></tr>");
            sb.AppendLine("</table>");
        }

        if (summary.ArtifactDistribution.Count > 0)
        {
            sb.AppendLine("<h2>Artifact Distribution</h2>");
            sb.AppendLine("<table><tr><th>Type</th><th>Count</th></tr>");
            foreach (var ad in summary.ArtifactDistribution)
                sb.AppendLine($"<tr><td>{ad.Type}</td><td>{ad.Count}</td></tr>");
            sb.AppendLine("</table>");
        }

        if (summary.RecentTimelineEvents.Count > 0)
        {
            sb.AppendLine("<h2>Recent Timeline Events</h2>");
            sb.AppendLine("<table><tr><th>Timestamp</th><th>Event Type</th><th>Description</th><th>Risk</th></tr>");
            foreach (var evt in summary.RecentTimelineEvents.Take(20))
            {
                var riskClass = $"risk-{evt.RiskLevel.ToString().ToLower()}";
                sb.AppendLine($"<tr><td>{evt.Timestamp:yyyy-MM-dd HH:mm:ss}</td><td>{evt.EventType}</td><td>{evt.Description}</td><td class='{riskClass}'>{evt.RiskLevel}</td></tr>");
            }
            sb.AppendLine("</table>");
        }

        sb.AppendLine("</body></html>");
        return Task.FromResult(sb.ToString());
    }

    public Task<string> GenerateTechnicalReportAsync(List<TimelineEvent> events, List<Evidence> evidence)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        sb.AppendLine("<title>Technical Report - ForensicAnalyzerPro</title>");
        sb.AppendLine("<style>body{font-family:'Consolas',monospace;margin:40px;color:#333}");
        sb.AppendLine("h1{color:#1a237e;border-bottom:2px solid #1a237e}");
        sb.AppendLine("h2{color:#283593;margin-top:30px}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;margin:10px 0 20px;font-size:12px}");
        sb.AppendLine("th,td{border:1px solid #999;padding:6px 8px;text-align:left}");
        sb.AppendLine("th{background-color:#37474f;color:white}");
        sb.AppendLine("tr:nth-child(even){background-color:#eceff1}");
        sb.AppendLine(".meta-key{font-weight:bold;color:#1565c0}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Technical Report</h1>");
        sb.AppendLine($"<p>Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>");
        sb.AppendLine($"<p>Total Events: {events.Count} | Total Evidence: {evidence.Count}</p>");

        sb.AppendLine("<h2>Event Listing</h2>");
        sb.AppendLine("<table><tr><th>Timestamp</th><th>Event Type</th><th>Source</th><th>Description</th><th>File Path</th><th>User</th><th>Risk</th><th>Metadata</th></tr>");
        var ordered = events.OrderByDescending(e => e.Timestamp).ToList();
        foreach (var evt in ordered)
        {
            var metaHtml = string.Join("<br>", evt.Metadata.Select(m => $"<span class='meta-key'>{m.Key}:</span> {m.Value}"));
            sb.AppendLine($"<tr><td>{evt.Timestamp:yyyy-MM-dd HH:mm:ss}</td><td>{evt.EventType}</td><td>{evt.SourceName}</td><td>{evt.Description}</td><td>{evt.FilePath}</td><td>{evt.User}</td><td>{evt.RiskLevel}</td><td>{metaHtml}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine("<h2>Evidence Information</h2>");
        sb.AppendLine("<table><tr><th>Name</th><th>Source</th><th>SHA256</th><th>MD5</th><th>Size</th><th>Collected</th><th>Case ID</th></tr>");
        foreach (var ev in evidence)
        {
            sb.AppendLine($"<tr><td>{ev.Name}</td><td>{ev.SourcePath}</td><td style='font-size:10px'>{ev.SHA256}</td><td style='font-size:10px'>{ev.MD5}</td><td>{ev.Size}</td><td>{ev.CollectedAt:yyyy-MM-dd HH:mm:ss}</td><td>{ev.CaseId}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine("</body></html>");
        return Task.FromResult(sb.ToString());
    }

    public Task<string> GenerateTimelineReportAsync(List<TimelineEvent> events)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        sb.AppendLine("<title>Timeline Report - ForensicAnalyzerPro</title>");
        sb.AppendLine("<style>body{font-family:Arial;margin:40px;color:#333}");
        sb.AppendLine("h1{color:#1a237e;border-bottom:2px solid #1a237e}");
        sb.AppendLine(".timeline{position:relative;padding:20px 0}");
        sb.AppendLine(".timeline::after{content:'';position:absolute;width:4px;background-color:#1a237e;top:0;bottom:0;left:20px}");
        sb.AppendLine(".event{margin:20px 0;padding:12px 20px 12px 50px;position:relative;border-radius:6px;border:1px solid #ddd}");
        sb.AppendLine(".event::before{content:'';position:absolute;width:16px;height:16px;left:14px;top:16px;border-radius:50%;z-index:1}");
        sb.AppendLine(".risk-critical{border-left:4px solid #d32f2f;background:#ffebee}.risk-critical::before{background:#d32f2f}");
        sb.AppendLine(".risk-high{border-left:4px solid #f57c00;background:#fff3e0}.risk-high::before{background:#f57c00}");
        sb.AppendLine(".risk-medium{border-left:4px solid #fbc02d;background:#fffde7}.risk-medium::before{background:#fbc02d}");
        sb.AppendLine(".risk-low{border-left:4px solid #388e3c;background:#e8f5e9}.risk-low::before{background:#388e3c}");
        sb.AppendLine(".risk-none{border-left:4px solid #9e9e9e;background:#f5f5f5}.risk-none::before{background:#9e9e9e}");
        sb.AppendLine(".event-time{font-size:12px;color:#666;margin-bottom:4px}");
        sb.AppendLine(".event-type{font-weight:bold;color:#1a237e;font-size:14px}");
        sb.AppendLine(".event-desc{font-size:13px;margin-top:4px}");
        sb.AppendLine(".event-meta{font-size:11px;color:#888;margin-top:4px}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Timeline Report</h1>");
        sb.AppendLine($"<p>Total Events: {events.Count} | Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>");

        sb.AppendLine("<div class='timeline'>");
        var sorted = events.OrderBy(e => e.Timestamp).ToList();
        foreach (var evt in sorted)
        {
            var riskClass = $"risk-{evt.RiskLevel.ToString().ToLower()}";
            var metaText = string.Join(" | ", evt.Metadata.Select(m => $"{m.Key}: {m.Value}"));
            sb.AppendLine($"<div class='event {riskClass}'>");
            sb.AppendLine($"<div class='event-time'>{evt.Timestamp:yyyy-MM-dd HH:mm:ss} UTC</div>");
            sb.AppendLine($"<div class='event-type'>[{evt.EventType}] {evt.SourceName}</div>");
            sb.AppendLine($"<div class='event-desc'>{evt.Description}</div>");
            sb.AppendLine($"<div class='event-meta'>User: {evt.User} | Risk: {evt.RiskLevel} | File: {evt.FilePath}{(metaText.Length > 0 ? $" | {metaText}" : "")}</div>");
            sb.AppendLine("</div>");
        }
        sb.AppendLine("</div>");

        sb.AppendLine("</body></html>");
        return Task.FromResult(sb.ToString());
    }

    public Task<string> GenerateIOCReportAsync(List<IOC> iocs, List<TimelineEvent> matches)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        sb.AppendLine("<title>IOC Report - ForensicAnalyzerPro</title>");
        sb.AppendLine("<style>body{font-family:Arial;margin:40px;color:#333}");
        sb.AppendLine("h1{color:#1a237e;border-bottom:2px solid #1a237e}");
        sb.AppendLine("h2{color:#283593;margin-top:30px}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;margin:10px 0 20px;font-size:13px}");
        sb.AppendLine("th,td{border:1px solid #999;padding:8px;text-align:left}");
        sb.AppendLine("th{background-color:#1a237e;color:white}");
        sb.AppendLine("tr:nth-child(even){background-color:#f5f5f5}");
        sb.AppendLine(".risk-critical{background-color:#ffebee}");
        sb.AppendLine(".risk-high{background-color:#fff3e0}");
        sb.AppendLine(".risk-medium{background-color:#fffde7}");
        sb.AppendLine(".risk-low{background-color:#e8f5e9}");
        sb.AppendLine(".risk-none{background-color:#f5f5f5}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Indicators of Compromise (IOC) Report</h1>");
        sb.AppendLine($"<p>Total IOCs: {iocs.Count} | Matched Events: {matches.Count}</p>");

        sb.AppendLine("<h2>IOC Definitions</h2>");
        sb.AppendLine("<table><tr><th>Name</th><th>Type</th><th>Value</th><th>Risk Level</th><th>Active</th><th>Description</th></tr>");
        foreach (var ioc in iocs)
        {
            var riskClass = $"risk-{ioc.RiskLevel.ToString().ToLower()}";
            sb.AppendLine($"<tr class='{riskClass}'><td>{ioc.Name}</td><td>{ioc.Type}</td><td style='font-family:Consolas'>{ioc.Value}</td><td>{ioc.RiskLevel}</td><td>{ioc.IsActive}</td><td>{ioc.Description}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine("<h2>Matched Events</h2>");
        sb.AppendLine("<table><tr><th>Timestamp</th><th>Event Type</th><th>Description</th><th>Matched IOC</th><th>Risk Level</th><th>User</th></tr>");
        foreach (var evt in matches)
        {
            var matchedIoc = evt.Metadata.GetValueOrDefault("MatchedIOC", "N/A");
            var riskClass = $"risk-{evt.RiskLevel.ToString().ToLower()}";
            sb.AppendLine($"<tr class='{riskClass}'><td>{evt.Timestamp:yyyy-MM-dd HH:mm:ss}</td><td>{evt.EventType}</td><td>{evt.Description}</td><td>{matchedIoc}</td><td>{evt.RiskLevel}</td><td>{evt.User}</td></tr>");
        }
        sb.AppendLine("</table>");

        sb.AppendLine("</body></html>");
        return Task.FromResult(sb.ToString());
    }

    public Task<byte[]> ExportToPdfAsync(string htmlContent)
    {
        QuestPDF.Settings.License = LicenseType.Community;

        var document = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(2, Unit.Centimetre);
                page.DefaultTextStyle(TextStyle.Default.FontSize(12));
                page.Content().Element(c => ComposeContent(c, htmlContent));
            });
        });

        var pdfBytes = document.GeneratePdf();
        return Task.FromResult(pdfBytes);
    }

    public Task<string> ExportToCsvAsync<T>(List<T> items)
    {
        if (items.Count == 0)
            return Task.FromResult(string.Empty);

        var sb = new StringBuilder();
        var properties = typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance);

        var headerLine = string.Join(",", properties.Select(p => EscapeCsvField(p.Name)));
        sb.AppendLine(headerLine);

        foreach (var item in items)
        {
            var values = properties.Select(p =>
            {
                var val = p.GetValue(item);
                return EscapeCsvField(val?.ToString() ?? string.Empty);
            });
            sb.AppendLine(string.Join(",", values));
        }

        return Task.FromResult(sb.ToString());
    }

    public Task<string> ExportToJsonAsync<T>(T data)
    {
        var json = JsonConvert.SerializeObject(data, Formatting.Indented);
        return Task.FromResult(json);
    }

    private static void ComposeContent(IContainer container, string htmlContent)
    {
        container.Column(col =>
        {
            col.Item().Text("ForensicAnalyzerPro Report")
                .FontSize(20).Bold().FontColor(Colors.Blue.Darken4);

            col.Item().PaddingVertical(10).LineHorizontal(1);

            col.Item().Text(htmlContent.Replace("<br>", "\n").Replace("<br/>", "\n"))
                .FontSize(12);
        });
    }

    private static string EscapeCsvField(string field)
    {
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r'))
            return $"\"{field.Replace("\"", "\"\"")}\"";

        return field;
    }
}
