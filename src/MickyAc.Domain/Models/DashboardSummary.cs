namespace MickyAc.Domain.Models;

public class DashboardSummary
{
    public int TotalArtifacts { get; set; }
    public int TotalEvidence { get; set; }
    public int TotalCases { get; set; }
    public int TotalIoCs { get; set; }
    public int HighRiskIoCs { get; set; }
    public int RecentEvents { get; set; }
    public int ScansCompleted { get; set; }
    public int ScansRunning { get; set; }
    public List<ArtifactTypeCount> ArtifactDistribution { get; set; } = new();
    public List<RiskDistribution> RiskDistribution { get; set; } = new();
    public List<TimelineEvent> RecentTimelineEvents { get; set; } = new();
}

public class ArtifactTypeCount
{
    public string Type { get; set; } = string.Empty;
    public int Count { get; set; }
}

public class RiskDistribution
{
    public string Level { get; set; } = string.Empty;
    public int Count { get; set; }
}
