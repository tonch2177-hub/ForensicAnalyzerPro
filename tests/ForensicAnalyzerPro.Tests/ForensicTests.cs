using ForensicAnalyzerPro.Domain.Enums;
using ForensicAnalyzerPro.Domain.Models;
using ForensicAnalyzerPro.Infrastructure.Engines.IOCScanning;
using ForensicAnalyzerPro.Infrastructure.Engines.Timeline;
using ForensicAnalyzerPro.Infrastructure.EvidenceManagement;
using ForensicAnalyzerPro.Infrastructure.Parsers.Amcache;
using ForensicAnalyzerPro.Infrastructure.Parsers.BAM;
using ForensicAnalyzerPro.Infrastructure.Parsers.Prefetch;
using ForensicAnalyzerPro.Infrastructure.Reporting;
using FluentAssertions;

namespace ForensicAnalyzerPro.Tests;

public class ParserTests
{
    [Fact]
    public async Task AmcacheParser_ShouldReturnEvents()
    {
        var parser = new AmcacheParser();
        var events = await parser.ParseAsync(CancellationToken.None);

        events.Should().NotBeNull();
        events.Should().HaveCountGreaterThanOrEqualTo(3);
    }

    [Fact]
    public void PrefetchParser_CanParse_ValidPath_ReturnsTrue()
    {
        var parser = new PrefetchParser();
        var tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pf");

        try
        {
            File.WriteAllText(tempFile, string.Empty);
            var result = parser.CanParse(tempFile);
            result.Should().BeTrue();
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void BAMParser_Name_IsNotEmpty()
    {
        var parser = new BAMParser();
        parser.Name.Should().NotBeEmpty();
    }
}

public class TimelineEngineTests
{
    [Fact]
    public async Task BuildTimeline_ShouldMergeAndSortEvents()
    {
        var engine = new TimelineEngine();
        var now = DateTime.UtcNow;

        var list1 = new List<TimelineEvent>
        {
            new() { Id = "1", Timestamp = now.AddHours(-2), Description = "Event A" },
            new() { Id = "2", Timestamp = now.AddHours(-1), Description = "Event B" }
        };

        var list2 = new List<TimelineEvent>
        {
            new() { Id = "3", Timestamp = now.AddHours(-3), Description = "Event C" },
            new() { Id = "4", Timestamp = now, Description = "Event D" }
        };

        var sources = new List<List<TimelineEvent>> { list1, list2 };
        var result = await engine.BuildTimelineAsync(sources);

        result.Should().HaveCount(4);
        result.Should().BeInAscendingOrder(e => e.Timestamp);
    }

    [Fact]
    public async Task SearchAsync_ShouldFindMatchingEvents()
    {
        var engine = new TimelineEngine();
        var events = new List<TimelineEvent>
        {
            new() { Description = "Malware detected in system32" },
            new() { Description = "Normal application launch" },
            new() { Description = "Malware signature found" },
            new() { Description = "Clean event" }
        };

        var result = await engine.SearchAsync(events, "Malware");

        result.Should().HaveCount(2);
        result.Should().Contain(e => e.Description!.Contains("Malware"));
    }

    [Fact]
    public async Task FilterByDateAsync_ShouldReturnEventsInRange()
    {
        var engine = new TimelineEngine();
        var now = DateTime.UtcNow;

        var events = new List<TimelineEvent>
        {
            new() { Timestamp = now.AddDays(-5) },
            new() { Timestamp = now.AddDays(-3) },
            new() { Timestamp = now.AddDays(-1) },
            new() { Timestamp = now.AddDays(1) },
            new() { Timestamp = now.AddDays(5) }
        };

        var start = now.AddDays(-4);
        var end = now.AddDays(2);
        var result = await engine.FilterByDateAsync(events, start, end);

        result.Should().HaveCount(3);
    }
}

public class IOCEngineTests
{
    [Fact]
    public async Task MatchHashAsync_ShouldMatchCorrectHash()
    {
        var engine = new IOCEngine();
        var iocs = new List<IOC>
        {
            new()
            {
                Type = "Hash",
                Value = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1",
                IsActive = true
            }
        };

        var result = await engine.MatchHashAsync(
            "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1",
            iocs);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task MatchFileNameAsync_ShouldMatchCorrectFile()
    {
        var engine = new IOCEngine();
        var iocs = new List<IOC>
        {
            new()
            {
                Type = "FileName",
                Value = "malware.exe",
                IsActive = true
            }
        };

        var result = await engine.MatchFileNameAsync(@"C:\Users\test\malware.exe", iocs);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task ScanForIoCsAsync_ShouldMarkMatchingEvents()
    {
        var engine = new IOCEngine();
        var iocs = new List<IOC>
        {
            new()
            {
                Type = "Hash",
                Value = "KNOWN_MALICIOUS_HASH",
                RiskLevel = RiskLevel.Critical,
                IsActive = true
            }
        };

        var events = new List<TimelineEvent>
        {
            new() { Hash = "KNOWN_MALICIOUS_HASH", Description = "Suspicious file", RiskLevel = RiskLevel.None },
            new() { Hash = "CLEAN_HASH", Description = "Clean file", RiskLevel = RiskLevel.None }
        };

        var result = await engine.ScanForIoCsAsync(events, iocs);

        result[0].RiskLevel.Should().Be(RiskLevel.Critical);
        result[0].Metadata.Should().ContainKey("MatchedIOC");
        result[1].RiskLevel.Should().Be(RiskLevel.None);
    }
}

public class EvidenceManagerTests
{
    [Fact]
    public async Task CalculateSHA256Async_ShouldReturnValidHash()
    {
        var manager = new EvidenceManager();
        var tempFile = Path.GetTempFileName();

        try
        {
            File.WriteAllText(tempFile, "Hello, World!");
            var hash = await manager.CalculateSHA256Async(tempFile);

            hash.Should().Be("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task CollectEvidenceAsync_ShouldCreateEvidence()
    {
        var manager = new EvidenceManager();
        var tempFile = Path.GetTempFileName();

        try
        {
            File.WriteAllText(tempFile, "Test evidence content");
            var evidence = await manager.CollectEvidenceAsync(tempFile, "TestEvidence", "A test evidence item");

            evidence.Should().NotBeNull();
            evidence.Name.Should().Be("TestEvidence");
            evidence.Description.Should().Be("A test evidence item");
            evidence.SourcePath.Should().Be(tempFile);
            evidence.OriginalPath.Should().Be(tempFile);
            evidence.SHA256.Should().NotBeNullOrEmpty();
            evidence.MD5.Should().NotBeNullOrEmpty();
            evidence.Size.Should().BeGreaterThan(0);
            evidence.CollectedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
            evidence.CollectedBy.Should().NotBeNullOrEmpty();
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }
}

public class ReportGeneratorTests
{
    [Fact]
    public async Task GenerateExecutiveReportAsync_ShouldReturnHtml()
    {
        var generator = new ReportGenerator();
        var forensicCase = new ForensicCase
        {
            Title = "Test Case",
            CaseNumber = "CASE-001",
            Status = CaseStatus.Open,
            RiskLevel = RiskLevel.Medium,
            Description = "Test case description",
            CreatedBy = "Tester"
        };
        var summary = new DashboardSummary
        {
            TotalArtifacts = 100,
            TotalEvidence = 50,
            TotalCases = 10,
            TotalIoCs = 25,
            HighRiskIoCs = 5,
            RecentEvents = 30,
            ScansCompleted = 20,
            ScansRunning = 2
        };

        var html = await generator.GenerateExecutiveReportAsync(forensicCase, summary);

        html.Should().Contain("<html>");
        html.Should().Contain("<table>");
        html.Should().Contain("Executive");
        html.Should().Contain("CASE-001");
    }

    [Fact]
    public async Task ExportToJsonAsync_ShouldReturnValidJson()
    {
        var generator = new ReportGenerator();
        var events = new List<TimelineEvent>
        {
            new()
            {
                Id = "evt-1",
                EventType = "ProcessExecuted",
                Description = "Test process execution",
                Timestamp = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            }
        };

        var json = await generator.ExportToJsonAsync(events);

        json.Should().Contain("ProcessExecuted");
        json.Should().Contain("Test process execution");
        json.Should().Contain("evt-1");
    }
}
