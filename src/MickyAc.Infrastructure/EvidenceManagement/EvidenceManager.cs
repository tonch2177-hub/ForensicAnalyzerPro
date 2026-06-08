using System.Security.Cryptography;
using MickyAc.Domain.Interfaces;
using MickyAc.Domain.Models;

namespace MickyAc.Infrastructure.EvidenceManagement;

public class EvidenceManager : IEvidenceManager
{
    private readonly List<Evidence> _evidenceStore = new();

    public async Task<Evidence> CollectEvidenceAsync(string sourcePath, string name, string description)
    {
        var fileInfo = new FileInfo(sourcePath);

        var evidence = new Evidence
        {
            Name = name,
            Description = description,
            SourcePath = sourcePath,
            OriginalPath = sourcePath,
            Size = fileInfo.Exists ? fileInfo.Length : 0,
            CollectedAt = DateTime.UtcNow,
            CollectedBy = Environment.UserName
        };

        if (fileInfo.Exists)
        {
            evidence.SHA256 = await CalculateSHA256Async(sourcePath);
            evidence.MD5 = await CalculateMD5Async(sourcePath);
        }

        _evidenceStore.Add(evidence);
        return evidence;
    }

    public async Task<string> CalculateSHA256Async(string filePath)
    {
        await using var stream = File.OpenRead(filePath);
        var hash = await SHA256.HashDataAsync(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public async Task<string> CalculateMD5Async(string filePath)
    {
        await using var stream = File.OpenRead(filePath);
        var hash = await MD5.HashDataAsync(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public async Task<bool> VerifyIntegrityAsync(Evidence evidence)
    {
        if (string.IsNullOrEmpty(evidence.SHA256))
            return false;

        var computed = await CalculateSHA256Async(evidence.SourcePath);
        return string.Equals(computed, evidence.SHA256, StringComparison.OrdinalIgnoreCase);
    }

    public Task<Evidence> AddToCaseAsync(Evidence evidence, string caseId)
    {
        evidence.CaseId = caseId;
        return Task.FromResult(evidence);
    }

    public Task<List<Evidence>> GetAllEvidenceAsync(string? caseId = null)
    {
        var results = string.IsNullOrEmpty(caseId)
            ? _evidenceStore.ToList()
            : _evidenceStore.Where(e => e.CaseId == caseId).ToList();

        return Task.FromResult(results);
    }

    public Task<string> ExportEvidenceAsync(Evidence evidence, string outputPath)
    {
        var destDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
            Directory.CreateDirectory(destDir);

        File.Copy(evidence.SourcePath, outputPath, overwrite: true);
        return Task.FromResult(outputPath);
    }
}
