using ForensicAnalyzerPro.Domain.Models;

namespace ForensicAnalyzerPro.Domain.Interfaces;

public interface IEvidenceManager
{
    Task<Evidence> CollectEvidenceAsync(string sourcePath, string name, string description);
    Task<string> CalculateSHA256Async(string filePath);
    Task<string> CalculateMD5Async(string filePath);
    Task<bool> VerifyIntegrityAsync(Evidence evidence);
    Task<Evidence> AddToCaseAsync(Evidence evidence, string caseId);
    Task<List<Evidence>> GetAllEvidenceAsync(string? caseId = null);
    Task<string> ExportEvidenceAsync(Evidence evidence, string outputPath);
}
