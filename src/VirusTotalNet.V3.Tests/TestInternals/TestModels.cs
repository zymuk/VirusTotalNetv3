using System.Collections.Generic;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.Tests.TestInternals;

public sealed class TestFileAttributes
{
    public string? Sha256 { get; set; }
    public long? Size { get; set; }
    public string? Name { get; set; }
    public int? TimesSubmitted { get; set; }
    public DateTime? FirstSubmissionDate { get; set; }
    public DateTimeOffset? LastModificationDate { get; set; }
    public LastAnalysisStats? LastAnalysisStats { get; set; }
    public Dictionary<string, LastAnalysisResult>? LastAnalysisResults { get; set; }
}

public sealed class TestFileObject : VtObject<TestFileAttributes> { }

public sealed class StringBox
{
    public string? Value { get; set; }
}