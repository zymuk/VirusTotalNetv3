using VirusTotalNet.v3.Models;

namespace VirusTotalNet.Tests.TestInternals;

public sealed class TestFileAttributes
{
    public string? Sha256 { get; set; }
    public long? Size { get; set; }
    public string? Name { get; set; }
    public int? TimesSubmitted { get; set; }
    public DateTime? FirstSubmissionDate { get; set; }
    public DateTimeOffset? LastModificationDate { get; set; }
}

public sealed class TestFileObject : VtObject<TestFileAttributes> { }

public sealed class StringBox
{
    public string? Value { get; set; }
}