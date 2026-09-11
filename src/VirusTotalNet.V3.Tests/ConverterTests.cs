using System.Text.Json;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.Tests;

public class ConverterTests
{
    private const string NullableDateTimeOffset =
        """{ "last_modification_date": null }""";
    private const string UnixFromNumber =
        """{ "last_modification_date": 1704067200 }""";
    private const string UnixFromString =
        """{ "last_modification_date": "1704067200" }""";
    private const string CrammedDate =
        """{ "first_submission_date": "20240101" }""";
    private const string IsoDate =
        """{ "first_submission_date": "2024-01-01" }""";
    private const string NullDate =
        """{ "first_submission_date": null }""";
    private const string NullLiteralString =
        """{ "value": "null" }""";
    private const string NaString =
        """{ "value": "N/A" }""";
    private const string NullString =
        """{ "value": null }""";
    private const string NumberString =
        """{ "value": 5 }""";

    private static DateTimeOffset? ReadTimestamp(string json)
        => JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options)?.LastModificationDate;

    private static DateTime? ReadDate(string json)
        => JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options)?.FirstSubmissionDate;

    private static string? ReadValue(string json)
        => JsonSerializer.Deserialize<StringBox>(json, VirusTotalJson.Options)?.Value;

    [Fact]
    public void UnixTimestamp_FromNumber()
        => Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1704067200), ReadTimestamp(UnixFromNumber));

    [Fact]
    public void UnixTimestamp_FromString()
        => Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1704067200), ReadTimestamp(UnixFromString));

    [Fact]
    public void UnixTimestamp_Null()
        => Assert.Null(ReadTimestamp(NullableDateTimeOffset));

    [Fact]
    public void UnixTimestamp_SerializeRoundtrip()
    {
        var value = DateTimeOffset.FromUnixTimeSeconds(1704067200);
        var json = JsonSerializer.Serialize(new TestFileAttributes { LastModificationDate = value }, VirusTotalJson.Options);
        var echo = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);

        Assert.Equal(value, echo?.LastModificationDate);
    }

    [Fact]
    public void YearMonthDay_FromCrammed()
        => Assert.Equal(new DateTime(2024, 1, 1), ReadDate(CrammedDate));

    [Fact]
    public void YearMonthDay_FromIso()
        => Assert.Equal(new DateTime(2024, 1, 1), ReadDate(IsoDate));

    [Fact]
    public void YearMonthDay_Null()
        => Assert.Null(ReadDate(NullDate));

    [Fact]
    public void YearMonthDay_SerializeRoundtrip()
    {
        var json = JsonSerializer.Serialize(new TestFileAttributes { FirstSubmissionDate = new DateTime(2024, 1, 1) }, VirusTotalJson.Options);
        Assert.Contains("20240101", json);
        Assert.Equal(new DateTime(2024, 1, 1), JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options)?.FirstSubmissionDate);
    }

    [Fact]
    public void TolerantString_NullLiteralIsNull()
        => Assert.Null(ReadValue(NullLiteralString));

    [Fact]
    public void TolerantString_PreservesNa()
        => Assert.Equal("N/A", ReadValue(NaString));

    [Fact]
    public void TolerantString_NullTokenIsNull()
        => Assert.Null(ReadValue(NullString));

    [Fact]
    public void TolerantString_NumberBecomesString()
        => Assert.Equal("5", ReadValue(NumberString));

    [Fact]
    public void TolerantString_NullIsOmittedOnWrite()
    {
        var json = JsonSerializer.Serialize(new StringBox { Value = null }, VirusTotalJson.Options);
        Assert.Equal("{}", json);
    }
}