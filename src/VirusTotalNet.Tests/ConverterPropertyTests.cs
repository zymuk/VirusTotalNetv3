using System.Globalization;
using System.Text.Json;
using CsCheck;
using VirusTotalNet.Tests.TestInternals;
using VirusTotalNet.v3.Core;

namespace VirusTotalNet.Tests;

public class ConverterPropertyTests
{
    private static readonly Gen<DateTimeOffset> WholeSecondTimestamps =
        Gen.Long[-62_135_596_800L, 253_402_300_799L].Select(DateTimeOffset.FromUnixTimeSeconds);

    private static readonly Gen<DateTime> CalendarDates =
        Gen.DateTime.Select(d => d.Date);

    private static readonly Gen<string?> RoundTripStrings =
        Gen.String[Gen.Char.AlphaNumeric, 0, 32]
            .Select(static s => (string?)s)
            .Where(s => s is null || !string.Equals(s, "null", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void UnixTimestamp_RoundTrips_AnyWholeSecond()
    {
        WholeSecondTimestamps.Sample(value =>
        {
            var json = JsonSerializer.Serialize(new TestFileAttributes { LastModificationDate = value }, VirusTotalJson.Options);
            var echo = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);
            return echo?.LastModificationDate == value;
        });
    }

    [Fact]
    public void UnixTimestamp_ReadFromNumber_IsFromUnixTime()
    {
        WholeSecondTimestamps.Sample(value =>
        {
            var json = $$"""{ "last_modification_date": {{value.ToUnixTimeSeconds()}} }""";
            var read = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);
            return read?.LastModificationDate == value;
        });
    }

    [Fact]
    public void UnixTimestamp_ReadFromString_IsFromUnixTime()
    {
        WholeSecondTimestamps.Sample(value =>
        {
            var seconds = value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            var json = $$"""{ "last_modification_date": "{{seconds}}" }""";
            var read = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);
            return read?.LastModificationDate == value;
        });
    }

    [Fact]
    public void YearMonthDay_RoundTrips_AnyCalendarDate()
    {
        CalendarDates.Sample(value =>
        {
            var json = JsonSerializer.Serialize(new TestFileAttributes { FirstSubmissionDate = value }, VirusTotalJson.Options);
            Assert.Contains(value.ToString("yyyyMMdd", CultureInfo.InvariantCulture), json);
            var echo = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);
            return echo?.FirstSubmissionDate == value;
        });
    }

    [Fact]
    public void YearMonthDay_ReadFromCrammed_IsThatDate()
    {
        CalendarDates.Sample(value =>
        {
            var crammed = value.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
            var json = $$"""{ "first_submission_date": "{{crammed}}" }""";
            var read = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);
            return read?.FirstSubmissionDate == value;
        });
    }

    [Fact]
    public void YearMonthDay_ReadFromIso_IsThatDate()
    {
        CalendarDates.Sample(value =>
        {
            var iso = value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            var json = $$"""{ "first_submission_date": "{{iso}}" }""";
            var read = JsonSerializer.Deserialize<TestFileAttributes>(json, VirusTotalJson.Options);
            return read?.FirstSubmissionDate == value;
        });
    }

    [Fact]
    public void TolerantString_RoundTrips_AnyNormalString()
    {
        RoundTripStrings.Sample(value =>
        {
            var json = JsonSerializer.Serialize(new StringBox { Value = value }, VirusTotalJson.Options);
            var echo = JsonSerializer.Deserialize<StringBox>(json, VirusTotalJson.Options);
            return echo?.Value == value;
        });
    }

    [Fact]
    public void TolerantString_ReadFromNumber_IsInvariantDecimalText()
    {
        Gen.Decimal.Sample(value =>
        {
            var text = value.ToString(CultureInfo.InvariantCulture);
            var json = $$"""{ "value": {{text}} }""";
            var read = JsonSerializer.Deserialize<StringBox>(json, VirusTotalJson.Options);
            return read?.Value == value.ToString(CultureInfo.InvariantCulture);
        });
    }

    [Fact]
    public void TolerantString_NullLiteral_IsNull_AnyCase()
    {
        var gen = Gen.OneOf(Gen.Const("null"), Gen.Const("NULL"), Gen.Const("Null"), Gen.Const("nUlL"));
        gen.Sample(value =>
        {
            var json = $$"""{ "value": "{{value}}" }""";
            var read = JsonSerializer.Deserialize<StringBox>(json, VirusTotalJson.Options);
            return read?.Value is null;
        });
    }
}
