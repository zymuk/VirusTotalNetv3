using System.Text.Json;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Tests;

public class EnvelopeTests
{
    private static string ReadFixture(string name) => File.ReadAllText(Path.Combine("Fixtures", name));

    [Fact]
    public void FileReport_DeserializesTypedData_Lossless()
    {
        var response = JsonSerializer.Deserialize<VtResponse<TestFileObject>>(ReadFixture("file_report.json"), VirusTotalJson.Options);

        Assert.NotNull(response);
        var data = Assert.IsType<TestFileObject>(response?.Data);

        Assert.Equal("file", data.Type);
        Assert.Equal("aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2", data.Id);

        Assert.NotNull(data.Attributes);
        Assert.Equal("aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2", data.Attributes!.Sha256);
        Assert.Equal(12345, data.Attributes!.Size);
        Assert.Equal(12, data.Attributes!.TimesSubmitted);
        Assert.Equal("sample.exe", data.Attributes!.Name);
        Assert.Equal(new DateTime(2024, 1, 1), data.Attributes!.FirstSubmissionDate);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1704067200), data.Attributes!.LastModificationDate);

        Assert.Equal(2, data.Attributes!.LastAnalysisStats!.Malicious);
        Assert.Equal(45, data.Attributes!.LastAnalysisStats!.Harmless);

        Assert.NotNull(data.Attributes!.LastAnalysisResults);
        Assert.Equal(2, data.Attributes!.LastAnalysisResults!.Count);
        Assert.Equal("malicious", data.Attributes!.LastAnalysisResults!["Avast"].Category);
        Assert.Equal("Avast", data.Attributes!.LastAnalysisResults!["Avast"].EngineName);
        Assert.Equal("23.9.8494.0", data.Attributes!.LastAnalysisResults!["Avast"].EngineVersion);
        Assert.Equal("Win32:Evo-Gen", data.Attributes!.LastAnalysisResults!["Avast"].Result);
        Assert.Equal("undetected", data.Attributes!.LastAnalysisResults!["Microsoft"].Category);
        Assert.Null(data.Attributes!.LastAnalysisResults!["Microsoft"].Result);
        Assert.Equal("2026-09-10T00:00:00+00:00", data.Attributes!.LastAnalysisResults!["Avast"].EngineUpdate);

        Assert.NotNull(data.Relationships);
        Assert.True(data.Relationships!.Raw.ContainsKey("comments"));
        Assert.NotNull(data.Links);
        Assert.Contains("/files/", data.Links!.Self);

        Assert.NotNull(response.Meta);
        Assert.True(response.Meta!.Raw.ContainsKey("file_info"));
        Assert.NotNull(response.Links);
        Assert.Contains("/files/", response!.Links!.Self);
        Assert.True(response!.Raw.ContainsKey("top_level_extra"));
    }

    [Fact]
    public void Collection_DeserializesDataList_AndBuildsView()
    {
        var response = JsonSerializer.Deserialize<VtResponse<List<TestFileObject>>>(ReadFixture("collection.json"), VirusTotalJson.Options);

        Assert.NotNull(response);
        var data = Assert.IsType<List<TestFileObject>>(response?.Data);
        Assert.Equal(2, data.Count);
        Assert.Equal("file", data[0].Type);
        Assert.Equal("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", data[1].Id);
        Assert.NotNull(response?.Meta);
        Assert.Equal(2, response!.Meta!.Count);
        Assert.NotNull(response!.Links);
        Assert.Contains("cursor=abc123", response!.Links!.Next);

        var view = VtCollection<TestFileObject>.FromEnvelope(response);
        Assert.Equal(2, view.Items.Count);
        Assert.Equal(2, view.Count);
        Assert.Equal("abc123", view.NextCursor);

        var empty = VtCollection<TestFileObject>.FromEnvelope(new VtResponse<List<TestFileObject>>());
        Assert.Empty(empty.Items);
        Assert.Equal(0, empty.Count);
        Assert.Null(empty.NextCursor);
    }

    [Fact]
    public void Error_DeserializesEnvelope()
    {
        var response = JsonSerializer.Deserialize<VtResponse<TestFileObject>>(ReadFixture("error.json"), VirusTotalJson.Options);

        Assert.NotNull(response);
        Assert.Null(response!.Data);
        Assert.NotNull(response!.Error);
        Assert.Equal("QuotaExceededError", response.Error!.Code);
        Assert.Equal("Quota exceeded", response.Error!.Message);
        Assert.Contains("quota", response.Error!.Detail, StringComparison.OrdinalIgnoreCase);
    }
}