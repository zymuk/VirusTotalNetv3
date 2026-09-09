using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;

namespace VirusTotalNet.Tests;

public class AnalysisClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private static string AnalysisJson(string status, string id = "analysis-1")
        => $$"""{ "data": { "type": "analysis", "id": "{{id}}", "attributes": { "status": "{{status}}" } } }""";

    [Fact]
    public async Task GetAnalysis_SendsGet_ToAnalysesEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("completed")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new AnalysisClient(vt);

        var analysis = await client.GetAnalysisAsync("analysis-1");

        Assert.Equal("completed", analysis.Attributes!.Status);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "analyses/analysis-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task WaitForCompletion_Polls_UntilCompleted()
    {
        var statuses = new[] { "queued", "queued", "in-progress", "completed" };
        var index = 0;
        var handler = new StubHttpMessageHandler(_ =>
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson(statuses[index++])));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new AnalysisClient(vt);

        var analysis = await client.WaitForCompletionAsync(
            "analysis-1", TimeSpan.FromMilliseconds(10));

        Assert.Equal("completed", analysis.Attributes!.Status);
        Assert.Equal(4, handler.Requests.Count);
    }

    [Fact]
    public async Task WaitForCompletion_ReturnsImmediately_WhenAlreadyCompleted()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("completed")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new AnalysisClient(vt);

        var analysis = await client.WaitForCompletionAsync(
            "analysis-1", TimeSpan.FromMilliseconds(10));

        Assert.Equal("completed", analysis.Attributes!.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForCompletion_UnknownStatus_ReturnsAsIs()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("failed")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new AnalysisClient(vt);

        var analysis = await client.WaitForCompletionAsync(
            "analysis-1", TimeSpan.FromMilliseconds(10));

        Assert.Equal("failed", analysis.Attributes!.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForCompletion_Cancellation_StopsPolling()
    {
        var handler = new StubHttpMessageHandler(_ =>
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("queued")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new AnalysisClient(vt);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.WaitForCompletionAsync("analysis-1", TimeSpan.FromMilliseconds(20), cts.Token));
    }

    [Fact]
    public async Task CompletionMethods_InvalidArgs_Throw()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("completed")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new AnalysisClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetAnalysisAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.WaitForCompletionAsync(""));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => client.WaitForCompletionAsync("analysis-1", TimeSpan.Zero));

        Assert.Empty(handler.Requests);
    }
}