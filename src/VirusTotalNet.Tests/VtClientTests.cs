using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.Tests.TestInternals;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.Tests;

public class VtClientTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    [Fact]
    public async Task Get_SetsAuthHeader_AndBaseUrl()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": { "type": "file", "id": "abc" } }"""));

        using var client = new VtClient(Options(), new HttpClient(handler));

        var response = await client.GetAsync<TestFileObject>("/files/abc");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);

        Assert.True(request.Headers.TryGetValues("x-apikey", out var authValues));
        Assert.Equal("test-key", Assert.Single(authValues!));

        Assert.Equal(VirusTotalOptions.DefaultBaseAddress + "files/abc", request.RequestUri!.ToString());
        Assert.NotNull(response);
        Assert.Equal("abc", response.Data!.Id);
    }

    [Fact]
    public async Task Get_TraversesBaseAddress()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": null }"""));

        using var client = new VtClient(Options(), new HttpClient(handler));

        await client.GetAsync<TestFileObject>("files/abc");

        var request = Assert.Single(handler.Requests);
        Assert.StartsWith(VirusTotalOptions.DefaultBaseAddress, request.RequestUri!.ToString());
    }

    [Fact]
    public async Task Get_NonSuccess_WithoutErrorEnvelope_ThrowsHttpException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.InternalServerError, "oops"));

        using var client = new VtClient(new VirusTotalOptions { ApiKey = "k", UseRetry = false }, new HttpClient(handler));

        var ex = await Assert.ThrowsAsync<VtHttpException>(
            () => client.GetAsync<TestFileObject>("/files/abc"));

        Assert.Equal(HttpStatusCode.InternalServerError, ex.StatusCode);
    }

    [Fact]
    public async Task Get_NotFound_ErrorCode_MapsToNotFoundException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "Not found" } }"""));

        using var client = new VtClient(Options(), new HttpClient(handler));

        var ex = await Assert.ThrowsAsync<NotFoundException>(
            () => client.GetAsync<TestFileObject>("/files/xyz"));

        Assert.Equal("NotFoundError", ex.ErrorCode);
    }

    [Fact]
    public async Task Get_QuotaExceeded_ErrorCode_MapsToQuotaExceededException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json((HttpStatusCode)429,
                """{ "error": { "code": "QuotaExceededError", "message": "Quota exceeded" } }"""));

        using var client = new VtClient(new VirusTotalOptions { ApiKey = "k", UseRetry = false }, new HttpClient(handler));

        var ex = await Assert.ThrowsAsync<QuotaExceededException>(
            () => client.GetAsync<TestFileObject>("/files/abc"));

        Assert.Equal("QuotaExceededError", ex.ErrorCode);
    }

    [Fact]
    public async Task Get_ThrowOnFalse_ReturnsEnvelope_WithError()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "error": { "code": "NotFoundError", "message": "Not found" }, "data": null }"""));

        using var client = new VtClient(
            new VirusTotalOptions { ApiKey = "k", ThrowOnError = false },
            new HttpClient(handler));

        var response = await client.GetAsync<TestFileObject>("/files/abc");

        Assert.NotNull(response.Error);
        Assert.Equal("NotFoundError", response.Error!.Code);
    }

    [Fact]
    public async Task Post_SendsJsonBody()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, """{ "data": { "type": "analysis", "id": "a1" } }"""));

        using var client = new VtClient(Options(), new HttpClient(handler));

        var response = await client.PostAsync<TestFileObject>("/files/abc/analyse", new { body = "payload" });

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("a1", response.Data!.Id);
    }
}
