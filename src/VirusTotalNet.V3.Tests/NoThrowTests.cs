using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Tests;

public class NoThrowTests
{
    private static VirusTotalOptions ThrowOnErrorFalse(string key = "test-key")
        => new() { ApiKey = key, ThrowOnError = false };

    [Fact]
    public async Task GetAsync_ThrowOnErrorFalse_ReturnsErrorEnvelopeInsteadOfThrowing()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "File not found" } }"""));

        using var vt = new VtClient(ThrowOnErrorFalse(), new HttpClient(handler));

        var response = await vt.GetAsync<FileObject>("/files/unknown");

        Assert.Null(response.Data);
        Assert.NotNull(response.Error);
        Assert.Equal("NotFoundError", response.Error!.Code);
        Assert.Equal(HttpStatusCode.NotFound, response.Error.StatusCode);
    }

    [Fact]
    public async Task GetAsync_ThrowOnErrorFalse_NonJsonError_SynthesizesEnvelope()
    {
        var handler = new StubHttpMessageHandler(
            request => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        using var vt = new VtClient(ThrowOnErrorFalse(), new HttpClient(handler));

        var response = await vt.GetAsync<FileObject>("/files/unknown");

        Assert.Null(response.Data);
        Assert.NotNull(response.Error);
        Assert.Null(response.Error!.Code);
        Assert.Equal("HTTP 500 Internal Server Error", response.Error.Message);
        Assert.Equal(HttpStatusCode.InternalServerError, response.Error.StatusCode);
    }

    [Fact]
    public async Task GetAsync_ThrowOnErrorFalse_SuccessWithErrorEnvelope_ReturnsIt()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "error": { "code": "WrongUrlError", "message": "Bad URL" } }"""));

        using var vt = new VtClient(ThrowOnErrorFalse(), new HttpClient(handler));

        var response = await vt.GetAsync<UrlObject>("/urls/x");

        Assert.Equal("WrongUrlError", response.Error!.Code);
    }

    [Fact]
    public async Task GetAsync_ThrowOnErrorTrue_Default_StillThrows()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "File not found" } }"""));

        using var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));

        await Assert.ThrowsAsync<NotFoundException>(() => vt.GetAsync<FileObject>("/files/unknown"));
    }

    [Fact]
    public async Task ModuleClient_ThrowOnErrorFalse_StillThrows()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "File not found" } }"""));

        using var vt = new VtClient(ThrowOnErrorFalse(), new HttpClient(handler));
        var client = new FileClient(vt);

        await Assert.ThrowsAsync<NotFoundException>(() => client.GetFileAsync("unknown"));
    }

    [Fact]
    public async Task TryGetAsync_Success_ReturnsValue()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "id": "aHR0cHM6Ly9leGFtcGxlLmNvbS8", "type": "url" } }"""));

        using var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));

        var result = await vt.TryGetAsync<UrlObject>("/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8");

        Assert.True(result.IsSuccess);
        Assert.Equal("aHR0cHM6Ly9leGFtcGxlLmNvbS8", result.Value!.Id);
    }

    [Fact]
    public async Task TryGetAsync_Failure_ReturnsErrorWithoutThrowing()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "File not found" } }"""));

        using var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));

        var result = await vt.TryGetAsync<FileObject>("/files/unknown");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Value);
        Assert.Equal("NotFoundError", result.Error!.Code);
        Assert.Equal(HttpStatusCode.NotFound, result.Error.StatusCode);
    }

    [Fact]
    public async Task TryPostAsync_Object_Success()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "analysis", "id": "an-1" } }"""));

        using var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));

        var result = await vt.TryPostAsync<AnalysisObject>("/files/x/analyse", new { });

        Assert.True(result.IsSuccess);
        Assert.Equal("an-1", result.Value!.Id);
        Assert.Equal("{}", handler.LastRequestBody);
    }

    [Fact]
    public void VtResult_ValueOrThrow_ThrowsOnFailure()
    {
        var failure = VtResult<string>.Failure(new VtError { Code = "NotFoundError", Message = "Nope" });
        var success = VtResult<string>.Success("ok");

        Assert.Equal("ok", success.ValueOrThrow());
        Assert.Equal("ok", success.GetValueOrDefault());
        Assert.Null(failure.GetValueOrDefault());

        var ex = Assert.ThrowsAny<VirusTotalException>(() => failure.ValueOrThrow());
        Assert.Equal("NotFoundError", ex.ErrorCode);
    }

    [Fact]
    public void VtResult_From_WrapsEnvelope()
    {
        var ok = VtResult<UrlObject>.From(new VtResponse<UrlObject> { Data = new UrlObject { Id = "x" } });
        Assert.True(ok.IsSuccess);
        Assert.Equal("x", ok.Value!.Id);

        var bad = VtResult<UrlObject>.From(new VtResponse<UrlObject> { Error = new VtError { Code = "NotFoundError" } });
        Assert.False(bad.IsSuccess);
        Assert.Equal("NotFoundError", bad.Error!.Code);
    }
}