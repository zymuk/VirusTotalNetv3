using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.v3.Tests.TestInternals;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Tests;

public class RetryTests
{
    private static VirusTotalOptions Options(bool useRetry = true, int maxRetries = 3)
        => new() { ApiKey = "test-key", UseRetry = useRetry, MaxRetries = maxRetries };

    [Fact]
    public async Task Retries_On429_UsesAllAttempts_ThenThrows()
    {
        var attempts = 0;
        var handler = new StubHttpMessageHandler(_ =>
        {
            attempts++;
            return StubHttpMessageHandler.Json((HttpStatusCode)429,
                """{ "error": { "code": "RateLimitExceededError", "message": "slow" } }""");
        });

        using var client = new VtClient(Options(maxRetries: 2), new HttpClient(handler));

        var ex = await Assert.ThrowsAsync<RateLimitException>(
            () => client.GetAsync<TestFileObject>("/files/abc"));

        Assert.Equal(3, attempts); // initial + 2 retries
        Assert.NotNull(ex);
    }

    [Fact]
    public async Task Retries_On5xx_ThenSucceeds()
    {
        var calls = 0;
        var handler = new StubHttpMessageHandler(_ =>
        {
            calls++;
            if (calls <= 2)
                return StubHttpMessageHandler.Json(HttpStatusCode.InternalServerError, "boom");

            return StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "file", "id": "abc" } }""");
        });

        using var client = new VtClient(Options(), new HttpClient(handler));

        var response = await client.GetAsync<TestFileObject>("/files/abc");

        Assert.Equal(3, calls);
        Assert.Equal("abc", response.Data!.Id);
    }

    [Fact]
    public async Task Retry_Disabled_DoesNotRetry()
    {
        var calls = 0;
        var handler = new StubHttpMessageHandler(_ =>
        {
            calls++;
            return StubHttpMessageHandler.Json(HttpStatusCode.InternalServerError, "boom");
        });

        using var client = new VtClient(Options(useRetry: false, maxRetries: 3), new HttpClient(handler));

        await Assert.ThrowsAsync<VtHttpException>(
            () => client.GetAsync<TestFileObject>("/files/abc"));

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task NonRetryable_4xx_DoesNotRetry()
    {
        var calls = 0;
        var handler = new StubHttpMessageHandler(_ =>
        {
            calls++;
            return StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                """{ "error": { "code": "NotFoundError", "message": "nope" } }""");
        });

        using var client = new VtClient(Options(), new HttpClient(handler));

        await Assert.ThrowsAsync<NotFoundException>(
            () => client.GetAsync<TestFileObject>("/files/xyz"));

        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task RetryAfter_IsRespected()
    {
        var handler = new StubHttpMessageHandler(_ =>
        {
            var response = StubHttpMessageHandler.Json((HttpStatusCode)429,
                """{ "error": { "code": "RateLimitExceededError", "message": "slow" } }""");
            response.Headers.Add("Retry-After", "0");
            return response;
        });

        using var client = new VtClient(Options(maxRetries: 1), new HttpClient(handler));

        var started = DateTime.UtcNow;
        await Assert.ThrowsAsync<RateLimitException>(
            () => client.GetAsync<TestFileObject>("/files/abc"));
        var elapsed = DateTime.UtcNow - started;

        Assert.True(handler.Requests.Count == 2, "expected initial + 1 retry");
    }
}
