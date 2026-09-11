using System.Net;
using VirusTotalNet.v3.Core;

namespace VirusTotalNet.v3.Tests;

public class ExceptionTests
{
    [Fact]
    public void Hierarchy_VirusTotalException_IsBase()
    {
        Assert.True(typeof(VirusTotalException).IsAssignableFrom(typeof(VtHttpException)));
        Assert.True(typeof(VtHttpException).IsAssignableFrom(typeof(NotFoundException)));
        Assert.True(typeof(VtHttpException).IsAssignableFrom(typeof(QuotaExceededException)));
        Assert.True(typeof(VtHttpException).IsAssignableFrom(typeof(RateLimitException)));
        Assert.True(typeof(VtHttpException).IsAssignableFrom(typeof(AuthenticationException)));
        Assert.True(typeof(VtHttpException).IsAssignableFrom(typeof(InvalidRequestException)));
        Assert.True(typeof(VtHttpException).IsAssignableFrom(typeof(ServerException)));
    }

    [Fact]
    public void NotFound_CarriesCode()
    {
        var ex = new NotFoundException("nope", "NotFoundError");
        Assert.Equal("NotFoundError", ex.ErrorCode);
        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
    }

    [Fact]
    public void Authentication_IsUnauthorized()
    {
        var ex = new AuthenticationException("bad key", "InvalidApiKeyError");
        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
        Assert.Equal("InvalidApiKeyError", ex.ErrorCode);
    }

    [Fact]
    public void RateLimit_CarriesRetryAfter()
    {
        var retry = System.TimeSpan.FromSeconds(15);
        var ex = new RateLimitException("slow down", retry);
        Assert.Equal(retry, ex.RetryAfter);
    }
}
