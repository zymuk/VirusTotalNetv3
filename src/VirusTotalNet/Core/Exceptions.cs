using System;
using System.Net;

namespace VirusTotalNet.v3.Core;

/// <summary>Base exception for all VirusTotal API errors.</summary>
public abstract class VirusTotalException : Exception
{
    /// <summary>Gets the error code from the API response (e.g., <c>QuotaExceededError</c>).</summary>
    public string? ErrorCode { get; }

    protected VirusTotalException(string message, string? errorCode = null)
        : base(message) => ErrorCode = errorCode;

    protected VirusTotalException(string message, Exception innerException, string? errorCode = null)
        : base(message, innerException) => ErrorCode = errorCode;
}

/// <summary>Exception thrown when the VirusTotal API returns an error response (4xx/5xx).</summary>
public class VtHttpException : VirusTotalException
{
    /// <summary>Gets the HTTP status code of the failed response.</summary>
    public HttpStatusCode StatusCode { get; }

    public VtHttpException(HttpStatusCode statusCode, string message, string? errorCode = null)
        : base(message, errorCode) => StatusCode = statusCode;

    public VtHttpException(HttpStatusCode statusCode, string message, Exception innerException, string? errorCode = null)
        : base(message, innerException, errorCode) => StatusCode = statusCode;
}

/// <summary>Exception thrown when the API quota is exceeded (HTTP 429 or <c>QuotaExceededError</c>).</summary>
public class QuotaExceededException : VtHttpException
{
    public QuotaExceededException(string message, string? errorCode = "QuotaExceededError")
        : base((HttpStatusCode)429, message, errorCode) { }
}

/// <summary>Exception thrown when the API key is invalid or missing (HTTP 401).</summary>
public class AuthenticationException : VtHttpException
{
    public AuthenticationException(string message, string? errorCode = "AuthenticationRequiredError")
        : base(HttpStatusCode.Unauthorized, message, errorCode) { }
}

/// <summary>Exception thrown when the requested resource is not found (HTTP 404).</summary>
public class NotFoundException : VtHttpException
{
    public NotFoundException(string message, string? errorCode = "NotFoundError")
        : base(HttpStatusCode.NotFound, message, errorCode) { }
}

/// <summary>Exception thrown when the request is invalid or malformed (HTTP 400).</summary>
public class InvalidRequestException : VtHttpException
{
    public InvalidRequestException(string message, string? errorCode = "BadRequestError")
        : base(HttpStatusCode.BadRequest, message, errorCode) { }
}

/// <summary>Exception thrown when the API returns a server error (HTTP 5xx).</summary>
public class ServerException : VtHttpException
{
    public ServerException(string message, string? errorCode = "InternalError")
        : base(HttpStatusCode.InternalServerError, message, errorCode) { }
}

/// <summary>Exception thrown when a <c>VtResult</c> carrying failure is unwrapped via <c>ValueOrThrow</c>.</summary>
public class VtResultException : VirusTotalException
{
    public VtResultException(string message, string? errorCode = null)
        : base(message, errorCode) { }
}

/// <summary>Exception thrown when the rate limit is exceeded (HTTP 429 with retry-after).</summary>
public class RateLimitException : VtHttpException
{
    public TimeSpan? RetryAfter { get; }

    public RateLimitException(string message, TimeSpan? retryAfter = null, string? errorCode = "RateLimitExceededError")
        : base((HttpStatusCode)429, message, errorCode) => RetryAfter = retryAfter;
}
