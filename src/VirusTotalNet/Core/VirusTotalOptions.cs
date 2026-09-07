using System;

namespace VirusTotalNet.v3.Core;

/// <summary>Configuration for the VirusTotal API v3 client.</summary>
public sealed class VirusTotalOptions
{
    /// <summary>Default base address of the VirusTotal API v3.</summary>
    public const string DefaultBaseAddress = "https://www.virustotal.com/api/v3/";

    /// <summary>VirusTotal API key (obtain one at &lt;see href="https://www.virustotal.com/gui/my-apikey"&gt;/&gt;). Sent as the <c>x-apikey</c> header.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Base address of the API. Defaults to <see cref="DefaultBaseAddress"/>.</summary>
    public Uri BaseAddress { get; set; } = new(DefaultBaseAddress);

    /// <summary>Per-request timeout.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(100);

    /// <summary>Hard limit of requests per minute for the shared rate limiter. Defaults to 4 (VirusTotal free plan).</summary>
    public int RequestsPerMinute { get; set; } = 4;

    /// <summary>Hard limit of requests per day for the shared rate limiter. Defaults to 500 (VirusTotal free plan).</summary>
    public int RequestsPerDay { get; set; } = 500;

    /// <summary>Whether transient failures (HTTP 429/5xx) are retried with exponential backoff and jitter.</summary>
    public bool UseRetry { get; set; } = true;

    /// <summary>Maximum number of retries before giving up. Ignored when <see cref="UseRetry"/> is false.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Initial backoff delay before the first retry; doubles on every attempt, with jitter.</summary>
    public TimeSpan InitialRetryDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Whether failed API calls throw an exception. When false, calls return a result instead.</summary>
    public bool ThrowOnError { get; set; } = true;

    /// <summary>Validates the options, throwing <see cref="ArgumentException"/> for invalid values.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(ApiKey))
            throw new ArgumentException("The API key must not be empty.", nameof(ApiKey));
        if (RequestsPerMinute <= 0 || RequestsPerDay <= 0)
            throw new ArgumentException("Request limits must be greater than zero.", nameof(RequestsPerMinute));
        if (MaxRetries < 0)
            throw new ArgumentException("MaxRetries must not be negative.", nameof(MaxRetries));
    }
}