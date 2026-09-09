using System;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Core;

/// <summary>
/// Client for the VirusTotal API v3.
/// Wraps <see cref="HttpClient"/> with authentication header, base URL and retry policy.
/// </summary>
public sealed class VtClient : IVtClient, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly VirusTotalOptions _options;
    private readonly RateLimiter _rateLimiter;
    private readonly Random _jitter;
    private readonly bool _ownsHttpClient;

    public VtClient(VirusTotalOptions options, HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();

        _httpClient = httpClient ?? new HttpClient();
        _ownsHttpClient = httpClient is null;
        _rateLimiter = new RateLimiter(_options.RequestsPerMinute, _options.RequestsPerDay);
        _jitter = new Random();

        _httpClient.BaseAddress = _options.BaseAddress;
        _httpClient.DefaultRequestHeaders.Add("x-apikey", _options.ApiKey);
        _httpClient.Timeout = _options.Timeout;
    }

    public HttpClient Client => _httpClient;

    public async Task<VtResponse<T>> GetAsync<T>(string uri, CancellationToken cancellationToken = default)
    {
        return await SendWithRetryAsync(
            () => new HttpRequestMessage(HttpMethod.Get, BuildRelativeUri(uri)),
            DeserializeResponse<T>,
            cancellationToken).ConfigureAwait(false);
    }

#if NET8_0_OR_GREATER
    public async Task<VtResponse<T>> GetAsync<T>(string uri, JsonTypeInfo<VtResponse<T>> typeInfo, CancellationToken cancellationToken = default)
    {
        return await SendWithRetryAsync(
            () => new HttpRequestMessage(HttpMethod.Get, BuildRelativeUri(uri)),
            (response, ct) => DeserializeResponse(response, typeInfo, ct),
            cancellationToken).ConfigureAwait(false);
    }
#endif

    public async Task<System.IO.Stream> GetStreamAsync(string uri, CancellationToken cancellationToken = default)
    {
        var attempt = 0;
        while (true)
        {
            await _rateLimiter.WaitUntilAllowedAsync(cancellationToken).ConfigureAwait(false);

            using var request = new HttpRequestMessage(HttpMethod.Get, BuildRelativeUri(uri));

            HttpResponseMessage? response = null;
            try
            {
                response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsRetryableNetworkError(ex) && ShouldRetry(attempt))
            {
                response?.Dispose();
                await BackoffDelayAsync(attempt, retryAfter: null, cancellationToken).ConfigureAwait(false);
                attempt++;
                continue;
            }

            if (response.IsSuccessStatusCode)
                return await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

            if (IsRetryableStatus(response) && ShouldRetry(attempt))
            {
                var retryAfter = GetRetryAfter(response);
                response.Dispose();
                await BackoffDelayAsync(attempt, retryAfter, cancellationToken).ConfigureAwait(false);
                attempt++;
                continue;
            }

            var error = await MapErrorResponseAsync(response).ConfigureAwait(false);
            response.Dispose();
            throw error;
        }
    }

    private static async Task<VirusTotalException> MapErrorResponseAsync(HttpResponseMessage response)
    {
        try
        {
            var stream = await ReadContentStream(response).ConfigureAwait(false);
            var envelope = await DeserializeAsync<JsonElement>(stream, default).ConfigureAwait(false);

            if (envelope?.Error is { } error)
                return MapErrorToException(error, response.StatusCode);
        }
        catch
        {
        }

        return new VtHttpException(response.StatusCode, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
    }

    public async Task<VtResponse<T>> PostAsync<T>(string uri, object body, CancellationToken cancellationToken = default)
    {
        return await SendWithRetryAsync(
            () =>
            {
                var content = new StringContent(SerializeBody(body), Encoding.UTF8, "application/json");
                return new HttpRequestMessage(HttpMethod.Post, BuildRelativeUri(uri)) { Content = content };
            },
            DeserializeResponse<T>,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<VtResponse<T>> PostAsync<T>(string uri, HttpContent content, CancellationToken cancellationToken = default)
    {
        return await SendWithRetryAsync(
            () => new HttpRequestMessage(HttpMethod.Post, BuildRelativeUri(uri)) { Content = content },
            DeserializeResponse<T>,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<VtResponse<T>> SendWithRetryAsync<T>(
        Func<HttpRequestMessage> requestFactory,
        Func<HttpResponseMessage, CancellationToken, Task<VtResponse<T>>> deserialize,
        CancellationToken cancellationToken)
    {
        var attempt = 0;
        while (true)
        {
            await _rateLimiter.WaitUntilAllowedAsync(cancellationToken).ConfigureAwait(false);

            HttpResponseMessage? response = null;
            try
            {
                using var request = requestFactory();
                response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (IsRetryableNetworkError(ex) && ShouldRetry(attempt))
            {
                response?.Dispose();
                await BackoffDelayAsync(attempt, retryAfter: null, cancellationToken).ConfigureAwait(false);
                attempt++;
                continue;
            }

            if (IsSuccessWithRetry(response))
            {
                var result = await deserialize(response, cancellationToken).ConfigureAwait(false);
                response.Dispose();
                return result;
            }

            if (IsRetryableStatus(response) && ShouldRetry(attempt))
            {
                var retryAfter = GetRetryAfter(response);
                response.Dispose();
                await BackoffDelayAsync(attempt, retryAfter, cancellationToken).ConfigureAwait(false);
                attempt++;
                continue;
            }

            var final = await deserialize(response, cancellationToken).ConfigureAwait(false);
            response.Dispose();
            return final;
        }
    }

    private bool ShouldRetry(int attempt) => _options.UseRetry && attempt < _options.MaxRetries;

    private async Task BackoffDelayAsync(int attempt, TimeSpan? retryAfter, CancellationToken cancellationToken)
    {
        var baseDelay = retryAfter ?? TimeSpan.FromMilliseconds(_options.InitialRetryDelay.TotalMilliseconds * Math.Pow(2, attempt));
        var jitterMs = (int)(baseDelay.TotalMilliseconds * 0.2);
        var jitter = jitterMs > 0 ? _jitter.Next(0, jitterMs) : 0;
        var delay = baseDelay + TimeSpan.FromMilliseconds(jitter);

        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsSuccessWithRetry(HttpResponseMessage? response)
        => response is not null && response.IsSuccessStatusCode;

    private static bool IsRetryableStatus(HttpResponseMessage? response)
        => response is not null && ((int)response.StatusCode == 429 || (int)response.StatusCode >= 500);

    private static bool IsRetryableNetworkError(Exception ex)
        => ex is HttpRequestException || ex is TaskCanceledException;

    private static TimeSpan? GetRetryAfter(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Retry-After", out var values))
            return null;

        foreach (var value in values)
        {
            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
                return TimeSpan.FromSeconds(seconds);

            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
                return date.Subtract(DateTimeOffset.UtcNow);
        }

        return null;
    }

    private async Task<VtResponse<T>> DeserializeResponse<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            var stream = await ReadContentStream(response).ConfigureAwait(false);
            var envelope = await DeserializeAsync<T>(stream, cancellationToken).ConfigureAwait(false);

            if (envelope?.Error != null && _options.ThrowOnError)
                throw MapErrorToException(envelope.Error, response.StatusCode);

            return envelope ?? new VtResponse<T>();
        }

        VtResponse<T>? errorEnvelope = null;
        try
        {
            var errorStream = await ReadContentStream(response).ConfigureAwait(false);
            errorEnvelope = await DeserializeAsync<T>(errorStream, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
        }

        if (errorEnvelope?.Error != null)
            throw MapErrorToException(errorEnvelope.Error, response.StatusCode);

        throw new VtHttpException(response.StatusCode, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
    }

#if NET8_0_OR_GREATER
    private async Task<VtResponse<T>> DeserializeResponse<T>(HttpResponseMessage response, JsonTypeInfo<VtResponse<T>> typeInfo, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            var stream = await ReadContentStream(response).ConfigureAwait(false);
            var envelope = await JsonSerializer.DeserializeAsync(stream, typeInfo, cancellationToken).ConfigureAwait(false);

            if (envelope?.Error != null && _options.ThrowOnError)
                throw MapErrorToException(envelope.Error, response.StatusCode);

            return envelope ?? new VtResponse<T>();
        }

        VtResponse<T>? errorEnvelope = null;
        try
        {
            var errorStream = await ReadContentStream(response).ConfigureAwait(false);
            errorEnvelope = await JsonSerializer.DeserializeAsync(errorStream, typeInfo, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
        }

        if (errorEnvelope?.Error != null)
            throw MapErrorToException(errorEnvelope.Error, response.StatusCode);

        throw new VtHttpException(response.StatusCode, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
    }
#endif

    private static VirusTotalException MapErrorToException(VtError error, HttpStatusCode statusCode)
    {
        var message = error.Message ?? $"API error: {error.Code}";

        return error.Code switch
        {
            "QuotaExceededError" => new QuotaExceededException(message, error.Code),
            "AuthenticationRequiredError" or "InvalidApiKeyError" => new AuthenticationException(message, error.Code),
            "NotFoundError" => new NotFoundException(message, error.Code),
            "BadRequestError" or "InvalidArgumentError" => new InvalidRequestException(message, error.Code),
            "RateLimitExceededError" => new RateLimitException(message, errorCode: error.Code),
            "InternalError" or "ServiceUnavailableError" => new ServerException(message, error.Code),
            _ => new VtHttpException(statusCode, message, error.Code)
        };
    }

    private static string SerializeBody(object body)
    {
        var options = VirusTotalJson.CreateOptions();
#pragma warning disable IL2026, IL3050
        return JsonSerializer.Serialize(body, body.GetType(), options);
#pragma warning restore IL2026, IL3050
    }

    private static async Task<VtResponse<T>?> DeserializeAsync<T>(System.IO.Stream stream, CancellationToken cancellationToken)
    {
        var options = VirusTotalJson.CreateOptions();
#pragma warning disable IL2026, IL3050
        return await JsonSerializer.DeserializeAsync<VtResponse<T>>(stream, options, cancellationToken).ConfigureAwait(false);
#pragma warning restore IL2026, IL3050
    }

    private static async Task<System.IO.Stream> ReadContentStream(HttpResponseMessage response)
    {
#if NET8_0_OR_GREATER
        return await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        return await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
    }

    private static Uri BuildRelativeUri(string uri)
    {
        if (Uri.TryCreate(uri, UriKind.Absolute, out var absolute))
            return absolute;

        var trimmed = uri.StartsWith("/", StringComparison.Ordinal) ? uri.Substring(1) : uri;
        return new Uri(trimmed, UriKind.Relative);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
