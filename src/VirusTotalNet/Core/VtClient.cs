using System;
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
/// Wraps <see cref="HttpClient"/> with authentication header and base URL.
/// </summary>
public sealed class VtClient : IVtClient, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly VirusTotalOptions _options;
    private readonly RateLimiter _rateLimiter;
    private readonly bool _ownsHttpClient;

    public VtClient(VirusTotalOptions options, HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();

        _httpClient = httpClient ?? new HttpClient();
        _ownsHttpClient = httpClient is null;
        _rateLimiter = new RateLimiter(_options.RequestsPerMinute, _options.RequestsPerDay);

        _httpClient.BaseAddress = _options.BaseAddress;
        _httpClient.DefaultRequestHeaders.Add("x-apikey", _options.ApiKey);
        _httpClient.Timeout = _options.Timeout;
    }

    public HttpClient Client => _httpClient;

    public async Task<VtResponse<T>> GetAsync<T>(string uri, CancellationToken cancellationToken = default)
    {
        await _rateLimiter.WaitUntilAllowedAsync(cancellationToken).ConfigureAwait(false);

        var requestUri = BuildRelativeUri(uri);
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await DeserializeResponse<T>(response, cancellationToken).ConfigureAwait(false);
    }

#if NET8_0_OR_GREATER
    public async Task<VtResponse<T>> GetAsync<T>(string uri, JsonTypeInfo<VtResponse<T>> typeInfo, CancellationToken cancellationToken = default)
    {
        await _rateLimiter.WaitUntilAllowedAsync(cancellationToken).ConfigureAwait(false);

        var requestUri = BuildRelativeUri(uri);
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await DeserializeResponse(response, typeInfo, cancellationToken).ConfigureAwait(false);
    }

#endif

    public async Task<VtResponse<T>> PostAsync<T>(string uri, object body, CancellationToken cancellationToken = default)
    {
        await _rateLimiter.WaitUntilAllowedAsync(cancellationToken).ConfigureAwait(false);

        var content = new StringContent(SerializeBody(body), Encoding.UTF8, "application/json");

        var requestUri = BuildRelativeUri(uri);
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri) { Content = content };
        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await DeserializeResponse<T>(response, cancellationToken).ConfigureAwait(false);
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
        var trimmed = uri.StartsWith("/", StringComparison.Ordinal) ? uri.Substring(1) : uri;
        return new Uri(trimmed, UriKind.Relative);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }
}
