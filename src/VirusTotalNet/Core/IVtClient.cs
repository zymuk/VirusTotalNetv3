using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Core;

/// <summary>
/// Abstraction for VirusTotal API client operations.
/// Wraps <see cref="HttpClient"/> with authentication header and base URL.
/// </summary>
public interface IVtClient
{
    /// <summary>
    /// Gets the underlying <see cref="HttpClient"/> used by this client.
    /// </summary>
    HttpClient Client { get; }

    /// <summary>
    /// Performs a GET request and deserialises the response envelope.
    /// </summary>
    Task<VtResponse<T>> GetAsync<T>(string uri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a POST request with a JSON body and deserialises the response envelope.
    /// </summary>
    Task<VtResponse<T>> PostAsync<T>(string uri, object body, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a POST request with a raw <see cref="HttpContent"/> body (e.g. multipart file upload)
    /// and deserialises the response envelope. Same retry/rate-limit/error handling as the other calls.
    /// </summary>
    Task<VtResponse<T>> PostAsync<T>(string uri, HttpContent content, CancellationToken cancellationToken = default);
}
