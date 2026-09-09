using System;
using System.IO;
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
    /// Performs a GET request and returns the raw response body as a stream (for binary payloads such as file downloads).
    /// The returned stream must be disposed by the caller.
    /// </summary>
    Task<Stream> GetStreamAsync(string uri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a POST request with a JSON body and deserialises the response envelope.
    /// </summary>
    Task<VtResponse<T>> PostAsync<T>(string uri, object body, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a POST request with a raw <see cref="HttpContent"/> body (e.g. multipart file upload)
    /// and deserialises the response envelope. Same retry/rate-limit/error handling as the other calls.
    /// </summary>
    Task<VtResponse<T>> PostAsync<T>(string uri, HttpContent content, CancellationToken cancellationToken = default);

    /// <summary>
    /// Result-style GET that never throws for API errors: returns a <see cref="VtResult{T}"/>
    /// carrying either the payload or the error. Transport/retry/rate-limit semantics match
    /// <see cref="GetAsync{T}(string, CancellationToken)"/>; <see cref="VirusTotalOptions.ThrowOnError"/>
    /// is ignored.
    /// </summary>
    Task<VtResult<T>> TryGetAsync<T>(string uri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Result-style POST with a JSON body; see <see cref="TryGetAsync{T}"/> for semantics.
    /// </summary>
    Task<VtResult<T>> TryPostAsync<T>(string uri, object body, CancellationToken cancellationToken = default);

/// <summary>
        /// Result-style POST with raw <see cref="HttpContent"/>; see <see cref="TryGetAsync{T}"/> for semantics.
        /// </summary>
        Task<VtResult<T>> TryPostAsync<T>(string uri, HttpContent content, CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs a DELETE request and deserialises the response envelope.
        /// </summary>
        Task<VtResponse<T>> DeleteAsync<T>(string uri, CancellationToken cancellationToken = default);

        /// <summary>
        /// Result-style DELETE that never throws for API errors: returns a <see cref="VtResult{T}"/>
        /// carrying either the payload or the error. Transport/retry/rate-limit semantics match
        /// <see cref="DeleteAsync{T}(string, CancellationToken)"/>; <see cref="VirusTotalOptions.ThrowOnError"/>
        /// is ignored.
        /// </summary>
        Task<VtResult<T>> TryDeleteAsync<T>(string uri, CancellationToken cancellationToken = default);
}
