using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Operations on <c>file_behaviour</c> resources: retrieve behaviour reports and download associated artifacts.
/// </summary>
public interface IBehaviourClient
{
    /// <summary>
    /// Retrieves a behaviour report (<c>GET /file_behaviours/{id}</c>).
    /// </summary>
    /// <param name="id">The behaviour ID, in the format <see langword="file_sha256"/>_<see langword="sandbox_name"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The behaviour object.</returns>
    Task<BehaviourObject> GetBehaviourAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads the EVTX file for a behaviour (<c>GET /file_behaviours/{id}/evtx</c>).
    /// </summary>
    /// <param name="id">The behaviour ID, in the format <see langword="file_sha256"/>_<see langword="sandbox_name"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the EVTX file bytes; the caller must dispose it.</returns>
    Task<Stream> DownloadEvtxAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads the PCAP file for a behaviour (<c>GET /file_behaviours/{id}/pcap</c>).
    /// </summary>
    /// <param name="id">The behaviour ID, in the format <see langword="file_sha256"/>_<see langword="sandbox_name"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the PCAP file bytes; the caller must dispose it.</returns>
    Task<Stream> DownloadPcapAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads the memory dump file for a behaviour (<c>GET /file_behaviours/{id}/memdump</c>).
    /// </summary>
    /// <param name="id">The behaviour ID, in the format <see langword="file_sha256"/>_<see langword="sandbox_name"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the memory dump file bytes; the caller must dispose it.</returns>
    Task<Stream> DownloadMemdumpAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Downloads the HTML report for a behaviour (<c>GET /file_behaviours/{id}/html</c>).
    /// </summary>
    /// <param name="id">The behaviour ID, in the format <see langword="file_sha256"/>_<see langword="sandbox_name"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream with the HTML report bytes; the caller must dispose it.</returns>
    Task<Stream> DownloadHtmlAsync(string id, CancellationToken cancellationToken = default);
}