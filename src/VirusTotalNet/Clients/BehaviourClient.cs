using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// <see cref="IBehaviourClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class BehaviourClient : IBehaviourClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a behaviour client backed by the given <see cref="IVtClient"/>.</summary>
    public BehaviourClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<BehaviourObject> GetBehaviourAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A behaviour ID is required.", nameof(id));

        var response = await _client.GetAsync<BehaviourObject>($"/file_behaviours/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new BehaviourObject();
    }

    /// <inheritdoc />
    public async Task<Stream> DownloadEvtxAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A behaviour ID is required.", nameof(id));

        return await _client.GetStreamAsync($"/file_behaviours/{id}/evtx", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Stream> DownloadPcapAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A behaviour ID is required.", nameof(id));

        return await _client.GetStreamAsync($"/file_behaviours/{id}/pcap", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Stream> DownloadMemdumpAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A behaviour ID is required.", nameof(id));

        return await _client.GetStreamAsync($"/file_behaviours/{id}/memdump", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<Stream> DownloadHtmlAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A behaviour ID is required.", nameof(id));

        return await _client.GetStreamAsync($"/file_behaviours/{id}/html", cancellationToken).ConfigureAwait(false);
    }
}