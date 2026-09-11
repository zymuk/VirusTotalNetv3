using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// Operations on <c>ip_address</c> resources: retrieve, rescan, and list appearances.
/// </summary>
public interface IIpClient
{
    /// <summary>
    /// Retrieves the object of an IP address (<c>GET /ip_addresses/{ip}</c>).
    /// </summary>
    /// <param name="ip">The IP address (IPv4 or IPv6), e.g. <c>8.8.8.8</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The IP-address object with its attributes.</returns>
    Task<IpObject> GetIpAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rescans an IP address (<c>POST /ip_addresses/{ip}/analyse</c>).
    /// </summary>
    /// <param name="ip">The IP address.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    Task<AnalysisObject> AnalyseIpAsync(string ip, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the domains that resolve to the IP address (<c>GET /ip_addresses/{ip}/resolutions</c>).
    /// </summary>
    /// <param name="ip">The IP address.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of resolution objects with its next cursor.</returns>
    Task<VtCollection<ResolutionObject>> GetResolutionsAsync(string ip, string? cursor = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IIpClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class IpClient : IIpClient
{
    private readonly IVtClient _client;

    /// <summary>Creates an IP-address client backed by the given <see cref="IVtClient"/>.</summary>
    public IpClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<IpObject> GetIpAsync(string ip, CancellationToken cancellationToken = default)
    {
        var id = ValidateIp(ip);
        var response = await _client.GetAsync<IpObject>($"/ip_addresses/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new IpObject();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> AnalyseIpAsync(string ip, CancellationToken cancellationToken = default)
    {
        var id = ValidateIp(ip);
        var response = await _client.PostAsync<AnalysisObject>($"/ip_addresses/{id}/analyse", new { }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    /// <inheritdoc />
    public async Task<VtCollection<ResolutionObject>> GetResolutionsAsync(string ip, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var id = ValidateIp(ip);
        var response = await _client.GetAsync<List<ResolutionObject>>(Paginate($"/ip_addresses/{id}/resolutions", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<ResolutionObject>.FromEnvelope(response.EnsureSuccess());
    }

    private static string ValidateIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            throw new ArgumentException("An IP address is required.", nameof(ip));
        return ip.Trim();
    }

    private static string Paginate(string path, string? cursor)
        => string.IsNullOrEmpty(cursor) ? path : $"{path}?cursor={Uri.EscapeDataString(cursor)}";
}