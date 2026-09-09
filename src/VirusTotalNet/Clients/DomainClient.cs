using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// Operations on <c>domain</c> resources: retrieve, rescan, and list resolutions/subdomains.
/// </summary>
public interface IDomainClient
{
    /// <summary>
    /// Retrieves the object of a domain (<c>GET /domains/{domain}</c>).
    /// </summary>
    /// <param name="domain">The domain name, e.g. <c>example.com</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The domain object with its attributes.</returns>
    Task<DomainObject> GetDomainAsync(string domain, CancellationToken cancellationToken = default);

    /// <summary>
    /// Rescans a domain (<c>POST /domains/{domain}/analyse</c>).
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created analysis object.</returns>
    Task<AnalysisObject> AnalyseDomainAsync(string domain, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the DNS resolutions of a domain (<c>GET /domains/{domain}/resolutions</c>).
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of resolution objects with its next cursor.</returns>
    Task<VtCollection<ResolutionObject>> GetResolutionsAsync(string domain, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the subdomains of a domain (<c>GET /domains/{domain}/subdomains</c>).
    /// </summary>
    /// <param name="domain">The domain name.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A page of subdomain objects with its next cursor.</returns>
    Task<VtCollection<DomainObject>> GetSubdomainsAsync(string domain, string? cursor = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IDomainClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class DomainClient : IDomainClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a domain client backed by the given <see cref="IVtClient"/>.</summary>
    public DomainClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<DomainObject> GetDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        var id = ValidateDomain(domain);
        var response = await _client.GetAsync<DomainObject>($"/domains/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new DomainObject();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> AnalyseDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        var id = ValidateDomain(domain);
        var response = await _client.PostAsync<AnalysisObject>($"/domains/{id}/analyse", new { }, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    /// <inheritdoc />
    public async Task<VtCollection<ResolutionObject>> GetResolutionsAsync(string domain, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var id = ValidateDomain(domain);
        var response = await _client.GetAsync<List<ResolutionObject>>(Paginate($"/domains/{id}/resolutions", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<ResolutionObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<VtCollection<DomainObject>> GetSubdomainsAsync(string domain, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var id = ValidateDomain(domain);
        var response = await _client.GetAsync<List<DomainObject>>(Paginate($"/domains/{id}/subdomains", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<DomainObject>.FromEnvelope(response.EnsureSuccess());
    }

    private static string ValidateDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("A domain name is required.", nameof(domain));
        return domain.Trim();
    }

    private static string Paginate(string path, string? cursor)
        => string.IsNullOrEmpty(cursor) ? path : $"{path}?cursor={Uri.EscapeDataString(cursor)}";
}