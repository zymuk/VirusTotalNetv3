using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>Operations on threat actors (<c>/threat_actors</c>).</summary>
public interface IThreatActorClient
{
    /// <summary>Retrieves a threat actor (<c>GET /threat_actors/{id}</c>).</summary>
    Task<ThreatActorObject> GetThreatActorAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IThreatActorClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class ThreatActorClient : IThreatActorClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a threat-actor client backed by the given <see cref="IVtClient"/>.</summary>
    public ThreatActorClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<ThreatActorObject> GetThreatActorAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A threat actor id is required.", nameof(id));

        var response = await _client.GetAsync<ThreatActorObject>($"/threat_actors/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no threat actor.");
    }
}
