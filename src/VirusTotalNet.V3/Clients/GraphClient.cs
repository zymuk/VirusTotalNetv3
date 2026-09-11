using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Clients;

/// <summary>Operations on graphs (<c>/graphs</c>).</summary>
public interface IGraphClient
{
    /// <summary>Creates a graph (<c>POST /graphs</c>).</summary>
    Task<GraphObject> CreateGraphAsync(string name, string? description = null, bool? isPrivate = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a graph (<c>GET /graphs/{id}</c>).</summary>
    Task<GraphObject> GetGraphAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a graph (<c>PATCH /graphs/{id}</c>).</summary>
    Task<GraphObject> UpdateGraphAsync(string id, string? name = null, string? description = null, bool? isPrivate = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a graph (<c>DELETE /graphs/{id}</c>).</summary>
    Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IGraphClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class GraphClient : IGraphClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a graph client backed by the given <see cref="IVtClient"/>.</summary>
    public GraphClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<GraphObject> CreateGraphAsync(string name, string? description = null, bool? isPrivate = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A graph name is required.", nameof(name));

        var attributes = new Dictionary<string, object> { { "name", name } };
        if (description is not null) attributes["description"] = description;
        if (isPrivate is not null) attributes["private"] = isPrivate;

        var response = await _client.PostAsync<GraphObject>("/graphs", new
        {
            data = new
            {
                type = "graph",
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no graph.");
    }

    /// <inheritdoc />
    public async Task<GraphObject> GetGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A graph id is required.", nameof(id));

        var response = await _client.GetAsync<GraphObject>($"/graphs/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no graph.");
    }

    /// <inheritdoc />
    public async Task<GraphObject> UpdateGraphAsync(string id, string? name = null, string? description = null, bool? isPrivate = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A graph id is required.", nameof(id));

        var attributes = new Dictionary<string, object>();
        if (name is not null) attributes["name"] = name;
        if (description is not null) attributes["description"] = description;
        if (isPrivate is not null) attributes["private"] = isPrivate;

        if (attributes.Count == 0)
            throw new ArgumentException("At least one field must be provided for update.", nameof(name));

        var response = await _client.PatchAsync<GraphObject>($"/graphs/{id}", new
        {
            data = new
            {
                type = "graph",
                id,
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no graph.");
    }

    /// <inheritdoc />
    public async Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A graph id is required.", nameof(id));

        var response = await _client.DeleteAsync<GraphObject>($"/graphs/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }
}