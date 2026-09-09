using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>Operations on collections (<c>/collections</c>).</summary>
public interface ICollectionClient
{
    /// <summary>Creates a collection (<c>POST /collections</c>).</summary>
    Task<CollectionObject> CreateCollectionAsync(string name, string? description = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a collection (<c>GET /collections/{id}</c>).</summary>
    Task<CollectionObject> GetCollectionAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a collection (<c>PATCH /collections/{id}</c>).</summary>
    Task<CollectionObject> UpdateCollectionAsync(string id, string? name = null, string? description = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a collection (<c>DELETE /collections/{id}</c>).</summary>
    Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Adds elements to a collection (<c>POST /collections/{id}/relationships/elements</c>).</summary>
    Task AddElementsAsync(string collectionId, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default);

    /// <summary>Removes elements from a collection (<c>DELETE /collections/{id}/relationships/elements</c>).</summary>
    Task RemoveElementsAsync(string collectionId, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default);

    /// <summary>Lists elements of a collection (<c>GET /collections/{id}/relationships/elements</c>) with cursor pagination.</summary>
    Task<VtCollection<VtObjectId>> ListElementsAsync(string collectionId, string? cursor = null, CancellationToken cancellationToken = default);
}

/// <summary><see cref="ICollectionClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class CollectionClient : ICollectionClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a collection client backed by the given <see cref="IVtClient"/>.</summary>
    public CollectionClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<CollectionObject> CreateCollectionAsync(string name, string? description = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A collection name is required.", nameof(name));

        var response = await _client.PostAsync<CollectionObject>("/collections", new
        {
            data = new
            {
                type = "collection",
                attributes = new { name, description }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no collection.");
    }

    /// <inheritdoc />
    public async Task<CollectionObject> GetCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A collection id is required.", nameof(id));

        var response = await _client.GetAsync<CollectionObject>($"/collections/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no collection.");
    }

    /// <inheritdoc />
    public async Task<CollectionObject> UpdateCollectionAsync(string id, string? name = null, string? description = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A collection id is required.", nameof(id));

        var attributes = new Dictionary<string, object>();
        if (name is not null) attributes["name"] = name;
        if (description is not null) attributes["description"] = description;

        if (attributes.Count == 0)
            throw new ArgumentException("At least one field (name or description) must be provided for update.", nameof(name));

        var response = await _client.PatchAsync<CollectionObject>($"/collections/{id}", new
        {
            data = new
            {
                type = "collection",
                id,
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no collection.");
    }

    /// <inheritdoc />
    public async Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A collection id is required.", nameof(id));

        var response = await _client.DeleteAsync<CollectionObject>($"/collections/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task AddElementsAsync(string collectionId, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(collectionId))
            throw new ArgumentException("A collection id is required.", nameof(collectionId));

        var elementList = elements?.ToList() ?? throw new ArgumentNullException(nameof(elements));
        if (elementList.Count == 0)
            throw new ArgumentException("At least one element must be provided.", nameof(elements));

        var response = await _client.PostAsync<CollectionObject>($"/collections/{collectionId}/relationships/elements", new
        {
            data = elementList
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task RemoveElementsAsync(string collectionId, IEnumerable<VtObjectId> elements, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(collectionId))
            throw new ArgumentException("A collection id is required.", nameof(collectionId));

        var elementList = elements?.ToList() ?? throw new ArgumentNullException(nameof(elements));
        if (elementList.Count == 0)
            throw new ArgumentException("At least one element must be provided.", nameof(elements));

        var response = await _client.DeleteAsync<CollectionObject>($"/collections/{collectionId}/relationships/elements", new
        {
            data = elementList
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<VtCollection<VtObjectId>> ListElementsAsync(string collectionId, string? cursor = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(collectionId))
            throw new ArgumentException("A collection id is required.", nameof(collectionId));

        var path = $"/collections/{collectionId}/relationships/elements";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<VtObjectId>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<VtObjectId>.FromEnvelope(response.EnsureSuccess());
    }
}