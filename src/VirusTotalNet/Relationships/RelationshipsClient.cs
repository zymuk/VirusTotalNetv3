using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Internal;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Relationships;

/// <summary>
/// Well-known relationship names used by the type path <c>/{objectType}/{id}/{relationshipName}</c>.
/// </summary>
public static class RelationshipName
{
    /// <summary><c>comments</c></summary>
    public const string Comments = "comments";

    /// <summary><c>votes</c></summary>
    public const string Votes = "votes";

    /// <summary><c>resolutions</c> (domain ↔ IP history)</summary>
    public const string Resolutions = "resolutions";

    /// <summary><c>subdomains</c></summary>
    public const string Subdomains = "subdomains";

    /// <summary><c>contacted_urls</c></summary>
    public const string ContactedUrls = "contacted_urls";

    /// <summary><c>detected_urls</c></summary>
    public const string DetectedUrls = "detected_urls";

    /// <summary><c>behaviours</c></summary>
    public const string Behaviours = "behaviours";
}

/// <summary>
/// Relationship navigation: typed accessors plus a generic fallback, descriptor-first id
/// retrieval, in-session memoization and <c>IAsyncEnumerable</c> traversal. All calls share
/// the underlying client's rate limiter, so a big traversal cannot blow the budget.
/// </summary>
public interface IRelationshipsClient
{
    /// <summary>
    /// Retrieves one page of related objects (<c>GET /{objectType}/{id}/{relationshipName}</c>).
    /// The first page of each <c>(objectType, id, relationshipName)</c> is memoized per client
    /// for the lifetime of the session.
    /// </summary>
    /// <typeparam name="T">Object type of the related resources (e.g. <see cref="UrlObject"/>).</typeparam>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id (for URLs, the base64url-encoded id).</param>
    /// <param name="relationshipName">Relationship name, see <see cref="RelationshipName"/>.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<T>> GetRelatedAsync<T>(string objectType, string id, string relationshipName, string? cursor = null, CancellationToken cancellationToken = default)
        where T : class;

    /// <summary>
    /// Descriptor-first: retrieves only the <c>(type, id)</c> pairs of related objects, skipping
    /// attribute materialization to stay light on quota and memory.
    /// </summary>
    Task<VtCollection<VtObjectId>> GetRelatedIdsAsync(string objectType, string id, string relationshipName, string? cursor = null, CancellationToken cancellationToken = default);

#if NET8_0_OR_GREATER
    /// <summary>
    /// Traverses every page of a relationship, yielding the related objects in order.
    /// Cancellable via <paramref name="cancellationToken"/>. Only available on net8.0 and later
    /// (netstandard2.0 lacks <see cref="IAsyncEnumerable{T}"/>).
    /// </summary>
    IAsyncEnumerable<T> TraverseAsync<T>(string objectType, string id, string relationshipName, CancellationToken cancellationToken = default)
        where T : class;
#endif

    /// <summary>Clears the in-session memoization cache.</summary>
    void ClearCache();
}

/// <summary>
/// <see cref="IRelationshipsClient"/> implementation built on top of <see cref="IVtClient"/>.
/// </summary>
public sealed class RelationshipsClient : IRelationshipsClient
{
    private sealed class CachedPage
    {
        public List<JsonElement> Items { get; set; } = new();
        public long? Count { get; set; }
        public string? NextLink { get; set; }
    }

    private readonly IVtClient _client;
    private readonly ConcurrentDictionary<string, CachedPage> _cache = new();

    /// <summary>Creates a relationships client backed by the given <see cref="IVtClient"/>.</summary>
    public RelationshipsClient(IVtClient client)
        => _client = client ?? throw new ArgumentNullException(nameof(client));

    /// <inheritdoc />
    public async Task<VtCollection<T>> GetRelatedAsync<T>(string objectType, string id, string relationshipName, string? cursor = null, CancellationToken cancellationToken = default)
        where T : class
    {
        var page = await FetchPageAsync(objectType, id, relationshipName, cursor, cancellationToken).ConfigureAwait(false);
        return ToCollection<T>(page);
    }

    /// <inheritdoc />
    public async Task<VtCollection<VtObjectId>> GetRelatedIdsAsync(string objectType, string id, string relationshipName, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var page = await FetchPageAsync(objectType, id, relationshipName, cursor, cancellationToken).ConfigureAwait(false);

        var items = new List<VtObjectId>(page.Items.Count);
        foreach (var element in page.Items)
        {
            var descriptor = ToObjectId(element);
            if (descriptor is not null)
                items.Add(descriptor);
        }

        return new VtCollection<VtObjectId>
        {
            Items = items,
            Count = (int)(page.Count ?? items.Count),
            NextCursor = VtCursor.Next(page.NextLink)
        };
    }

#if NET8_0_OR_GREATER
    /// <inheritdoc />
    public async IAsyncEnumerable<T> TraverseAsync<T>(string objectType, string id, string relationshipName, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        where T : class
    {
        string? cursor = null;
        while (true)
        {
            var page = await GetRelatedAsync<T>(objectType, id, relationshipName, cursor, cancellationToken).ConfigureAwait(false);
            foreach (var item in page.Items)
                yield return item;

            if (string.IsNullOrEmpty(page.NextCursor))
                yield break;

            cursor = page.NextCursor;
        }
    }
#endif

    /// <inheritdoc />
    public void ClearCache() => _cache.Clear();

    private async Task<CachedPage> FetchPageAsync(string objectType, string id, string relationshipName, string? cursor, CancellationToken cancellationToken)
    {
        Validate(objectType, id, relationshipName);

        var key = $"{objectType}/{id}/{relationshipName}";
        if (cursor is null && _cache.TryGetValue(key, out var cached))
            return cached;

        var path = $"/{objectType}/{id}/{relationshipName}";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<JsonElement>>(path, cancellationToken).ConfigureAwait(false);

        var page = new CachedPage
        {
            Items = response.Data ?? new List<JsonElement>(),
            Count = response.Meta?.Count,
            NextLink = response.Links?.Next
        };

        if (cursor is null)
            _cache[key] = page;

        return page;
    }

    private static VtCollection<T> ToCollection<T>(CachedPage page)
        where T : class
    {
        var items = new List<T>(page.Items.Count);
        var options = VirusTotalJson.CreateOptions();
#pragma warning disable IL2026, IL3050
        foreach (var element in page.Items)
        {
            var item = element.Deserialize<T>(options);
            if (item is not null)
                items.Add(item);
        }
#pragma warning restore IL2026, IL3050

        return new VtCollection<T>
        {
            Items = items,
            Count = (int)(page.Count ?? items.Count),
            NextCursor = VtCursor.Next(page.NextLink)
        };
    }

    private static VtObjectId? ToObjectId(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
            return null;

        var type = element.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
        var id = element.TryGetProperty("id", out var idElement) ? idElement.GetString() : null;
        return type is null && id is null ? null : new VtObjectId(type, id);
    }

    private static void Validate(string objectType, string id, string relationshipName)
    {
        if (string.IsNullOrWhiteSpace(objectType))
            throw new ArgumentException("An object type is required.", nameof(objectType));
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("An object id is required.", nameof(id));
        if (string.IsNullOrWhiteSpace(relationshipName))
            throw new ArgumentException("A relationship name is required.", nameof(relationshipName));
    }
}