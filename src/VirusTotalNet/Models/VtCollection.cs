namespace VirusTotalNet.v3.Models;

/// <summary>
/// Ergonomic view over a collection/relationship payload. Built from the raw envelope
/// (a <see cref="VtResponse{T}"/> whose <c>data</c> is a list) so callers get plain
/// <see cref="Items"/>, <see cref="Count"/> and <see cref="NextCursor"/>.
/// </summary>
/// <typeparam name="T">Element type of the collection.</typeparam>
public sealed class VtCollection<T> where T : class
{
    /// <summary>Items of the current page; empty when the payload has no <c>data</c> array.</summary>
    public IReadOnlyList<T> Items { get; init; } = Array.Empty<T>();

    /// <summary>Total count reported by <c>meta.count</c>, falling back to <see cref="Items"/> count.</summary>
    public int Count { get; init; }

    /// <summary>Cursor for the next page, extracted from <c>links.next</c> (or <c>meta.cursor</c>), when present.</summary>
    public string? NextCursor { get; init; }

    /// <summary>Builds a collection view from the raw envelope of a collection/relationship endpoint.</summary>
    public static VtCollection<T> FromEnvelope(VtResponse<List<T>> response)
    {
        var data = response.Data ?? new List<T>();
        return new VtCollection<T>
        {
            Items = data,
            Count = (int)(response.Meta?.Count ?? data.Count),
            NextCursor = response.Meta?.Cursor ?? CursorFromLink(response.Links?.Next)
        };
    }

    private static string? CursorFromLink(string? link)
    {
        if (string.IsNullOrEmpty(link) || !Uri.TryCreate(link, UriKind.Absolute, out var uri))
            return null;

        var query = uri.Query.TrimStart('?');
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = pair.Split('=', 2, StringSplitOptions.None);
            if (kv.Length == 2 && kv[0] == "cursor")
                return Uri.UnescapeDataString(kv[1]);
        }

        return null;
    }
}