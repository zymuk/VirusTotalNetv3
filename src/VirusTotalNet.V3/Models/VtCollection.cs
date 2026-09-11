namespace VirusTotalNet.V3.Models;

/// <summary>
/// Ergonomic view over a collection/relationship payload. Built from the raw envelope
/// (a <see cref="VtResponse{T}"/> whose <c>data</c> is a list) so callers get plain
/// <see cref="Items"/>, <see cref="Count"/> and <see cref="NextCursor"/>.
/// </summary>
/// <typeparam name="T">Element type of the collection.</typeparam>
public sealed class VtCollection<T> where T : class
{
    /// <summary>Items of the current page; empty when the payload has no <c>data</c> array.</summary>
    public IReadOnlyList<T> Items { get; set; } = Array.Empty<T>();

    /// <summary>Total count reported by <c>meta.count</c>, falling back to <see cref="Items"/> count.</summary>
    public int Count { get; set; }

    /// <summary>Cursor for the next page, extracted from <c>links.next</c> (or <c>meta.cursor</c>), when present.</summary>
    public string? NextCursor { get; set; }

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
        => VirusTotalNet.V3.Internal.VtCursor.Next(link);
}