using System;

namespace VirusTotalNet.v3.Internal;

/// <summary>Extracts a pagination cursor from a <c>links.next</c> URL, shared by collection and relationship views.</summary>
internal static class VtCursor
{
    /// <summary>Returns the <c>cursor</c> query parameter from a <c>links.next</c> URL, or <c>null</c> when absent.</summary>
    public static string? Next(string? link)
    {
        if (string.IsNullOrEmpty(link) || !Uri.TryCreate(link, UriKind.Absolute, out var uri))
            return null;

        var query = uri.Query.TrimStart('?');
        foreach (var pair in query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            var key = pair.Substring(0, eq);
            var value = pair.Substring(eq + 1);
            if (key == "cursor")
                return Uri.UnescapeDataString(value.Replace('+', ' '));
        }

        return null;
    }
}