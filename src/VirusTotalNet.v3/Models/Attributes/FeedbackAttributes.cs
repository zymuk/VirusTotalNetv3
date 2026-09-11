using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>Attributes of a <c>comment</c> object (see <see cref="CommentObject"/>).</summary>
public sealed class CommentAttributes
{
    /// <summary>The comment text, in markdown format.</summary>
    public string? Text { get; set; }

    /// <summary>The comment text rendered as HTML.</summary>
    public string? Html { get; set; }

    /// <summary>The date the comment was posted (Unix seconds).</summary>
    public DateTimeOffset? Date { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>Attributes of a <c>vote</c> object (see <see cref="VoteObject"/>).</summary>
public sealed class VoteAttributes
{
    /// <summary>The vote verdict, e.g. <c>malicious</c> or <c>harmless</c>.</summary>
    public string? Verdict { get; set; }

    /// <summary>The date the vote was cast (Unix seconds).</summary>
    public DateTimeOffset? Date { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}