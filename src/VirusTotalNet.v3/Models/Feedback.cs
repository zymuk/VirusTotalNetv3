using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// Path segment of a VirusTotal object type, used to address relationship endpoints
/// such as comments and votes (e.g. <c>/files/{id}/comments</c>).
/// </summary>
public static class VtObjectType
{
    /// <summary><c>files</c></summary>
    public const string File = "files";

    /// <summary><c>urls</c></summary>
    public const string Url = "urls";

    /// <summary><c>domains</c></summary>
    public const string Domain = "domains";

    /// <summary><c>ip_addresses</c></summary>
    public const string IpAddress = "ip_addresses";

    /// <summary><c>analyses</c></summary>
    public const string Analysis = "analyses";

    /// <summary><c>comments</c></summary>
    public const string Comment = "comments";

    /// <summary><c>votes</c></summary>
    public const string Vote = "votes";
}

/// <summary>A <c>comment</c> object attached to a resource, e.g. from <c>GET /files/{id}/comments</c>.</summary>
public sealed class CommentObject : VtObject<CommentAttributes>
{
}

/// <summary>A <c>vote</c> object attached to a resource, e.g. from <c>GET /files/{id}/votes</c>.</summary>
public sealed class VoteObject : VtObject<VoteAttributes>
{
}