namespace VirusTotalNet.V3.Models;

/// <summary>
/// A lightweight <c>(type, id)</c> pair describing a related object without its attributes —
/// the "descriptor" form used by relationship payloads and returned by descriptor-first
/// navigation (<see cref="VirusTotalNet.V3.Relationships.IRelationshipsClient.GetRelatedIdsAsync"/>).
/// </summary>
public sealed class VtObjectId
{
    /// <summary>Creates a descriptor pair from an object type and identifier.</summary>
    public VtObjectId(string? type, string? id)
    {
        Type = type;
        Id = id;
    }

    /// <summary>Object type, e.g. <c>url</c> or <c>comment</c>.</summary>
    public string? Type { get; }

    /// <summary>Object identifier.</summary>
    public string? Id { get; }

    /// <summary>Deconstructs into a <c>(Type, Id)</c> tuple, enabling <c>var (type, id) = ...</c>.</summary>
    public void Deconstruct(out string? type, out string? id)
    {
        type = Type;
        id = Id;
    }

    /// <inheritdoc />
    public override string ToString() => $"{Type}/{Id}";
}