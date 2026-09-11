using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// A collection object returned by <c>/collections/{id}</c> endpoints.
/// </summary>
public sealed class CollectionObject : VtObject<CollectionAttributes>
{
}