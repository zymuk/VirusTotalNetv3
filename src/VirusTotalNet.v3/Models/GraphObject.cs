using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// A graph object returned by <c>/graphs/{id}</c> endpoints.
/// </summary>
public sealed class GraphObject : VtObject<GraphAttributes>
{
}