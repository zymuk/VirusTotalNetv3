using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// A graph object returned by <c>/graphs/{id}</c> endpoints.
/// </summary>
public sealed class GraphObject : VtObject<GraphAttributes>
{
}