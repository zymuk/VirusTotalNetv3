using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// A saved search object returned by <c>/saved_searches</c> endpoints.
/// </summary>
public sealed class SavedSearchObject : VtObject<SavedSearchAttributes>
{
}
