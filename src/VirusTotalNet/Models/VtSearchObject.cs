using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// A hit returned by <c>/intelligence/search</c>. Results are polymorphic (files, URLs,
/// domains, IP addresses, ...); the <c>Type</c>/<c>Id</c> pair identifies the object and the
/// attributes are kept losslessly in <c>Attributes.Raw</c>. Use the typed clients or
/// relationship navigation to expand a hit into a concrete object.
/// </summary>
public sealed class VtSearchObject : VtObject<SearchAttributes>
{
}