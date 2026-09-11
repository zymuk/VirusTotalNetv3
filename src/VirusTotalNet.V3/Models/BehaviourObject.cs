using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// A <c>behaviour</c> object describing how a sample behaved in a sandbox, e.g. from
/// <c>GET /files/{id}/behaviours</c> or <c>GET /file_behaviours/{id}</c>.
/// </summary>
public sealed class BehaviourObject : VtObject<BehaviourAttributes>
{
}