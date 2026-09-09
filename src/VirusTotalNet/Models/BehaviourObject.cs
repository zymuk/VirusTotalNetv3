using VirusTotalNet.v3.Models.Attributes;

namespace VirusTotalNet.v3.Models;

/// <summary>
/// A <c>behaviour</c> object describing how a sample behaved in a sandbox, e.g. from
/// <c>GET /files/{id}/behaviours</c>.
/// </summary>
public sealed class BehaviourObject : VtObject<BehaviourAttributes>
{
}