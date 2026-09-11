using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.Models;

/// <summary>
/// A threat actor object returned by <c>/threat_actors/{id}</c>.
/// </summary>
public sealed class ThreatActorObject : VtObject<ThreatActorAttributes>
{
}
