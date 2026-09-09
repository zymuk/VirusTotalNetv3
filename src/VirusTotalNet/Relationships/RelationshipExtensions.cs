using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Relationships;

/// <summary>
/// Typed, discoverable accessors for the most common relationships, hanging off the parent object.
/// Each method delegates to the generic <see cref="IRelationshipsClient"/> implementation so it
/// inherits memoization and the shared rate limiter.
/// </summary>
public static class RelationshipExtensions
{
    /// <summary>URLs the file contacted, in analysis order.</summary>
    public static Task<VtCollection<UrlObject>> ContactedUrlsAsync(this FileObject file, IRelationshipsClient client, CancellationToken cancellationToken = default)
        => client.GetRelatedAsync<UrlObject>(file.Type, file.Id, RelationshipName.ContactedUrls, null, cancellationToken);

    /// <summary>URLs the file contacted that were detected as malicious.</summary>
    public static Task<VtCollection<UrlObject>> DetectedUrlsAsync(this FileObject file, IRelationshipsClient client, CancellationToken cancellationToken = default)
        => client.GetRelatedAsync<UrlObject>(file.Type, file.Id, RelationshipName.DetectedUrls, null, cancellationToken);

    /// <summary>Sandbox behaviour reports of the file.</summary>
    public static Task<VtCollection<BehaviourObject>> BehavioursAsync(this FileObject file, IRelationshipsClient client, CancellationToken cancellationToken = default)
        => client.GetRelatedAsync<BehaviourObject>(file.Type, file.Id, RelationshipName.Behaviours, null, cancellationToken);

    /// <summary>Historical IP resolutions of the domain.</summary>
    public static Task<VtCollection<ResolutionObject>> ResolutionsAsync(this DomainObject domain, IRelationshipsClient client, CancellationToken cancellationToken = default)
        => client.GetRelatedAsync<ResolutionObject>(domain.Type, domain.Id, RelationshipName.Resolutions, null, cancellationToken);

    /// <summary>Subdomains of the domain.</summary>
    public static Task<VtCollection<DomainObject>> SubdomainsAsync(this DomainObject domain, IRelationshipsClient client, CancellationToken cancellationToken = default)
        => client.GetRelatedAsync<DomainObject>(domain.Type, domain.Id, RelationshipName.Subdomains, null, cancellationToken);

    /// <summary>Domains that have resolved to the IP address.</summary>
    public static Task<VtCollection<ResolutionObject>> ResolutionsAsync(this IpObject ip, IRelationshipsClient client, CancellationToken cancellationToken = default)
        => client.GetRelatedAsync<ResolutionObject>(ip.Type, ip.Id, RelationshipName.Resolutions, null, cancellationToken);

    /// <summary>Comments attached to any object.</summary>
    public static Task<VtCollection<CommentObject>> CommentsAsync<TA>(this VtObject<TA> obj, IRelationshipsClient client, CancellationToken cancellationToken = default)
        where TA : class
        => client.GetRelatedAsync<CommentObject>(obj.Type, obj.Id, RelationshipName.Comments, null, cancellationToken);

    /// <summary>Votes attached to any object.</summary>
    public static Task<VtCollection<VoteObject>> VotesAsync<TA>(this VtObject<TA> obj, IRelationshipsClient client, CancellationToken cancellationToken = default)
        where TA : class
        => client.GetRelatedAsync<VoteObject>(obj.Type, obj.Id, RelationshipName.Votes, null, cancellationToken);
}