using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// Comments and votes on any object type (files, URLs, domains, IP addresses).
/// </summary>
public interface IFeedbackClient
{
    /// <summary>
    /// Lists the comments of an object (<c>GET /{objectType}/{id}/comments</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id (for URLs, the base64url-encoded id).</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<CommentObject>> GetCommentsAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a comment to an object (<c>POST /{objectType}/{id}/comments</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="text">The comment text (markdown).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created comment object.</returns>
    Task<CommentObject> AddCommentAsync(string objectType, string id, string text, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the votes of an object (<c>GET /{objectType}/{id}/votes</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="cursor">Optional pagination cursor for the next page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<VtCollection<VoteObject>> GetVotesAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Casts a vote on an object (<c>POST /{objectType}/{id}/votes</c>).
    /// </summary>
    /// <param name="objectType">Object type path segment, see <see cref="VtObjectType"/>.</param>
    /// <param name="id">Object id.</param>
    /// <param name="verdict">The verdict, e.g. <c>malicious</c> or <c>harmless</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created vote object.</returns>
    Task<VoteObject> AddVoteAsync(string objectType, string id, string verdict, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IFeedbackClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class FeedbackClient : IFeedbackClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a feedback (comments/votes) client backed by the given <see cref="IVtClient"/>.</summary>
    public FeedbackClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<VtCollection<CommentObject>> GetCommentsAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        var response = await _client.GetAsync<List<CommentObject>>(Paginate(path + "/comments", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<CommentObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<CommentObject> AddCommentAsync(string objectType, string id, string text, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Comment text is required.", nameof(text));

        var body = new { data = new { type = VtObjectType.Comment, attributes = new { text } } };
        var response = await _client.PostAsync<CommentObject>(path + "/comments", body, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new CommentObject();
    }

    /// <inheritdoc />
    public async Task<VtCollection<VoteObject>> GetVotesAsync(string objectType, string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        var response = await _client.GetAsync<List<VoteObject>>(Paginate(path + "/votes", cursor), cancellationToken).ConfigureAwait(false);
        return VtCollection<VoteObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<VoteObject> AddVoteAsync(string objectType, string id, string verdict, CancellationToken cancellationToken = default)
    {
        var path = ValidatePath(objectType, id);
        if (string.IsNullOrWhiteSpace(verdict))
            throw new ArgumentException("A verdict is required.", nameof(verdict));

        var body = new { data = new { type = VtObjectType.Vote, attributes = new { verdict } } };
        var response = await _client.PostAsync<VoteObject>(path + "/votes", body, cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new VoteObject();
    }

    private static string ValidatePath(string objectType, string id)
    {
        if (string.IsNullOrWhiteSpace(objectType))
            throw new ArgumentException("An object type is required.", nameof(objectType));
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("An object id is required.", nameof(id));

        return $"/{objectType.Trim()}/{id.Trim()}";
    }

    private static string Paginate(string path, string? cursor)
        => string.IsNullOrEmpty(cursor) ? path : $"{path}?cursor={Uri.EscapeDataString(cursor)}";
}