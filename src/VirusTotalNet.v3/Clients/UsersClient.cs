using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// Operations on users and groups (<c>/users</c> and <c>/groups</c>): retrieve, update and
/// delete accounts, and manage group membership.
/// </summary>
public interface IUsersClient
{
    /// <summary>Retrieves a user by its id (<c>GET /users/{id}</c>).</summary>
    Task<UserObject> GetUserAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a user (<c>PATCH /users/{id}</c>); only provided fields are changed.</summary>
    Task<UserObject> UpdateUserAsync(string id, string? displayName = null, string? email = null, string? name = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a user (<c>DELETE /users/{id}</c>).</summary>
    Task DeleteUserAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a group by its id (<c>GET /groups/{id}</c>).</summary>
    Task<GroupObject> GetGroupAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a group (<c>PATCH /groups/{id}</c>).</summary>
    Task<GroupObject> UpdateGroupAsync(string id, string? name = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a group (<c>DELETE /groups/{id}</c>).</summary>
    Task DeleteGroupAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Lists the members of a group (<c>GET /groups/{id}/users</c>) with cursor pagination.</summary>
    Task<VtCollection<UserObject>> ListGroupUsersAsync(string id, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>Adds a user to a group (<c>POST /groups/{id}/users</c>).</summary>
    Task<UserObject> AddUserToGroupAsync(string groupId, string userId, string privileges = "full_admin", CancellationToken cancellationToken = default);

    /// <summary>Removes a user from a group (<c>DELETE /groups/{id}/users/{userId}</c>).</summary>
    Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IUsersClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class UsersClient : IUsersClient
{
    private readonly IVtClient _client;

    /// <summary>Creates a users client backed by the given <see cref="IVtClient"/>.</summary>
    public UsersClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<UserObject> GetUserAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var response = await _client.GetAsync<UserObject>($"/users/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no user.");
    }

    /// <inheritdoc />
    public async Task<UserObject> UpdateUserAsync(string id, string? displayName = null, string? email = null, string? name = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var attributes = new Dictionary<string, object>();
        if (displayName is not null) attributes["display_name"] = displayName;
        if (email is not null) attributes["email"] = email;
        if (name is not null) attributes["name"] = name;

        if (attributes.Count == 0)
            throw new ArgumentException("At least one field must be provided for update.", nameof(displayName));

        var response = await _client.PatchAsync<UserObject>($"/users/{id}", new
        {
            data = new
            {
                type = "user",
                id,
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no user.");
    }

    /// <inheritdoc />
    public async Task DeleteUserAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A user id is required.", nameof(id));

        var response = await _client.DeleteAsync<UserObject>($"/users/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<GroupObject> GetGroupAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));

        var response = await _client.GetAsync<GroupObject>($"/groups/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no group.");
    }

    /// <inheritdoc />
    public async Task<GroupObject> UpdateGroupAsync(string id, string? name = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A group name is required.", nameof(name));

        var response = await _client.PatchAsync<GroupObject>($"/groups/{id}", new
        {
            data = new
            {
                type = "group",
                id,
                attributes = new { name }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no group.");
    }

    /// <inheritdoc />
    public async Task DeleteGroupAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));

        var response = await _client.DeleteAsync<GroupObject>($"/groups/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<VtCollection<UserObject>> ListGroupUsersAsync(string id, string? cursor = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A group id is required.", nameof(id));

        var path = $"/groups/{id}/users";
        if (cursor is not null)
            path += $"?cursor={Uri.EscapeDataString(cursor)}";

        var response = await _client.GetAsync<List<UserObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<UserObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<UserObject> AddUserToGroupAsync(string groupId, string userId, string privileges = "full_admin", CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(groupId))
            throw new ArgumentException("A group id is required.", nameof(groupId));
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("A user id is required.", nameof(userId));

        var response = await _client.PostAsync<UserObject>($"/groups/{groupId}/users", new
        {
            data = new
            {
                type = "user",
                id = userId,
                attributes = new { privileges }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no user.");
    }

    /// <inheritdoc />
    public async Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(groupId))
            throw new ArgumentException("A group id is required.", nameof(groupId));
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("A user id is required.", nameof(userId));

        var response = await _client.DeleteAsync<UserObject>($"/groups/{groupId}/users/{userId}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }
}