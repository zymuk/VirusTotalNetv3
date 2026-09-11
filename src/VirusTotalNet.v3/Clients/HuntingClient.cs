using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// Livehunt operations (<c>/intelligence/hunting_rulesets</c> and
/// <c>/intelligence/hunting_notifications</c>): manage hunting rulesets and view the
/// notifications they trigger on live intelligence traffic.
/// </summary>
public interface IHuntingClient
{
    /// <summary>Creates a hunting ruleset (<c>POST /intelligence/hunting_rulesets</c>).</summary>
    Task<HuntingRulesetObject> CreateRulesetAsync(string name, string rules, bool enabled = true, int limit = 100, List<string>? notificationEmails = null, string? matchObjectType = null, CancellationToken cancellationToken = default);

    /// <summary>Lists hunting rulesets (<c>GET /intelligence/hunting_rulesets</c>) with optional filtering and ordering.</summary>
    Task<VtCollection<HuntingRulesetObject>> ListRulesetsAsync(string? filter = null, string? order = null, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a hunting ruleset by its id (<c>GET /intelligence/hunting_rulesets/{id}</c>).</summary>
    Task<HuntingRulesetObject> GetRulesetAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Updates a hunting ruleset (<c>PATCH /intelligence/hunting_rulesets/{id}</c>); only provided fields are changed.</summary>
    Task<HuntingRulesetObject> UpdateRulesetAsync(string id, string? name = null, string? rules = null, bool? enabled = null, int? limit = null, List<string>? notificationEmails = null, CancellationToken cancellationToken = default);

    /// <summary>Deletes a hunting ruleset (<c>DELETE /intelligence/hunting_rulesets/{id}</c>).</summary>
    Task DeleteRulesetAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Lists hunting notifications (<c>GET /intelligence/hunting_notifications</c>) with optional filtering, ordering and page size.</summary>
    Task<VtCollection<HuntingNotificationObject>> ListNotificationsAsync(string? filter = null, string? order = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a hunting notification by its id (<c>GET /intelligence/hunting_notifications/{id}</c>).</summary>
    Task<HuntingNotificationObject> GetNotificationAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary><see cref="IHuntingClient"/> implementation built on top of <see cref="VtClient"/>.</summary>
public sealed class HuntingClient : IHuntingClient
{
    private const string RulesetsPath = "/intelligence/hunting_rulesets";
    private const string NotificationsPath = "/intelligence/hunting_notifications";

    private readonly IVtClient _client;

    /// <summary>Creates a hunting client backed by the given <see cref="IVtClient"/>.</summary>
    public HuntingClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<HuntingRulesetObject> CreateRulesetAsync(string name, string rules, bool enabled = true, int limit = 100, List<string>? notificationEmails = null, string? matchObjectType = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("A ruleset name is required.", nameof(name));
        if (string.IsNullOrWhiteSpace(rules))
            throw new ArgumentException("Rules are required.", nameof(rules));

        var response = await _client.PostAsync<HuntingRulesetObject>(RulesetsPath, new
        {
            data = new
            {
                type = "hunting_ruleset",
                attributes = new { name, rules, enabled, limit, notificationEmails, matchObjectType }
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no hunting ruleset.");
    }

    /// <inheritdoc />
    public async Task<VtCollection<HuntingRulesetObject>> ListRulesetsAsync(string? filter = null, string? order = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = RulesetsPath;
        var separator = "?";
        if (filter is not null)
        {
            path += separator + "filter=" + Uri.EscapeDataString(filter);
            separator = "&";
        }
        if (order is not null)
        {
            path += separator + "order=" + Uri.EscapeDataString(order);
            separator = "&";
        }
        if (cursor is not null)
            path += separator + "cursor=" + Uri.EscapeDataString(cursor);

        var response = await _client.GetAsync<List<HuntingRulesetObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<HuntingRulesetObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<HuntingRulesetObject> GetRulesetAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A ruleset id is required.", nameof(id));

        var response = await _client.GetAsync<HuntingRulesetObject>($"{RulesetsPath}/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no hunting ruleset.");
    }

    /// <inheritdoc />
    public async Task<HuntingRulesetObject> UpdateRulesetAsync(string id, string? name = null, string? rules = null, bool? enabled = null, int? limit = null, List<string>? notificationEmails = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A ruleset id is required.", nameof(id));

        var attributes = new Dictionary<string, object>();
        if (name is not null) attributes["name"] = name;
        if (rules is not null) attributes["rules"] = rules;
        if (enabled is not null) attributes["enabled"] = enabled.Value;
        if (limit is not null) attributes["limit"] = limit.Value;
        if (notificationEmails is not null) attributes["notification_emails"] = notificationEmails;

        if (attributes.Count == 0)
            throw new ArgumentException("At least one field must be provided for update.", nameof(name));

        var response = await _client.PatchAsync<HuntingRulesetObject>($"{RulesetsPath}/{id}", new
        {
            data = new
            {
                type = "hunting_ruleset",
                id,
                attributes
            }
        }, cancellationToken).ConfigureAwait(false);

        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no hunting ruleset.");
    }

    /// <inheritdoc />
    public async Task DeleteRulesetAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A ruleset id is required.", nameof(id));

        var response = await _client.DeleteAsync<HuntingRulesetObject>($"{RulesetsPath}/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccess();
    }

    /// <inheritdoc />
    public async Task<VtCollection<HuntingNotificationObject>> ListNotificationsAsync(string? filter = null, string? order = null, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = NotificationsPath;
        var separator = "?";
        if (filter is not null)
        {
            path += separator + "filter=" + Uri.EscapeDataString(filter);
            separator = "&";
        }
        if (order is not null)
        {
            path += separator + "order=" + Uri.EscapeDataString(order);
            separator = "&";
        }
        if (limit is not null)
        {
            path += separator + "limit=" + limit.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
            separator = "&";
        }
        if (cursor is not null)
            path += separator + "cursor=" + Uri.EscapeDataString(cursor);

        var response = await _client.GetAsync<List<HuntingNotificationObject>>(path, cancellationToken).ConfigureAwait(false);
        return VtCollection<HuntingNotificationObject>.FromEnvelope(response.EnsureSuccess());
    }

    /// <inheritdoc />
    public async Task<HuntingNotificationObject> GetNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("A notification id is required.", nameof(id));

        var response = await _client.GetAsync<HuntingNotificationObject>($"{NotificationsPath}/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? throw new InvalidOperationException("The API returned no hunting notification.");
    }
}