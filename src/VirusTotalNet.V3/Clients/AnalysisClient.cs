using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Models.Attributes;

namespace VirusTotalNet.V3.Clients;

/// <summary>
/// Operations on <c>analysis</c> resources: retrieve a single analysis and wait for completion.
/// </summary>
public interface IAnalysisClient
{
    /// <summary>
    /// Retrieves an analysis by its id (<c>GET /analyses/{id}</c>). The result may still be
    /// <c>queued</c> or <c>in-progress</c>; use <see cref="WaitForCompletionAsync"/> to wait.
    /// </summary>
    /// <param name="id">Id of the analysis, as returned when submitting a scan.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The analysis object, including its current status.</returns>
    Task<AnalysisObject> GetAnalysisAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Polls the analysis until it reaches an end status (<c>completed</c>) or until the given
    /// <paramref name="cancellationToken"/> is cancelled. Each poll shares the client's rate
    /// limiter. For unknown statuses the current analysis is returned as-is to avoid an
    /// endless loop.
    /// </summary>
    /// <param name="id">Id of the analysis to wait for.</param>
    /// <param name="pollInterval">Delay between polls; defaults to <see cref="AnalysisClient.DefaultPollInterval"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The completed analysis object.</returns>
    Task<AnalysisObject> WaitForCompletionAsync(string id, TimeSpan? pollInterval = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IAnalysisClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class AnalysisClient : IAnalysisClient
{
    /// <summary>Default delay between polls when waiting for an analysis to complete.</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(15);

    private readonly IVtClient _client;

    /// <summary>Creates an analysis client backed by the given <see cref="IVtClient"/>.</summary>
    public AnalysisClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<AnalysisObject> GetAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("An analysis id is required.", nameof(id));

        var response = await _client.GetAsync<AnalysisObject>($"/analyses/{id}", cancellationToken).ConfigureAwait(false);
        return response.EnsureSuccess().Data ?? new AnalysisObject();
    }

    /// <inheritdoc />
    public async Task<AnalysisObject> WaitForCompletionAsync(string id, TimeSpan? pollInterval = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("An analysis id is required.", nameof(id));

        var interval = pollInterval ?? DefaultPollInterval;
        if (interval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(pollInterval), "The poll interval must be positive.");

        while (true)
        {
            var analysis = await GetAnalysisAsync(id, cancellationToken).ConfigureAwait(false);

            var status = analysis.Attributes?.Status;
            if (!IsPending(status))
                return analysis;

            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsPending(string? status)
    {
        return string.Equals(status, AnalysisStatus.Queued, StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, AnalysisStatus.InProgress, StringComparison.OrdinalIgnoreCase);
    }
}