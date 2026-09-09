using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;

namespace VirusTotalNet.v3.Clients;

/// <summary>
/// Operations on <c>file</c> resources: scan a sample via multipart upload and, in later
/// milestones, retrieve reports, rescan, and download.
/// </summary>
public interface IFileClient
{
    /// <summary>
    /// Uploads a file directly to VirusTotal and starts an analysis (<c>POST /files</c>).
    /// The file must not exceed <see cref="FileClient.MaxScanSize"/> bytes.
    /// </summary>
    /// <param name="stream">The file content to scan.</param>
    /// <param name="fileName">Name sent to the API; often used to infer the file type.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created analysis object; poll its id to retrieve the completed report.</returns>
    Task<AnalysisObject> ScanFileAsync(Stream stream, string? fileName = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// <see cref="IFileClient"/> implementation built on top of <see cref="VtClient"/>.
/// </summary>
public sealed class FileClient : IFileClient
{
    /// <summary>Maximum size in bytes of a file accepted by direct upload (32 MiB).</summary>
    public const long MaxScanSize = 32 * 1024 * 1024;

    private readonly IVtClient _client;

    /// <summary>Creates a file client backed by the given <see cref="IVtClient"/>.</summary>
    public FileClient(IVtClient client) => _client = client;

    /// <inheritdoc />
    public async Task<AnalysisObject> ScanFileAsync(Stream stream, string? fileName = null, CancellationToken cancellationToken = default)
    {
        if (stream is null)
            throw new ArgumentNullException(nameof(stream));

        if (stream.CanSeek && stream.Length > MaxScanSize)
            throw new ArgumentOutOfRangeException(nameof(stream), $"Files larger than {MaxScanSize} bytes cannot be uploaded directly; use the upload URL endpoint instead.");

        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(stream);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", fileName ?? "file");

        var response = await _client.PostAsync<AnalysisObject>("/files", content, cancellationToken).ConfigureAwait(false);
        return response.Data ?? new AnalysisObject();
    }
}