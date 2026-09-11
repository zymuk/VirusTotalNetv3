using System.Net;
using VirusTotalNet.V3.Models;

namespace VirusTotalNet.V3.Core;

/// <summary>
/// Internal guard used by the typed client modules: converts an error envelope into the typed
/// exception hierarchy so a client never silently returns an empty object when the API rejected
/// the request (e.g. while <see cref="VirusTotalOptions.ThrowOnError"/> is <c>false</c>).
/// </summary>
internal static class ResponseExtensions
{
    internal static VtResponse<T> EnsureSuccess<T>(this VtResponse<T> response)
    {
        if (response.Error is { } error)
            throw VtClient.MapErrorToException(error, error.StatusCode ?? HttpStatusCode.BadGateway);
        return response;
    }
}