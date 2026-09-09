using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalNet.Tests.TestInternals;

/// <summary>
/// A fake <see cref="HttpMessageHandler"/> that returns a scripted response
/// and records the requests it received for assertions.
/// </summary>
public sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    /// <summary>Raw body of the most recent request, captured before the content is disposed.</summary>
    public string? LastRequestBody { get; private set; }

    public List<HttpRequestMessage> Requests { get; } = new();

    public StubHttpMessageHandler(HttpResponseMessage response)
    {
        _responder = _ => response;
    }

    public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        _responder = responder;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);

        if (request.Content is not null)
            LastRequestBody = await request.Content.ReadAsStringAsync().ConfigureAwait(false);

        var response = _responder(request);
        response.RequestMessage = request;
        return response;
    }

    public static HttpResponseMessage Json(HttpStatusCode statusCode, string json)
    {
        return new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
    }
}
