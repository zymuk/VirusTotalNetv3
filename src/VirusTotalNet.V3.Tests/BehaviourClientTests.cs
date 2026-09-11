using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.V3.Tests.TestInternals;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.Tests;

public class BehaviourClientTests
{
    private const string BehaviourId = "aa1c00e982e0e0e4fdf1c70ddf2b2f7f4d0c9e7e702f00e3f9a76f8c6d5a4b3c2_SomeSandbox";

    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private static string BehaviourJson() => $$"""
    {
      "data": {
        "type": "file_behaviour",
        "id": "{{BehaviourId}}",
        "attributes": {
          "sandbox_name": "SomeSandbox",
          "behash": "e77446099f5d2fe3278cd6613bc70a76",
          "analysis_date": 1671810990,
          "has_html_report": true,
          "has_evtx": false,
          "has_memdump": false,
          "has_pcap": true,
          "calls_highlighted": ["GetTickCount"],
          "text_highlighted": ["Kirikiri"],
          "mitre_attack_techniques": [
            { "signature_description": "Obfuscated files or information", "id": "T1027", "severity": "3.5" }
          ]
        }
      }
    }
    """;

    [Fact]
    public async Task GetBehaviour_SendsGet_ToBehaviourEndpoint()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, BehaviourJson()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        var behaviour = await client.GetBehaviourAsync(BehaviourId);

        Assert.Equal(BehaviourId, behaviour.Id);
        Assert.Equal("SomeSandbox", behaviour.Attributes!.SandboxName);
        Assert.Equal("e77446099f5d2fe3278cd6613bc70a76", behaviour.Attributes.Behash);
        Assert.True(behaviour.Attributes.HasHtmlReport);
        Assert.False(behaviour.Attributes.HasEvtx);
        Assert.True(behaviour.Attributes.HasPcap);
        Assert.NotNull(behaviour.Attributes.MitreAttackTechniques);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/file_behaviours/" + BehaviourId, request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetBehaviour_MapsMitreAttackTechniques()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, BehaviourJson()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        var behaviour = await client.GetBehaviourAsync(BehaviourId);

        var technique = Assert.Single(behaviour.Attributes!.MitreAttackTechniques!);
        Assert.Equal("T1027", technique.Id);
        Assert.Equal("Obfuscated files or information", technique.SignatureDescription);
        Assert.Equal("3.5", technique.Severity);
    }

    [Fact]
    public async Task DownloadEvtx_SendsGet_ToEvtxEndpoint_ReturnsStream()
    {
        var payload = new byte[] { 0x45, 0x76, 0x65, 0x6E, 0x74 };
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload)
        });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        using var stream = await client.DownloadEvtxAsync(BehaviourId);

        Assert.IsType<MemoryStream>(stream);
        var bytes = await ReadAllAsync(stream);
        Assert.Equal(payload, bytes);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/file_behaviours/" + BehaviourId + "/evtx", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DownloadPcap_SendsGet_ToPcapEndpoint_ReturnsStream()
    {
        var payload = Encoding.UTF8.GetBytes("PCAP");
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload)
        });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        using var stream = await client.DownloadPcapAsync(BehaviourId);

        var bytes = await ReadAllAsync(stream);
        Assert.Equal(payload, bytes);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/file_behaviours/" + BehaviourId + "/pcap", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DownloadMemdump_SendsGet_ToMemdumpEndpoint_ReturnsStream()
    {
        var payload = Encoding.UTF8.GetBytes("MEMDUMP");
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload)
        });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        using var stream = await client.DownloadMemdumpAsync(BehaviourId);

        var bytes = await ReadAllAsync(stream);
        Assert.Equal(payload, bytes);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/file_behaviours/" + BehaviourId + "/memdump", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DownloadHtml_SendsGet_ToHtmlEndpoint_ReturnsStream()
    {
        var payload = Encoding.UTF8.GetBytes("<html>report</html>");
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload)
        });

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        using var stream = await client.DownloadHtmlAsync(BehaviourId);

        var bytes = await ReadAllAsync(stream);
        Assert.Equal(payload, bytes);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/file_behaviours/" + BehaviourId + "/html", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task Methods_InvalidId_ThrowWithoutSendingRequests()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, BehaviourJson()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new BehaviourClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetBehaviourAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.DownloadEvtxAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.DownloadPcapAsync(" "));
        await Assert.ThrowsAsync<ArgumentException>(() => client.DownloadMemdumpAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.DownloadHtmlAsync(" "));

        Assert.Empty(handler.Requests);
    }

    private static async Task<byte[]> ReadAllAsync(Stream stream)
    {
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms);
        return ms.ToArray();
    }
}