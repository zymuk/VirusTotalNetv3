using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.v3.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;
using Xunit;

namespace VirusTotalNet.v3.Tests;

public class SavedSearchAndThreatActorTests
{
    private static VirusTotalOptions Options(string key = "test-key")
        => new() { ApiKey = key };

    private const string SavedSearchName = "my-search";
    private const string SavedSearchQuery = "type:file";

    private const string ThreatActorId = "threat-actor-123";

    private static string SavedSearchJson(string id = "saved-search-abc")
        => @"{ ""data"": { ""type"": ""saved_search"", ""id"": """ + id + @""", ""attributes"": { ""name"": """ + SavedSearchName + @""", ""query"": """ + SavedSearchQuery + @""" } } }";

    private static string ThreatActorJson(string id = ThreatActorId)
        => @"{ ""data"": { ""type"": ""threat_actor"", ""id"": """ + id + @""", ""attributes"": { ""name"": ""APT-1"", ""reputation"": 85, ""first_seen"": ""2023-01-15T00:00:00Z"", ""last_seen"": ""2024-12-31T23:59:59Z"" } } }";

    [Fact]
    public async Task CreateSavedSearch_Posts_CorrectJson()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, SavedSearchJson("saved-search-abc")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SavedSearchClient(vt);

        var saved = await client.CreateSavedSearchAsync(SavedSearchName, SavedSearchQuery);

        Assert.Equal("saved-search-abc", saved!.Id);
        Assert.Equal(SavedSearchName, saved.Attributes!.Name);
        Assert.Equal(SavedSearchQuery, saved.Attributes!.Query);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://www.virustotal.com/api/v3/saved_searches", request.RequestUri!.ToString());
        // Check that the request body contains the expected fields (JSON formatting may vary)
        Assert.Contains("saved_search", handler.LastRequestBody!);
        Assert.Contains("my-search", handler.LastRequestBody!);
        Assert.Contains("type:file", handler.LastRequestBody!);
    }

    [Fact]
    public async Task GetSavedSearch_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, SavedSearchJson("saved-search-abc")));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SavedSearchClient(vt);

        var saved = await client.GetSavedSearchAsync("saved-search-abc");

        Assert.Equal("saved-search-abc", saved!.Id);
        Assert.Equal(SavedSearchName, saved.Attributes!.Name);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://www.virustotal.com/api/v3/saved_searches/saved-search-abc", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task ListSavedSearches_Returns_Collection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                @"{ ""data"": [ { ""type"": ""saved_search"", ""id"": ""ss1"", ""attributes"": { ""name"": ""search1"", ""query"": ""type:file"" } },
                                  { ""type"": ""saved_search"", ""id"": ""ss2"", ""attributes"": { ""name"": ""search2"", ""query"": ""type:url"" } } ],
                  ""meta"": { ""count"": 2, ""cursor"": ""abc123"" },
                  ""links"": { ""next"": ""https://vt.com/api/v3/saved_searches?cursor=abc123"" } }"));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SavedSearchClient(vt);

        var collection = await client.ListSavedSearchesAsync();

        Assert.Equal(2, collection!.Count);
        Assert.Equal("abc123", collection!.NextCursor);
        Assert.Equal(2, collection.Items.Count);
        Assert.Equal("ss1", collection.Items[0].Id);
        Assert.Equal("search1", collection.Items[0].Attributes!.Name);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://www.virustotal.com/api/v3/saved_searches", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DeleteSavedSearch_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new SavedSearchClient(vt);

        await client.DeleteSavedSearchAsync("saved-search-abc");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal("https://www.virustotal.com/api/v3/saved_searches/saved-search-abc", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetThreatActor_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, ThreatActorJson()));

        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new ThreatActorClient(vt);

        var actor = await client.GetThreatActorAsync(ThreatActorId);

        Assert.Equal(ThreatActorId, actor!.Id);
        Assert.Equal("APT-1", actor.Attributes!.Name);
        Assert.Equal(85, actor.Attributes!.Reputation);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("https://www.virustotal.com/api/v3/threat_actors/" + ThreatActorId, request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DeleteAsync_Basic_Returns_Envelope()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));

        using var vt = new VtClient(Options(), new HttpClient(handler));

        var response = await vt.DeleteAsync<SavedSearchObject>("/saved_searches/saved-search-abc");

        Assert.Null(response.Error);
        Assert.Null(response.Data);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
    }

    [Fact]
    public async Task TryDeleteAsync_Returns_Failure_When_ThrowOnError_True_And_404()
    {
        var handler = new StubHttpMessageHandler(
            request => StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                @"{ ""error"": { ""code"": ""NotFoundError"", ""message"": ""Not found"" } }"));

        using var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key", ThrowOnError = true }, new HttpClient(handler));

        var result = await vt.TryDeleteAsync<SavedSearchObject>("/saved_searches/nonexistent");

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Equal("NotFoundError", result.Error!.Code);
    }

    [Fact]
    public async Task TryDeleteAsync_Returns_Error_In_Result_Regardless_Of_ThrowOnError()
    {
        var handler = new StubHttpMessageHandler(
            request => StubHttpMessageHandler.Json(HttpStatusCode.NotFound,
                @"{ ""error"": { ""code"": ""NotFoundError"", ""message"": ""Not found"" } }"));

        using var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key", ThrowOnError = false }, new HttpClient(handler));

        var result = await vt.TryDeleteAsync<SavedSearchObject>("/saved_searches/nonexistent");

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Equal("NotFoundError", result.Error!.Code);
    }
}