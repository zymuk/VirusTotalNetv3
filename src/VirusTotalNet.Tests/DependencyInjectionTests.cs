using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VirusTotalNet.Tests.TestInternals;
using VirusTotalNet.v3;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.DependencyInjection;
using VirusTotalNet.v3.Models;
using VirusTotalNet.v3.Relationships;

namespace VirusTotalNet.Tests;

public class DependencyInjectionTests
{
    [Fact]
    public void AddVirusTotal_RegistersAllModuleClientsAndFacade()
    {
        var services = new ServiceCollection();
        services.AddVirusTotal(options => options.ApiKey = "test-key");

        using var provider = services.BuildServiceProvider();

        Assert.IsType<FileClient>(provider.GetRequiredService<IFileClient>());
        Assert.IsType<BehaviourClient>(provider.GetRequiredService<IBehaviourClient>());
        Assert.IsType<AnalysisClient>(provider.GetRequiredService<IAnalysisClient>());
        Assert.IsType<UrlClient>(provider.GetRequiredService<IUrlClient>());
        Assert.IsType<DomainClient>(provider.GetRequiredService<IDomainClient>());
        Assert.IsType<IpClient>(provider.GetRequiredService<IIpClient>());
        Assert.IsType<FeedbackClient>(provider.GetRequiredService<IFeedbackClient>());
        Assert.IsType<SearchClient>(provider.GetRequiredService<ISearchClient>());
        Assert.IsType<RelationshipsClient>(provider.GetRequiredService<IRelationshipsClient>());
        Assert.IsType<VirusTotal>(provider.GetRequiredService<VirusTotal>());
    }

    [Fact]
    public void AddVirusTotal_SharesOneClientAcrossRegistrations()
    {
        var services = new ServiceCollection();
        services.AddVirusTotal(options => options.ApiKey = "test-key");

        using var provider = services.BuildServiceProvider();

        var client = provider.GetRequiredService<IVtClient>();
        Assert.Same(client, provider.GetRequiredService<VtClient>());
        Assert.Same(client, provider.GetRequiredService<VirusTotal>().Client);
    }

    [Fact]
    public async Task AddVirusTotal_UsesContainerHttpClient_ForAllClients()
    {
        var handler = new StubHttpMessageHandler(
            request => StubHttpMessageHandler.Json(HttpStatusCode.OK,
                """{ "data": { "type": "file", "id": "abc" } }"""));

        var services = new ServiceCollection();
        services.AddSingleton(new HttpClient(handler));
        services.AddVirusTotal(options => options.ApiKey = "test-key");

        using var provider = services.BuildServiceProvider();

        var file = await provider.GetRequiredService<IFileClient>().GetFileAsync("abc");

        Assert.Equal("abc", file.Id);
        Assert.Single(handler.Requests);

        // The same stubbed HttpClient is reachable through the facade's shared client.
        await provider.GetRequiredService<VirusTotal>().Client.GetAsync<FileObject>("/files/def");
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public void AddVirusTotal_ConfigurationSection_BindsOptions()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VirusTotal:ApiKey"] = "key-from-config",
                ["VirusTotal:RequestsPerMinute"] = "10",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddVirusTotal(configuration);

        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<VirusTotalOptions>();
        Assert.Equal("key-from-config", options.ApiKey);
        Assert.Equal(10, options.RequestsPerMinute);
    }

    [Fact]
    public void AddVirusTotal_MissingApiKey_ThrowsOnResolve()
    {
        var services = new ServiceCollection();
        services.AddVirusTotal();

        using var provider = services.BuildServiceProvider();

        Assert.Throws<ArgumentException>(() => provider.GetRequiredService<IVtClient>());
    }

    [Fact]
    public void AddVirusTotal_ApiKey_IsSentAsHeader()
    {
        var services = new ServiceCollection();
        services.AddVirusTotal(options => options.ApiKey = "secret-key");

        using var provider = services.BuildServiceProvider();

        var vt = provider.GetRequiredService<VirusTotal>();
        Assert.Equal("secret-key", Assert.Single(vt.Client.Client.DefaultRequestHeaders.GetValues("x-apikey")));
    }
}