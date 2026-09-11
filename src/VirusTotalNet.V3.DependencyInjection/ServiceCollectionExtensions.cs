using System;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using VirusTotalNet.V3.Clients;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Relationships;

namespace VirusTotalNet.V3.DependencyInjection;

/// <summary>
/// Service-collection extensions for the VirusTotal API v3 client. This package is optional:
/// registering with <see cref="AddVirusTotal(IServiceCollection, Action{VirusTotalOptions}?)"/>
/// adds the client, its options and every module client to the container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the VirusTotal API v3 client and all module clients (files, analyses, URLs,
    /// domains, IPs, feedback, search, relationships) plus the <see cref="VirusTotal"/> facade.
    /// All clients are singletons backed by one shared <see cref="IVtClient"/>.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">Optional delegate to configure <see cref="VirusTotalOptions"/>; required if the API key is not supplied another way.</param>
    /// <returns>The same service collection for chaining.</returns>
    public static IServiceCollection AddVirusTotal(this IServiceCollection services, Action<VirusTotalOptions>? configure = null)
    {
        if (services is null)
            throw new ArgumentNullException(nameof(services));

        services.AddOptions<VirusTotalOptions>();
        if (configure is not null)
            services.Configure(configure);

        return RegisterVirusTotalServices(services);
    }

    /// <summary>
    /// Registers the VirusTotal API v3 client bound from an <c>IConfiguration</c> section
    /// (default section name <c>"VirusTotal"</c>, matching the <see cref="VirusTotalOptions"/> property names).
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configuration">Configuration root to read the section from.</param>
    /// <param name="sectionName">Name of the section holding the options.</param>
    /// <returns>The same service collection for chaining.</returns>
    public static IServiceCollection AddVirusTotal(this IServiceCollection services, IConfiguration configuration, string sectionName = "VirusTotal")
    {
        if (services is null)
            throw new ArgumentNullException(nameof(services));
        if (configuration is null)
            throw new ArgumentNullException(nameof(configuration));

        services.AddOptions<VirusTotalOptions>().Bind(configuration.GetSection(sectionName));

        return RegisterVirusTotalServices(services);
    }

    private static IServiceCollection RegisterVirusTotalServices(IServiceCollection services)
    {
        services.AddSingleton(sp => sp.GetRequiredService<IOptions<VirusTotalOptions>>().Value);

        services.AddSingleton(sp => new VtClient(
            sp.GetRequiredService<VirusTotalOptions>(),
            sp.GetService<HttpClient>()));

        services.AddSingleton<IVtClient>(sp => sp.GetRequiredService<VtClient>());

        services.AddSingleton<IFileClient, FileClient>();
        services.AddSingleton<IBehaviourClient, BehaviourClient>();
        services.AddSingleton<IAnalysisClient, AnalysisClient>();
        services.AddSingleton<IUrlClient, UrlClient>();
        services.AddSingleton<IDomainClient, DomainClient>();
        services.AddSingleton<IIpClient, IpClient>();
        services.AddSingleton<IFeedbackClient, FeedbackClient>();
        services.AddSingleton<ISearchClient, SearchClient>();
        services.AddSingleton<IRelationshipsClient, RelationshipsClient>();
        services.AddSingleton<ISavedSearchClient, SavedSearchClient>();
        services.AddSingleton<IThreatActorClient, ThreatActorClient>();
        services.AddSingleton<ICollectionClient, CollectionClient>();
        services.AddSingleton<IGraphClient, GraphClient>();
        services.AddSingleton<IFeedsClient, FeedsClient>();
        services.AddSingleton<IPrivateScanningClient, PrivateScanningClient>();
        services.AddSingleton<IHuntingClient, HuntingClient>();
        services.AddSingleton<IRetrohuntClient, RetrohuntClient>();
        services.AddSingleton<IUsersClient, UsersClient>();

        services.AddSingleton(sp => new VirusTotal(sp.GetRequiredService<IVtClient>()));

        return services;
    }
}