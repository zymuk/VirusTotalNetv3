using System.Text.Json;
using VirusTotalNet.v3.Core;

namespace VirusTotalNet.v3.Tests;

public class OptionsTests
{
    [Fact]
    public void Defaults_AreDocumentedValues()
    {
        var options = new VirusTotalOptions();

        Assert.Equal(string.Empty, options.ApiKey);
        Assert.Equal(new Uri(VirusTotalOptions.DefaultBaseAddress), options.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(100), options.Timeout);
        Assert.Equal(4, options.RequestsPerMinute);
        Assert.Equal(500, options.RequestsPerDay);
        Assert.True(options.UseRetry);
        Assert.Equal(3, options.MaxRetries);
        Assert.Equal(TimeSpan.FromMilliseconds(500), options.InitialRetryDelay);
        Assert.True(options.ThrowOnError);
    }

    [Fact]
    public void Validate_Throws_WhenApiKeyEmpty()
    {
        var options = new VirusTotalOptions();

        Assert.Throws<ArgumentException>(() => options.Validate());
    }

    [Fact]
    public void Validate_Throws_WhenApiKeyWhitespace()
    {
        var options = new VirusTotalOptions { ApiKey = "   " };

        Assert.Throws<ArgumentException>(() => options.Validate());
    }

    [Fact]
    public void Validate_Passes_WithApiKey()
    {
        var options = new VirusTotalOptions { ApiKey = "test-key" };

        options.Validate();
    }

    [Fact]
    public void Validate_Throws_WhenLimitsNonPositive()
    {
        var badMinute = new VirusTotalOptions { ApiKey = "k", RequestsPerMinute = 0 };
        var badDay = new VirusTotalOptions { ApiKey = "k", RequestsPerDay = -1 };

        Assert.Throws<ArgumentException>(() => badMinute.Validate());
        Assert.Throws<ArgumentException>(() => badDay.Validate());
    }

    [Fact]
    public void CreateOptions_ConfiguresTolerantJson()
    {
        var options = VirusTotalJson.CreateOptions();

        Assert.Equal(JsonNamingPolicy.SnakeCaseLower, options.PropertyNamingPolicy);
        Assert.True(options.PropertyNameCaseInsensitive);
        Assert.True(options.AllowTrailingCommas);
        Assert.Equal(3, options.Converters.Count);
    }

    [Fact]
    public void SharedOptions_AreStable()
    {
        var shared = VirusTotalJson.Options;

        Assert.NotNull(shared);
        Assert.Equal(VirusTotalJson.CreateOptions().Converters.Count, shared.Converters.Count);
    }
}