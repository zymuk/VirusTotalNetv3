using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalNet.v3.Tests.TestInternals;
using VirusTotalNet.v3.Clients;
using VirusTotalNet.v3.Core;
using VirusTotalNet.v3.Models;
using Xunit;

namespace VirusTotalNet.v3.Tests;

public class FeedsClientTests
{
    private const string Time = "202609111200";
    private static readonly byte[] FakeBatch = { 0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };

    [Theory]
    [InlineData("files", "GetFileFeedStreamAsync")]
    [InlineData("urls", "GetUrlFeedStreamAsync")]
    [InlineData("domains", "GetDomainFeedStreamAsync")]
    [InlineData("ip_addresses", "GetIpFeedStreamAsync")]
    [InlineData("file_behaviours", "GetFileBehaviourFeedStreamAsync")]
    public async Task Feed_Returns_Stream_With_Expected_Content(string segment, string method)
    {
        var handler = new StubHttpMessageHandler(_ => ClientResponse());
        var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));
        var client = new FeedsClient(vt);

        var result = method switch
        {
            "GetFileFeedStreamAsync" => await client.GetFileFeedStreamAsync(Time),
            "GetUrlFeedStreamAsync" => await client.GetUrlFeedStreamAsync(Time),
            "GetDomainFeedStreamAsync" => await client.GetDomainFeedStreamAsync(Time),
            "GetIpFeedStreamAsync" => await client.GetIpFeedStreamAsync(Time),
            _ => await client.GetFileBehaviourFeedStreamAsync(Time)
        };

        using (result)
        {
            using var ms = new MemoryStream();
            await result.CopyToAsync(ms);
            Assert.Equal(FakeBatch, ms.ToArray());
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal($"https://www.virustotal.com/api/v3/feeds/{segment}/{Time}", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task HourlyBehaviourFeed_Uses_Hourly_Url()
    {
        var handler = new StubHttpMessageHandler(_ => ClientResponse());
        var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));
        var client = new FeedsClient(vt);

        using (await client.GetFileBehaviourFeedHourlyStreamAsync(Time))
        {
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"https://www.virustotal.com/api/v3/feeds/file_behaviours/{Time}/hourly", request.RequestUri!.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData(null)]
    public async Task Feed_Rejects_Empty_Time(string? time)
    {
        var handler = new StubHttpMessageHandler(_ => ClientResponse());
        var vt = new VtClient(new VirusTotalOptions { ApiKey = "test-key" }, new HttpClient(handler));
        var client = new FeedsClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.GetFileFeedStreamAsync(time!));
        Assert.Empty(handler.Requests);
    }

    private static HttpResponseMessage ClientResponse()
        => new(HttpStatusCode.OK) { Content = new ByteArrayContent(FakeBatch) };
}

public class PrivateScanningClientTests
{
    private const string PrivatePath = "https://www.virustotal.com/api/v3";

    private static string AnalysisJson(string id = "analysis-123") =>
        @"{ ""data"": { ""type"": ""analysis"", ""id"": """ + id + @""" } }";

    private static string PrivateFileJson(string id = "private-file-1") =>
        @"{ ""data"": { ""type"": ""private_file"", ""id"": """ + id + @""", ""attributes"": { ""size"": 1024, ""type_tag"": ""peexe"", ""sha256"": ""abcdef123456"" } } }";

    [Fact]
    public async Task UploadPrivateFile_Sends_Multipart_With_Options()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("analysis-777")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var fileBytes = new byte[] { 1, 2, 3 };
        using var stream = new MemoryStream(fileBytes);
        var analysis = await client.UploadPrivateFileAsync(stream, disableSandbox: false, enableInternet: true, retentionPeriodDays: 30, storageRegion: "EU");

        Assert.Equal("analysis-777", analysis!.Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{PrivatePath}/private/files", request.RequestUri!.ToString());
        Assert.Contains("disable_sandbox", handler.LastRequestBody!);
        Assert.Contains("enable_internet", handler.LastRequestBody!);
        Assert.Contains("retention_period_days", handler.LastRequestBody!);
        Assert.Contains("storage_region", handler.LastRequestBody!);
    }

    [Fact]
    public async Task UploadPrivateFile_Throws_When_File_Null()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson()));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        await Assert.ThrowsAsync<ArgumentNullException>(() => client.UploadPrivateFileAsync(null!));
    }

    [Fact]
    public async Task GetUploadUrl_Returns_Url()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ ""data"": ""https://upld.virustotal.com/user/test-url"" }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var url = await client.GetPrivateFileUploadUrlAsync();

        Assert.Equal("https://upld.virustotal.com/user/test-url", url);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal($"{PrivatePath}/private/files/upload_url", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task ListPrivateFiles_Returns_Collection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                @"{ ""data"": [ { ""type"": ""private_file"", ""id"": ""pf1"", ""attributes"": { ""size"": 10 } },
                                  { ""type"": ""private_file"", ""id"": ""pf2"", ""attributes"": { ""size"": 20 } } ],
                  ""meta"": { ""count"": 2, ""cursor"": ""cur123"" } }"
                .Replace('\'', '"')));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var collection = await client.ListPrivateFilesAsync("cur123");

        Assert.Equal(2, collection!.Count);
        Assert.Equal("cur123", collection.NextCursor);
        Assert.Equal("pf1", collection.Items[0].Id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{PrivatePath}/private/files?cursor=cur123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetPrivateFile_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, PrivateFileJson("pf-123")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var file = await client.GetPrivateFileAsync("pf-123");

        Assert.Equal("pf-123", file!.Id);
        Assert.Equal(1024, file.Attributes!.Size);
        Assert.Equal("peexe", file.Attributes.TypeTag);

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{PrivatePath}/private/files/pf-123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DeletePrivateFile_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        await client.DeletePrivateFileAsync("pf-123");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"{PrivatePath}/private/files/pf-123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AnalysePrivateFile_Returns_Analysis()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("analysis-999")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var analysis = await client.AnalysePrivateFileAsync("pf-1");

        Assert.Equal("analysis-999", analysis!.Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{PrivatePath}/private/files/pf-1/analyse", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetPrivateAnalysis_Retrieves_Analysis()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, AnalysisJson("analysis-123")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var analysis = await client.GetPrivateAnalysisAsync("analysis-123");

        Assert.Equal("analysis-123", analysis!.Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{PrivatePath}/private/analyses/analysis-123", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetPrivateBehaviours_Returns_Collection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                @"{ ""data"": [ { ""type"": ""behaviour"", ""id"": ""beh1"" } ] }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new PrivateScanningClient(vt);

        var behaviours = await client.GetPrivateFileBehavioursAsync("pf-1");

        Assert.Single(behaviours!.Items);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{PrivatePath}/private/files/pf-1/behaviours", request.RequestUri!.ToString());
    }

    private static VirusTotalOptions Options(string key = "test-key") => new() { ApiKey = key };
}

public class HuntingClientTests
{
    private const string Base = "https://www.virustotal.com/api/v3";

    private static string RulesetJson(string id = "ruleset-1") =>
        @"{ ""data"": { ""type"": ""hunting_ruleset"", ""id"": """ + id + @""", ""attributes"": { ""name"": ""my-rule"", ""rules"": ""rule demo { condition: true }"", ""enabled"": true, ""limit"": 100 } } }".Replace('\'', '"');

    [Fact]
    public async Task CreateRuleset_Posts_Json()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, RulesetJson("ruleset-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        var ruleset = await client.CreateRulesetAsync("my-rule", "rule demo { condition: true }");

        Assert.Equal("ruleset-1", ruleset!.Id);
        Assert.Equal("my-rule", ruleset.Attributes!.Name);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{Base}/intelligence/hunting_rulesets", request.RequestUri!.ToString());
        Assert.Contains("hunting_ruleset", handler.LastRequestBody!);
        Assert.Contains("my-rule", handler.LastRequestBody!);
    }

    [Fact]
    public async Task CreateRuleset_Validates_Inputs()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, RulesetJson()));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateRulesetAsync("", "rule"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateRulesetAsync("name", ""));
    }

    [Fact]
    public async Task ListRulesets_Includes_Query_Parameters()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ ""data"": [] }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        await client.ListRulesetsAsync(filter: "enabled:true", order: "modification_date-", cursor: "abc");

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/hunting_rulesets?filter=enabled%3Atrue&order=modification_date-&cursor=abc", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task UpdateRuleset_Sends_Patch_With_Snake_Case_Keys()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, RulesetJson("ruleset-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        await client.UpdateRulesetAsync("ruleset-1", enabled: false, notificationEmails: new() { "a@b.com" });

        var request = Assert.Single(handler.Requests);
        Assert.Equal(new HttpMethod("PATCH"), request.Method);
        Assert.Equal($"{Base}/intelligence/hunting_rulesets/ruleset-1", request.RequestUri!.ToString());
        Assert.Contains("notification_emails", handler.LastRequestBody!);
        Assert.Contains("a@b.com", handler.LastRequestBody!);
        Assert.DoesNotContain("name", handler.LastRequestBody!);
    }

    [Fact]
    public async Task UpdateRuleset_Throws_When_No_Fields()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, RulesetJson()));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.UpdateRulesetAsync("ruleset-1"));
    }

    [Fact]
    public async Task GetRuleset_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, RulesetJson("ruleset-7")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        var ruleset = await client.GetRulesetAsync("ruleset-7");

        Assert.Equal("ruleset-7", ruleset!.Id);
        Assert.True(ruleset.Attributes!.Enabled);
        Assert.Equal(100, ruleset.Attributes.Limit);

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/hunting_rulesets/ruleset-7", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task DeleteRuleset_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        await client.DeleteRulesetAsync("ruleset-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"{Base}/intelligence/hunting_rulesets/ruleset-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task ListNotifications_Includes_Limit_Parameter()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ ""data"": [] }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        await client.ListNotificationsAsync(limit: 50, order: "date-");

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/hunting_notifications?order=date-&limit=50", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetNotification_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                @"{ ""data"": { ""type"": ""hunting_notification"", ""id"": ""notif-9"", ""attributes"": { ""date"": 1700000000, ""rule_name"": ""my-rule"" } } }".Replace('\'', '"')));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new HuntingClient(vt);

        var notification = await client.GetNotificationAsync("notif-9");

        Assert.Equal("notif-9", notification!.Id);
        Assert.Equal("my-rule", notification.Attributes!.RuleName);

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/hunting_notifications/notif-9", request.RequestUri!.ToString());
    }

    private static VirusTotalOptions Options(string key = "test-key") => new() { ApiKey = key };
}

public class RetrohuntClientTests
{
    private const string Base = "https://www.virustotal.com/api/v3";

    private static string JobJson(string id = "retro-1") =>
        @"{ ""data"": { ""type"": ""retrohunt_job"", ""id"": """ + id + @""", ""attributes"": { ""status"": ""running"", ""rules"": ""rule x { condition: true }"", ""corpus"": ""main"" } } }".Replace('\'', '"');

    [Fact]
    public async Task CreateJob_Posts_Snake_Case_Body()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, JobJson("retro-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RetrohuntClient(vt);

        var job = await client.CreateJobAsync("rule x { condition: true }", "me@example.com", "main", 100, 200);

        Assert.Equal("retro-1", job!.Id);
        Assert.Equal("running", job.Attributes!.Status);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{Base}/intelligence/retrohunt_jobs", request.RequestUri!.ToString());
        Assert.Contains("notification_email", handler.LastRequestBody!);
        Assert.Contains("me@example.com", handler.LastRequestBody!);
        Assert.Contains("time_range", handler.LastRequestBody!);
    }

    [Fact]
    public async Task CreateJob_Validates_Rules()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, JobJson()));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RetrohuntClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateJobAsync(""));
    }

    [Fact]
    public async Task ListJobs_Returns_Collection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ ""data"": [ { ""type"": ""retrohunt_job"", ""id"": ""r1"" } ] }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RetrohuntClient(vt);

        await client.ListJobsAsync("cursor1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/retrohunt_jobs?cursor=cursor1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetJob_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, JobJson("retro-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RetrohuntClient(vt);

        var job = await client.GetJobAsync("retro-1");

        Assert.Equal("retro-1", job!.Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/retrohunt_jobs/retro-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AbortJob_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RetrohuntClient(vt);

        await client.AbortJobAsync("retro-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"{Base}/intelligence/retrohunt_jobs/retro-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task MatchingFiles_Returns_Collection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                @"{ ""data"": [ { ""type"": ""file"", ""id"": ""sha256hash123"" } ] }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new RetrohuntClient(vt);

        var files = await client.GetMatchingFilesAsync("retro-1");

        Assert.Single(files!.Items);
        Assert.Equal("sha256hash123", files.Items[0].Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/intelligence/retrohunt_jobs/retro-1/matching_files", request.RequestUri!.ToString());
    }

    private static VirusTotalOptions Options(string key = "test-key") => new() { ApiKey = key };
}

public class UsersClientTests
{
    private const string Base = "https://www.virustotal.com/api/v3";

    private static string UserJson(string id = "user-1") =>
        @"{ ""data"": { ""type"": ""user"", ""id"": """ + id + @""", ""attributes"": { ""email"": ""a@b.com"", ""name"": ""alice"", ""display_name"": ""Alice"" } } }".Replace('\'', '"');

    private static string GroupJson(string id = "group-1") =>
        @"{ ""data"": { ""type"": ""group"", ""id"": """ + id + @""", ""attributes"": { ""name"": ""SecTeam"" } } }".Replace('\'', '"');

    [Fact]
    public async Task GetUser_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, UserJson("user-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        var user = await client.GetUserAsync("user-1");

        Assert.Equal("user-1", user!.Id);
        Assert.Equal("alice", user.Attributes!.Name);

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/users/user-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task UpdateUser_Sends_Patch_With_Snake_Case()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, UserJson("user-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        await client.UpdateUserAsync("user-1", displayName: "New Name");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(new HttpMethod("PATCH"), request.Method);
        Assert.Equal($"{Base}/users/user-1", request.RequestUri!.ToString());
        Assert.Contains("display_name", handler.LastRequestBody!);
        Assert.Contains("New Name", handler.LastRequestBody!);
    }

    [Fact]
    public async Task UpdateUser_Throws_When_No_Fields()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, UserJson()));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        await Assert.ThrowsAsync<ArgumentException>(() => client.UpdateUserAsync("user-1"));
    }

    [Fact]
    public async Task DeleteUser_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        await client.DeleteUserAsync("user-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"{Base}/users/user-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task GetGroup_Retrieves_Object()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, GroupJson("group-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        var group = await client.GetGroupAsync("group-1");

        Assert.Equal("group-1", group!.Id);
        Assert.Equal("SecTeam", group.Attributes!.Name);

        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/groups/group-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task UpdateGroup_Sends_Patch()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, GroupJson("group-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        await client.UpdateGroupAsync("group-1", "Renamed");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(new HttpMethod("PATCH"), request.Method);
        Assert.Equal($"{Base}/groups/group-1", request.RequestUri!.ToString());
        Assert.Contains("Renamed", handler.LastRequestBody!);
    }

    [Fact]
    public async Task DeleteGroup_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        await client.DeleteGroupAsync("group-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"{Base}/groups/group-1", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task ListGroupUsers_Returns_Collection()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK,
                @"{ ""data"": [ { ""type"": ""user"", ""id"": ""user-1"" } ] }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        var users = await client.ListGroupUsersAsync("group-1");

        Assert.Single(users!.Items);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"{Base}/groups/group-1/users", request.RequestUri!.ToString());
    }

    [Fact]
    public async Task AddUserToGroup_Posts_Membership()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, UserJson("user-1")));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        var user = await client.AddUserToGroupAsync("group-1", "user-1", "admin");

        Assert.Equal("user-1", user!.Id);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"{Base}/groups/group-1/users", request.RequestUri!.ToString());
        Assert.Contains("admin", handler.LastRequestBody!);
    }

    [Fact]
    public async Task RemoveUserFromGroup_Sends_Delete()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(HttpStatusCode.OK, @"{ }"));
        using var vt = new VtClient(Options(), new HttpClient(handler));
        var client = new UsersClient(vt);

        await client.RemoveUserFromGroupAsync("group-1", "user-1");

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Delete, request.Method);
        Assert.Equal($"{Base}/groups/group-1/users/user-1", request.RequestUri!.ToString());
    }

    private static VirusTotalOptions Options(string key = "test-key") => new() { ApiKey = key };
}