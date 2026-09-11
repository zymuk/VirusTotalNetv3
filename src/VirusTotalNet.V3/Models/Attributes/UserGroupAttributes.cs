namespace VirusTotalNet.V3.Models.Attributes;

public sealed class UserAttributes
{
    public string? Email { get; set; }
    public string? Name { get; set; }
    public string? Privileges { get; set; }
    public bool? AgreedToTos { get; set; }
    public int? ApiKeyCount { get; set; }
    public bool? ControlledAtos { get; set; }
    public string? DisplayName { get; set; }
    public UserGroupsRelationship? Groups { get; set; }
}

public sealed class UserGroupsRelationship
{
    public List<UserGroupRef>? Data { get; set; }
}

public sealed class UserGroupRef
{
    public string? Type { get; set; }
    public string? Id { get; set; }
}

public sealed class GroupAttributes
{
    public string? Name { get; set; }
    public int? Privileges { get; set; }
    public List<string>? Parent { get; set; }
    public GroupQuotas? Quotas { get; set; }
}

public sealed class GroupQuotas
{
    public int? IntelligenceSearch { get; set; }
    public int? IntelligenceSearchSelectors { get; set; }
    public int? IntelligenceRetrorunHunt { get; set; }
    public int? IntelligenceLivehuntNotifications { get; set; }
    public int? FileFeed { get; set; }
    public int? UrlFeed { get; set; }
    public int? DomainFeed { get; set; }
    public int? IpFeed { get; set; }
    public int? PrivateScanning { get; set; }
}
