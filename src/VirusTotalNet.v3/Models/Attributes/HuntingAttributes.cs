namespace VirusTotalNet.v3.Models.Attributes;

public sealed class HuntingRulesetAttributes
{
    public int? CreationDate { get; set; }
    public bool Enabled { get; set; }
    public int Limit { get; set; }
    public int? ModificationDate { get; set; }
    public string? Name { get; set; }
    public List<string>? NotificationEmails { get; set; }
    public string? Rules { get; set; }
    public bool? Notifications { get; set; }
    public bool? ExcludeNewsletter { get; set; }
    public bool? OnlyInTheLast { get; set; }
    public string? MatchObjectType { get; set; }
}

public sealed class HuntingNotificationAttributes
{
    public int? Date { get; set; }
    public bool? MatchInSubfile { get; set; }
    public string? RuleName { get; set; }
    public List<string>? RuleTags { get; set; }
    public string? Snippet { get; set; }
    public string? SourceCountry { get; set; }
    public string? SourceKey { get; set; }
    public List<string>? Tags { get; set; }
}
