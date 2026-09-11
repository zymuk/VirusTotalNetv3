using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalNet.v3.Models.Attributes;

/// <summary>
/// Attributes of a <c>behaviour</c> object (see <see cref="BehaviourObject"/>), produced by
/// sandbox analyses when a file is executed. Fields vary per sandbox; unknown ones are
/// preserved losslessly in <see cref="VtObject{TA}.Raw"/>.
/// </summary>
public sealed class BehaviourAttributes
{
    /// <summary>Name of the sandbox that produced this behaviour report.</summary>
    [JsonPropertyName("sandbox_name")]
    public string? SandboxName { get; set; }

    /// <summary>The sandbox verdict (e.g. <c>malicious</c>, <c>harmless</c>).</summary>
    [JsonPropertyName("sandbox_verdict")]
    public string? SandboxVerdict { get; set; }

    /// <summary>SHA-256 of the sample executed in this behaviour report.</summary>
    [JsonPropertyName("sample_sha256")]
    public string? SampleSha256 { get; set; }

    /// <summary>Timestamp the behaviour was observed (Unix seconds).</summary>
    [JsonPropertyName("analysis_date")]
    public DateTimeOffset? AnalysisDate { get; set; }

    /// <summary>Used to find similar behaviour analyses.</summary>
    [JsonPropertyName("behash")]
    public string? Behash { get; set; }

    /// <summary>API calls/Syscalls worth highlighting.</summary>
    [JsonPropertyName("calls_highlighted")]
    public IList<string>? CallsHighlighted { get; set; }

    /// <summary>Shell command executions observed during the analysis.</summary>
    [JsonPropertyName("command_executions")]
    public IList<string>? CommandExecutions { get; set; }

    /// <summary>Files opened during execution.</summary>
    [JsonPropertyName("files_opened")]
    public IList<string>? FilesOpened { get; set; }

    /// <summary>Files written to during execution.</summary>
    [JsonPropertyName("files_written")]
    public IList<string>? FilesWritten { get; set; }

    /// <summary>Names of the files deleted.</summary>
    [JsonPropertyName("files_deleted")]
    public IList<string>? FilesDeleted { get; set; }

    /// <summary>Full path of files subject to some sort of active attribute modification.</summary>
    [JsonPropertyName("files_attribute_changed")]
    public IList<string>? FilesAttributeChanged { get; set; }

    /// <summary>Whether there is an HTML report for this behaviour analysis.</summary>
    [JsonPropertyName("has_html_report")]
    public bool? HasHtmlReport { get; set; }

    /// <summary>Whether there is a EVTX file for this behaviour analysis.</summary>
    [JsonPropertyName("has_evtx")]
    public bool? HasEvtx { get; set; }

    /// <summary>Whether there is a memdump file for this behaviour analysis.</summary>
    [JsonPropertyName("has_memdump")]
    public bool? HasMemdump { get; set; }

    /// <summary>Whether there is a PCAP network capture for this behaviour analysis.</summary>
    [JsonPropertyName("has_pcap")]
    public bool? HasPcap { get; set; }

    /// <summary>The hosts file field stores the content of the local hostname-ip mapping hosts file IF AND ONLY IF the file was modified.</summary>
    [JsonPropertyName("hosts_file")]
    public string? HostsFile { get; set; }

    /// <summary>List of IDS alerts, sorted by timestamp.</summary>
    [JsonPropertyName("ids_alerts")]
    public IList<IdsAlert>? IdsAlerts { get; set; }

    /// <summary>Name of the processes that were terminated during the execution.</summary>
    [JsonPropertyName("processes_terminated")]
    public IList<string>? ProcessesTerminated { get; set; }

    /// <summary>Name of the processes that were killed during the execution.</summary>
    [JsonPropertyName("processes_killed")]
    public IList<string>? ProcessesKilled { get; set; }

    /// <summary>Name of the processes that were subjected to code injection.</summary>
    [JsonPropertyName("processes_injected")]
    public IList<string>? ProcessesInjected { get; set; }

    /// <summary>Names of the services for which a handle was acquired.</summary>
    [JsonPropertyName("services_opened")]
    public IList<string>? ServicesOpened { get; set; }

    /// <summary>New services created.</summary>
    [JsonPropertyName("services_created")]
    public IList<string>? ServicesCreated { get; set; }

    /// <summary>New services started.</summary>
    [JsonPropertyName("services_started")]
    public IList<string>? ServicesStarted { get; set; }

    /// <summary>Services stopped during the execution.</summary>
    [JsonPropertyName("services_stopped")]
    public IList<string>? ServicesStopped { get; set; }

    /// <summary>Services deleted during the execution.</summary>
    [JsonPropertyName("services_deleted")]
    public IList<string>? ServicesDeleted { get; set; }

    /// <summary>Service binding, mainly in Android.</summary>
    [JsonPropertyName("services_bound")]
    public IList<string>? ServicesBound { get; set; }

    /// <summary>Names of windows that are searched for.</summary>
    [JsonPropertyName("windows_searched")]
    public IList<string>? WindowsSearched { get; set; }

    /// <summary>Names of windows that are set up to be invisible.</summary>
    [JsonPropertyName("windows_hidden")]
    public IList<string>? WindowsHidden { get; set; }

    /// <summary>Name of the mutexes for which the file acquires a handle.</summary>
    [JsonPropertyName("mutexes_opened")]
    public IList<string>? MutexesOpened { get; set; }

    /// <summary>New mutexes created.</summary>
    [JsonPropertyName("mutexes_created")]
    public IList<string>? MutexesCreated { get; set; }

    /// <summary>OS Signals and broadcast events observed.</summary>
    [JsonPropertyName("signals_observed")]
    public IList<string>? SignalsObserved { get; set; }

    /// <summary>Method/functionality called via reflection or runtime instantiation.</summary>
    [JsonPropertyName("invokes")]
    public IList<string>? Invokes { get; set; }

    /// <summary>Crypto algorithms observed during execution.</summary>
    [JsonPropertyName("crypto_algorithms_observed")]
    public IList<string>? CryptoAlgorithmsObserved { get; set; }

    /// <summary>Crypto keys observed during execution.</summary>
    [JsonPropertyName("crypto_keys")]
    public IList<string>? CryptoKeys { get; set; }

    /// <summary>Plaintext strings that are either ciphered or deciphered.</summary>
    [JsonPropertyName("crypto_plain_text")]
    public IList<string>? CryptoPlainText { get; set; }

    /// <summary>Plaintext which is the result of a decoding operation.</summary>
    [JsonPropertyName("text_decoded")]
    public IList<string>? TextDecoded { get; set; }

    /// <summary>Interesting text seen in window dialogs, titles, etc.</summary>
    [JsonPropertyName("text_highlighted")]
    public IList<string>? TextHighlighted { get; set; }

    /// <summary>Verdict confidence percentage (0-100).</summary>
    [JsonPropertyName("verdict_confidence")]
    public int? VerdictConfidence { get; set; }

    /// <summary>JA3 fingerprinting of TLS client connections.</summary>
    [JsonPropertyName("ja3_digests")]
    public IList<string>? Ja3Digests { get; set; }

    /// <summary>Contacted domains/IPs certificates.</summary>
    [JsonPropertyName("tls")]
    public IList<TlsInfo>? Tls { get; set; }

    /// <summary>Aggregated sigma analysis results from all sandbox generated EVTX files.</summary>
    [JsonPropertyName("sigma_analysis_results")]
    public IList<SigmaAnalysisResult>? SigmaAnalysisResults { get; set; }

    /// <summary>Aggregated list of matching signatures.</summary>
    [JsonPropertyName("signature_matches")]
    public IList<SignatureMatch>? SignatureMatches { get; set; }

    /// <summary>Aggregated list of mitre attack techniques.</summary>
    [JsonPropertyName("mitre_attack_techniques")]
    public IList<MitreAttackTechnique>? MitreAttackTechniques { get; set; }

    /// <summary>Android specific: activities launched by the app under study.</summary>
    [JsonPropertyName("activities_started")]
    public IList<string>? ActivitiesStarted { get; set; }

    /// <summary>Android specific: content for which an Android app registers logic to be informed about changes.</summary>
    [JsonPropertyName("content_model_observers")]
    public IList<string>? ContentModelObservers { get; set; }

    /// <summary>Android specific: content model entries performed by an Android app.</summary>
    [JsonPropertyName("content_model_sets")]
    public IList<ContentModelSet>? ContentModelSets { get; set; }

    /// <summary>Android specific: Android SQLite DBs deleted.</summary>
    [JsonPropertyName("databases_deleted")]
    public IList<string>? DatabasesDeleted { get; set; }

    /// <summary>Android specific: interactions with databases (e.g. when an Android app opens an SQLite DB).</summary>
    [JsonPropertyName("databases_opened")]
    public IList<string>? DatabasesOpened { get; set; }

    /// <summary>Android specific: Android permissions requested during runtime.</summary>
    [JsonPropertyName("permissions_requested")]
    public IList<string>? PermissionsRequested { get; set; }

    /// <summary>Android specific: entries in Android's shared preferences that are checked.</summary>
    [JsonPropertyName("shared_preferences_lookups")]
    public IList<string>? SharedPreferencesLookups { get; set; }

    /// <summary>Android specific: entries written in Android's shared preferences.</summary>
    [JsonPropertyName("shared_preferences_sets")]
    public IList<SharedPreferenceSet>? SharedPreferencesSets { get; set; }

    /// <summary>Android specific: registering a receiver in Android is considered as a broadcast hook.</summary>
    [JsonPropertyName("signals_hooked")]
    public IList<string>? SignalsHooked { get; set; }

    /// <summary>Android specific: interactions with Android's system properties dataset.</summary>
    [JsonPropertyName("system_property_lookups")]
    public IList<string>? SystemPropertyLookups { get; set; }

    /// <summary>Android specific: keys and values set in Android's system properties dataset.</summary>
    [JsonPropertyName("system_property_sets")]
    public IList<SystemPropertySet>? SystemPropertySets { get; set; }

    /// <summary>Windows specific: operations related to dynamic loading of libraries, shared objects and components.</summary>
    [JsonPropertyName("modules_loaded")]
    public IList<string>? ModulesLoaded { get; set; }

    /// <summary>Windows specific: Windows registry keys for which a handle is acquired.</summary>
    [JsonPropertyName("registry_keys_opened")]
    public IList<string>? RegistryKeysOpened { get; set; }

    /// <summary>Windows specific: keys and values of registry keys that are set.</summary>
    [JsonPropertyName("registry_keys_set")]
    public IList<RegistryKeyValue>? RegistryKeysSet { get; set; }

    /// <summary>Windows specific: names of Windows registry keys that are deleted.</summary>
    [JsonPropertyName("registry_keys_deleted")]
    public IList<string>? RegistryKeysDeleted { get; set; }

    /// <summary>Any attribute fields not mapped by properties above, preserved losslessly.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>
/// Represents an IDS alert from a behaviour analysis.
/// </summary>
public sealed class IdsAlert
{
    /// <summary>Alert context containing network information.</summary>
    [JsonPropertyName("alert_context")]
    public AlertContext? AlertContext { get; set; }

    /// <summary>Alert severity (high, medium, low, info).</summary>
    [JsonPropertyName("alert_severity")]
    public string? AlertSeverity { get; set; }
}

/// <summary>
/// Context of an IDS alert.
/// </summary>
public sealed class AlertContext
{
    /// <summary>Destination IP.</summary>
    [JsonPropertyName("dest_ip")]
    public string? DestIp { get; set; }

    /// <summary>Destination port.</summary>
    [JsonPropertyName("dest_port")]
    public int? DestPort { get; set; }

    /// <summary>Hostname if the alert is related to HTTP communication.</summary>
    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    /// <summary>Communication protocol name.</summary>
    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    /// <summary>Source IP.</summary>
    [JsonPropertyName("src_ip")]
    public string? SrcIp { get; set; }

    /// <summary>Source port.</summary>
    [JsonPropertyName("src_port")]
    public int? SrcPort { get; set; }

    /// <summary>URL if the alert is related to HTTP communication.</summary>
    [JsonPropertyName("url")]
    public string? Url { get; set; }
}

/// <summary>
/// TLS certificate information.
/// </summary>
public sealed class TlsInfo
{
    /// <summary>Certificate issuer information.</summary>
    [JsonPropertyName("issuer")]
    public Dictionary<string, string>? Issuer { get; set; }

    /// <summary>JA3 fingerprint of the TLS client.</summary>
    [JsonPropertyName("ja3")]
    public string? Ja3 { get; set; }

    /// <summary>JA3s fingerprint of the TLS server.</summary>
    [JsonPropertyName("ja3s")]
    public string? Ja3s { get; set; }

    /// <summary>Certificate serial number.</summary>
    [JsonPropertyName("serial_number")]
    public string? SerialNumber { get; set; }

    /// <summary>Server Name Indication (SNI).</summary>
    [JsonPropertyName("sni")]
    public string? Sni { get; set; }

    /// <summary>Certificate subject information.</summary>
    /// <summary>Certificate thumbprint.</summary>
    [JsonPropertyName("thumbprint")]
    public string? Thumbprint { get; set; }

    /// <summary>TLS version.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; set; }
}

/// <summary>
/// Sigma analysis result.
/// </summary>
public sealed class SigmaAnalysisResult
{
    /// <summary>Matched sigma rule title.</summary>
    [JsonPropertyName("rule_title")]
    public string? RuleTitle { get; set; }

    /// <summary>Sigma ruleset where this rule belongs to.</summary>
    [JsonPropertyName("rule_source")]
    public string? RuleSource { get; set; }

    /// <summary>Specific matched events.</summary>
    [JsonPropertyName("match_context")]
    public Dictionary<string, string>? MatchContext { get; set; }

    /// <summary>Rule level (critical, high, medium, low).</summary>
    [JsonPropertyName("rule_level")]
    public string? RuleLevel { get; set; }

    /// <summary>Rule description.</summary>
    [JsonPropertyName("rule_description")]
    public string? RuleDescription { get; set; }

    /// <summary>Rule author.</summary>
    [JsonPropertyName("rule_author")]
    public string? RuleAuthor { get; set; }

    /// <summary>Rule ID in VirusTotal.</summary>
    [JsonPropertyName("rule_id")]
    public string? RuleId { get; set; }
}

/// <summary>
/// Signature match.
/// </summary>
public sealed class SignatureMatch
{
    /// <summary>Format of the signature (YARA, SIGMA, CAPA, etc.).</summary>
    [JsonPropertyName("format")]
    public string? Format { get; set; }

    /// <summary>List of authors.</summary>
    [JsonPropertyName("authors")]
    public Dictionary<string, string>? Authors { get; set; }

    /// <summary>Rule source.</summary>
    [JsonPropertyName("rule_src")]
    public string? RuleSrc { get; set; }

    /// <summary>Rule name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Rule description.</summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

/// <summary>
/// MITRE ATT&amp;CK technique.
/// </summary>
public sealed class MitreAttackTechnique
{
    /// <summary>Description of the technique.</summary>
    [JsonPropertyName("signature_description")]
    public string? SignatureDescription { get; set; }

    /// <summary>Technique identifier (e.g., T1059).</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>Severity of the technique.</summary>
    [JsonPropertyName("severity")]
    public string? Severity { get; set; }
}

/// <summary>
/// Content model set (Android specific).
/// </summary>
public sealed class ContentModelSet
{
    /// <summary>Not specified in API docs, keeping as generic object.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>
/// Shared preference set (Android specific).
/// </summary>
public sealed class SharedPreferenceSet
{
    /// <summary>Preference name.</summary>
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    /// <summary>Preference value.</summary>
    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

/// <summary>
/// System property set (Android specific).
/// </summary>
public sealed class SystemPropertySet
{
    /// <summary>Not specified in API docs, keeping as generic object.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Raw { get; set; } = new();
}

/// <summary>
/// Registry key value (Windows specific).
/// </summary>
public sealed class RegistryKeyValue
{
    /// <summary>Registry key that was modified.</summary>
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    /// <summary>Value set to the registry key.</summary>
    [JsonPropertyName("value")]
    public string? Value { get; set; }
}