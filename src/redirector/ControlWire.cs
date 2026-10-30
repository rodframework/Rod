using System.Text.Json.Serialization;

namespace Rod.Redirector;

/// <summary>
/// The control channel's wire grammar as this side speaks it (architecture.md
/// Sec 8): a small JSON-over-WebSocket protocol owned by the teamserver's
/// transport layer. The shapes are mirrored here rather than shared -- the
/// redirector references nothing in-house by design, so the JSON is the
/// contract, the same way the wire protobuf is for implants.
///
/// Serialization is source-generated (<see cref="ControlJson"/>) because the
/// binary publishes Native AOT, where reflection serialization is not an
/// option.
/// </summary>
internal sealed record ControlMessage(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("credential")] string? Credential = null,
    [property: JsonPropertyName("nodeId")] string? NodeId = null,
    [property: JsonPropertyName("nodeSecret")] string? NodeSecret = null,
    [property: JsonPropertyName("version")] string? Version = null,
    [property: JsonPropertyName("commit")] string? Commit = null,
    [property: JsonPropertyName("digest")] string? Digest = null,
    [property: JsonPropertyName("rules")] RuleSetWire? Rules = null,
    [property: JsonPropertyName("reason")] string? Reason = null);

/// <summary>
/// A full rule set with its digest. The digest is the reconcile key: a set
/// whose digest matches the one already applied is a no-op.
/// </summary>
internal sealed record RuleSetWire(
    [property: JsonPropertyName("digest")] string? Digest,
    [property: JsonPropertyName("rules")] List<ForwardingRuleWire>? Rules);

/// <summary>
/// One forwarding rule: bind listen host:port, splice to upstream host:port.
/// The transport names the carriage -- "tcp" today -- and the allow list is
/// the optional source CIDR filter the rule carries.
/// </summary>
internal sealed record ForwardingRuleWire(
    [property: JsonPropertyName("ruleId")] string RuleId,
    [property: JsonPropertyName("transport")] string Transport,
    [property: JsonPropertyName("listenHost")] string ListenHost,
    [property: JsonPropertyName("listenPort")] int ListenPort,
    [property: JsonPropertyName("upstreamHost")] string UpstreamHost,
    [property: JsonPropertyName("upstreamPort")] int UpstreamPort,
    [property: JsonPropertyName("allowList")] string? AllowList);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ControlMessage))]
[JsonSerializable(typeof(NodeState))]
internal sealed partial class ControlJson : JsonSerializerContext;
