using System.Text.Json;
using System.Text.Json.Serialization;
using Rod.Audit;

namespace Rod.Persistence;

/// <summary>
/// The storage shape for <see cref="PayloadRecord"/>: the built artifact's
/// bytes as a <c>bytea</c> column with its metadata beside them, so the
/// payload library survives a teamserver restart. The bake-time
/// <see cref="PayloadRecord.Build"/> snapshot serializes to a JSON column --
/// it is a display document (every field nullable, growing by form
/// redesigns), not a relational shape worth normalizing. The record itself
/// stays the port's contract; this wrapper is the durable twin, the same
/// Stored* pattern the other engagement-scoped stores keep.
/// </summary>
internal sealed class StoredPayload
{
    public Guid PayloadId { get; set; }
    public Guid EngagementId { get; set; }
    public string Class { get; set; } = "";
    public string UnitId { get; set; } = "";
    public string ContentType { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public byte[] Content { get; set; } = [];
    public long Size { get; set; }
    public DateTimeOffset BuiltAt { get; set; }
    public string? Target { get; set; }
    public string? Endpoint { get; set; }
    public Guid? TokenId { get; set; }
    public Guid? EnvelopeKeyId { get; set; }
    public byte[]? EnvelopeKey { get; set; }
    public string? BuildJson { get; set; }
    public byte[]? WireGuardPublicKey { get; set; }
    public Guid? DeliversPayloadId { get; set; }

    public PayloadRecord ToRecord()
        => new(
            PayloadId,
            EngagementId,
            Class,
            UnitId,
            ContentType,
            Fingerprint,
            Content,
            Size,
            BuiltAt,
            Target,
            Endpoint,
            TokenId,
            EnvelopeKeyId,
            EnvelopeKey,
            BuildJson is null
                ? null
                : JsonSerializer.Deserialize(BuildJson, PayloadJsonContext.Default.PayloadBuildProfile),
            WireGuardPublicKey,
            DeliversPayloadId);

    public static StoredPayload From(PayloadRecord payload)
        => new()
        {
            PayloadId = payload.PayloadId,
            EngagementId = payload.EngagementId,
            Class = payload.Class,
            UnitId = payload.UnitId,
            ContentType = payload.ContentType,
            Fingerprint = payload.Fingerprint,
            Content = payload.Content,
            Size = payload.Size,
            BuiltAt = payload.BuiltAt,
            Target = payload.Target,
            Endpoint = payload.Endpoint,
            TokenId = payload.TokenId,
            EnvelopeKeyId = payload.EnvelopeKeyId,
            EnvelopeKey = payload.EnvelopeKey,
            BuildJson = payload.Build is null
                ? null
                : JsonSerializer.Serialize(payload.Build, PayloadJsonContext.Default.PayloadBuildProfile),
            WireGuardPublicKey = payload.WireGuardPublicKey,
            DeliversPayloadId = payload.DeliversPayloadId,
        };
}

/// <summary>
/// Source-generated serialization for the bake snapshot column: the same
/// reflection-free shape the audit layer's own context keeps, scoped to the
/// one type this column stores.
/// </summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(PayloadBuildProfile))]
internal sealed partial class PayloadJsonContext : JsonSerializerContext;
