using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Rod.CoreState;

namespace Rod.Persistence.Configurations;

/// <summary>
/// The strongly typed id value converters (ADR 0003). The core-state ids are
/// <c>readonly record struct</c> wrappers around a <see cref="Guid"/>; the
/// database column is a Postgres <c>uuid</c>. A converter for each id maps the
/// typed struct to and from its underlying Guid, so the domain keeps its
/// type-safe ids while the store holds a plain uuid.
/// </summary>
/// <remarks>
/// A registered <see cref="ValueConverter"/> is applied by the entity
/// configurations via <c>HasConversion</c>. Conversions are pure and symmetric,
/// so the default struct comparers EF Core derives are sufficient -- no custom
/// <c>ValueComparer</c> is required.
/// </remarks>
internal static class IdConverters
{
    public static ValueConverter<OperatorId, Guid> OperatorId { get; } =
        new(id => id.Value, value => new OperatorId(value));

    public static ValueConverter<EngagementId, Guid> EngagementId { get; } =
        new(id => id.Value, value => new EngagementId(value));

    public static ValueConverter<DeployTokenId, Guid> DeployTokenId { get; } =
        new(id => id.Value, value => new DeployTokenId(value));

    public static ValueConverter<LauncherId, Guid> LauncherId { get; } =
        new(id => id.Value, value => new LauncherId(value));

    public static ValueConverter<ImplantId, Guid> ImplantId { get; } =
        new(id => id.Value, value => new ImplantId(value));

    public static ValueConverter<TaskId, Guid> TaskId { get; } =
        new(id => id.Value, value => new TaskId(value));

    public static ValueConverter<SessionId, Guid> SessionId { get; } =
        new(id => id.Value, value => new SessionId(value));

    public static ValueConverter<ShellSessionId, Guid> ShellSessionId { get; } =
        new(id => id.Value, value => new ShellSessionId(value));

    public static ValueConverter<Rod.CoreState.CampaignId, Guid> CampaignId { get; } =
        new(id => id.Value, value => new Rod.CoreState.CampaignId(value));

    public static ValueConverter<Rod.CoreState.CampaignRecipientId, Guid> CampaignRecipientId { get; } =
        new(id => id.Value, value => new Rod.CoreState.CampaignRecipientId(value));

    public static ValueConverter<Rod.CoreState.Operators.OperatorApiTokenId, Guid> OperatorApiTokenId { get; } =
        new(id => id.Value, value => new Rod.CoreState.Operators.OperatorApiTokenId(value));

    public static ValueConverter<Rod.CoreState.CommentId, Guid> CommentId { get; } =
        new(id => id.Value, value => new Rod.CoreState.CommentId(value));

    public static ValueConverter<Rod.CoreState.ChatChannelId, Guid> ChatChannelId { get; } =
        new(id => id.Value, value => new Rod.CoreState.ChatChannelId(value));

    public static ValueConverter<Rod.CoreState.CredentialId, Guid> CredentialId { get; } =
        new(id => id.Value, value => new Rod.CoreState.CredentialId(value));

    public static ValueConverter<Rod.CoreState.ReconAssetId, Guid> ReconAssetId { get; } =
        new(id => id.Value, value => new Rod.CoreState.ReconAssetId(value));
}
