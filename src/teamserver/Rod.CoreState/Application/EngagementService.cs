using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.CoreState.Deployment;

namespace Rod.CoreState.Application;

/// <summary>
/// The first engagement use cases: create an engagement, and mint
/// a deploy token for it. Orchestrates the core-state ports; holds no state of
/// its own. The owner is the authenticated operator the transport layer resolved
/// off the session principal  (operator auth); the
/// service trusts that caller to have already proven its identity.
/// </summary>
public sealed class EngagementService
{
    private readonly IOperatorRepository _operators;
    private readonly IEngagementRepository _engagements;
    private readonly IDeployTokenService _deployTokens;
    private readonly TimeProvider _clock;

    public EngagementService(
        IOperatorRepository operators,
        IEngagementRepository engagements,
        IDeployTokenService deployTokens,
        TimeProvider clock)
    {
        _operators = operators;
        _engagements = engagements;
        _deployTokens = deployTokens;
        _clock = clock;
    }

    /// <summary>
    /// Creates an engagement owned by the authenticated operator. The owner is
    /// recorded as the engagement's single Owner member; its handle is resolved
    /// from the operator record so the response carries it without the caller
    /// having to supply it.
    /// </summary>
    public async Task<EngagementCreated> CreateEngagementAsync(
        CreateEngagementCommand command,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();

        // The owner is the authenticated operator; auth guarantees the account
        // exists, so this is a resolve-for-handle, not a get-or-create.
        var owner = await _operators.GetOrThrowAsync(command.OwnerId, cancellationToken);

        var engagement = Engagement.Create(
            EngagementId.New(), command.Name, owner.Id, now, command.Description, command.Range);
        await _engagements.SaveAsync(engagement, cancellationToken);

        return new EngagementCreated(
            engagement.Id,
            engagement.Name,
            engagement.Description,
            owner.Id,
            owner.Handle,
            engagement.CreatedAt,
            engagement.Range);
    }

    /// <summary>
    /// Mints a deploy token for an engagement, issued by the acting operator
    /// (the owner or a writer member -- the deploy service enforces the
    /// standing). The secret is returned once; only the caller sees it. A
    /// closed engagement (frozen for close-out or retired) mints nothing --
    /// it accepts no new deployments. The command's optional scope (max
    /// uses, lifetime) sizes the token for a deployment batch; absent values
    /// keep the single-use, one-hour default.
    /// </summary>
    public async Task<DeployTokenMinted> MintDeployTokenAsync(
        MintDeployTokenCommand command,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();

        var engagement = await _engagements.GetOrThrowAsync(command.EngagementId, cancellationToken);
        if (engagement.IsClosed)
        {
            throw new EngagementClosedException(
                $"Engagement {engagement.Id} is closed for close-out" +
                (engagement.IsRetired ? " (retired)" : " (frozen)") +
                "; it mints no deployment tokens.");
        }

        var token = await _deployTokens.MintAsync(
            engagement.Id, command.IssuedBy, now, command.MaxUses, command.Lifetime,
            cancellationToken: cancellationToken);

        return new DeployTokenMinted(
            token.Id,
            token.EngagementId,
            token.Secret,
            token.IssuedBy,
            token.IssuedAt,
            token.ExpiresAt,
            token.MaxUses);
    }

    /// <summary>
    /// Edits an engagement's working record: its name and free-text
    /// description. The description is the crew's own running notes, so it
    /// stays editable while the engagement operates (and while it is frozen --
    /// the freeze locks tasking, not notes); a retired engagement is sealed.
    /// The caller records the change in the audit trail.
    /// </summary>
    public async Task<EngagementEdited> EditEngagementAsync(
        EditEngagementCommand command,
        CancellationToken cancellationToken = default)
    {
        var engagement = await _engagements.GetOrThrowAsync(command.EngagementId, cancellationToken);
        engagement.Edit(command.Name, command.Description);
        await _engagements.SaveAsync(engagement, cancellationToken);

        var owner = await _operators.FindAsync(engagement.OwnerId, cancellationToken);
        return new EngagementEdited(engagement, owner?.Handle ?? engagement.OwnerId.ToString());
    }

    /// <summary>
    /// Applies the engagement's rules-of-engagement profile (architecture.md
    /// Sec 9 -- ROE guardrails). The profile is the server-side scope of what
    /// the engagement's operators may task; task issuance refuses anything
    /// outside it before queuing. Applying an empty profile reopens the
    /// engagement (the unrestricted scope). The change is effective
    /// immediately for later issuances; the caller records it in the audit
    /// trail.
    /// </summary>
    public async Task<RoeApplied> ApplyRoeAsync(
        ApplyRoeCommand command,
        CancellationToken cancellationToken = default)
    {
        var engagement = await _engagements.GetOrThrowAsync(command.EngagementId, cancellationToken);
        engagement.ApplyRoe(command.Profile);
        await _engagements.SaveAsync(engagement, cancellationToken);

        return new RoeApplied(engagement.Id, engagement.Roe);
    }

    /// <summary>
    /// Freezes the engagement for close-out (architecture.md Sec 2 step 10):
    /// the first half of the close-out path. From here the engagement accepts
    /// no new tasking and no new deployments, so its trail can be exported as
    /// final evidence; the caller records the freeze in the audit trail.
    /// </summary>
    public async Task<EngagementFrozen> FreezeAsync(
        FreezeEngagementCommand command,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();

        var engagement = await _engagements.GetOrThrowAsync(command.EngagementId, cancellationToken);
        engagement.Freeze(now);
        await _engagements.SaveAsync(engagement, cancellationToken);

        return new EngagementFrozen(engagement.Id, engagement.FrozenAt!.Value);
    }

    /// <summary>
    /// Reverses a freeze: the engagement resumes accepting tasking and
    /// deployments. The recovery for a mistaken freeze, refused once the
    /// close-out completes (retirement is terminal). The caller records the
    /// unfreeze in the audit trail.
    /// </summary>
    public async Task<EngagementUnfrozen> UnfreezeAsync(
        UnfreezeEngagementCommand command,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();

        var engagement = await _engagements.GetOrThrowAsync(command.EngagementId, cancellationToken);
        engagement.Unfreeze();
        await _engagements.SaveAsync(engagement, cancellationToken);

        return new EngagementUnfrozen(engagement.Id, now);
    }

    /// <summary>
    /// Retires the engagement, completing the close-out (architecture.md Sec 2
    /// step 10): terminal, and only reachable from the frozen state -- the
    /// aggregate rejects retiring an open engagement so the evidence export
    /// cannot be skipped. The caller records the retirement in the audit trail.
    /// </summary>
    public async Task<EngagementRetired> RetireAsync(
        RetireEngagementCommand command,
        CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow();

        var engagement = await _engagements.GetOrThrowAsync(command.EngagementId, cancellationToken);
        engagement.Retire(now);
        await _engagements.SaveAsync(engagement, cancellationToken);

        return new EngagementRetired(engagement.Id, engagement.RetiredAt!.Value);
    }
}

/// <summary>
/// Request to create an engagement. The owner is the authenticated operator;
/// only the name is supplied by the caller.
/// </summary>
public sealed record CreateEngagementCommand(
    OperatorId OwnerId,
    string Name,
    string? Description = null,
    bool Range = false);

/// <summary>Result of creating an engagement.</summary>
public sealed record EngagementCreated(
    EngagementId EngagementId,
    string Name,
    string? Description,
    OperatorId OwnerId,
    string OwnerHandle,
    DateTimeOffset CreatedAt,
    bool Range = false);

/// <summary>
/// Request to mint a deploy token for an engagement's owner. The optional scope
/// sizes the token for a deployment batch: <see cref="MaxUses"/> implants may
/// each spend one use inside <see cref="Lifetime"/>.
/// </summary>
public sealed record MintDeployTokenCommand(
    EngagementId EngagementId,
    OperatorId IssuedBy,
    int? MaxUses = null,
    TimeSpan? Lifetime = null);

/// <summary>
/// Request to edit an engagement's working record: the name and free-text
/// description. Both are required in the command shape; an omitted description
/// clears it (the endpoint distinguishes omitted from present on the wire).
/// </summary>
public sealed record EditEngagementCommand(
    EngagementId EngagementId,
    string Name,
    string? Description);

/// <summary>Result of editing an engagement's record: the saved aggregate and its owner's handle.</summary>
public sealed record EngagementEdited(
    Engagement Engagement,
    string OwnerHandle);

/// <summary>Request to apply an engagement's rules-of-engagement profile.</summary>
public sealed record ApplyRoeCommand(EngagementId EngagementId, RoeProfile Profile);

/// <summary>Request to freeze an engagement for close-out.</summary>
public sealed record FreezeEngagementCommand(EngagementId EngagementId);

/// <summary>Request to reverse a mistaken freeze and reopen the engagement.</summary>
public sealed record UnfreezeEngagementCommand(EngagementId EngagementId);

/// <summary>Request to retire an engagement, completing its close-out.</summary>
public sealed record RetireEngagementCommand(EngagementId EngagementId);

/// <summary>Result of freezing an engagement for close-out.</summary>
public sealed record EngagementFrozen(EngagementId EngagementId, DateTimeOffset FrozenAt);

/// <summary>Result of reversing a freeze: the engagement is open again.</summary>
public sealed record EngagementUnfrozen(EngagementId EngagementId, DateTimeOffset UnfrozenAt);

/// <summary>Result of retiring an engagement.</summary>
public sealed record EngagementRetired(EngagementId EngagementId, DateTimeOffset RetiredAt);

/// <summary>Result of applying an ROE profile: the engagement and its scope now in force.</summary>
public sealed record RoeApplied(EngagementId EngagementId, RoeProfile Profile);

/// <summary>
/// Result of minting a deploy token. <see cref="Secret"/> is the plaintext,
/// shown exactly once at mint time.
/// </summary>
public sealed record DeployTokenMinted(
    DeployTokenId DeployTokenId,
    EngagementId EngagementId,
    string Secret,
    OperatorId IssuedBy,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    int MaxUses);
