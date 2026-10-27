namespace Rod.CoreState;

/// <summary>
/// Base type for all engagement-domain invariant violations. Domain rules throw
/// a subclass so callers (use-case code, HTTP endpoints) can distinguish a
/// client-correctable error from an unexpected failure.
/// </summary>
public abstract class DomainException : InvalidOperationException
{
    protected DomainException(string message)
        : base(message)
    {
    }

    protected DomainException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>A deploy-token operation violated its rules -- e.g. unknown engagement.</summary>
public class DeployTokenException : DomainException
{
    public DeployTokenException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Why a deploy-token redeem failed. Carried on
/// <see cref="DeployTokenRedeemException"/> so the enroll endpoint can map each
/// reason to a distinct wire status code (architecture.md Sec 9) without the
/// core depending on the wire protocol.
/// </summary>
public enum DeployTokenRedeemReason
{
    /// <summary>
    /// No token matched the presented secret (unknown, malformed, or wrong) --
    /// including a credential whose row was hard-deleted: deletion removes the
    /// resolution itself, so a deleted credential's secrets read as nobody's.
    /// </summary>
    Unknown,

    /// <summary>The matched token had passed its hard expiry.</summary>
    Expired,

    /// <summary>The matched token had no remaining uses.</summary>
    Spent,

    /// <summary>The matched token had been revoked; it still resolves to its engagement.</summary>
    Revoked,
}

/// <summary>
/// A deploy-token redeem was refused -- the secret matched no token, or the
/// matched token was expired, spent, or revoked. <see cref="Reason"/> is the
/// actionable cause; the caller maps it to a wire status. When the secret did
/// resolve a stored token, <see cref="EngagementId"/> and
/// <see cref="TokenId"/> carry the attribution so a caller can record the
/// refusal against the engagement it targeted; an unknown secret belongs to
/// no engagement and carries nothing.
/// </summary>
public sealed class DeployTokenRedeemException : DeployTokenException
{
    public DeployTokenRedeemReason Reason { get; }

    /// <summary>The engagement the resolved token belongs to; null when unknown.</summary>
    public EngagementId? EngagementId { get; }

    /// <summary>The resolved token; null when unknown.</summary>
    public DeployTokenId? TokenId { get; }

    public DeployTokenRedeemException(DeployTokenRedeemReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }

    public DeployTokenRedeemException(
        DeployTokenRedeemReason reason,
        string message,
        EngagementId engagementId,
        DeployTokenId tokenId)
        : base(message)
    {
        Reason = reason;
        EngagementId = engagementId;
        TokenId = tokenId;
    }
}

/// <summary>
/// Why a handshake was refused. Carried on <see cref="HandshakeException"/> so
/// the transport endpoint can map each reason to a distinct wire status
/// (architecture.md Sec 9) without the core depending on the wire protocol --
/// mirroring <see cref="DeployTokenRedeemReason"/>.
/// </summary>
public enum HandshakeReason
{
    /// <summary>The implant id matched no enrolled implant.</summary>
    UnknownImplant,

    /// <summary>The presented protocol version is not one the server speaks.</summary>
    VersionMismatch,

    /// <summary>
    /// The certificate binding did not match the implant's enrolled engagement
    /// (architecture.md Sec 9 mTLS identity check).
    /// </summary>
    IdentityMismatch,

    /// <summary>
    /// The implant's baked-in kill date has passed (architecture.md Sec 7). A
    /// lost implant self-terminates at its kill date; the teamserver mirrors that
    /// here by refusing to open a session for an implant past its kill date.
    /// </summary>
    KillDateExpired,

    /// <summary>
    /// The implant has been retired (architecture.md Sec 7). A retired
    /// implant is taken out of operation and never gets a session again; the
    /// teamserver refuses to open one and the stream closes.
    /// </summary>
    ImplantRetired,
}

/// <summary>
/// A handshake was refused -- the implant is unknown, the protocol version is
/// unsupported, the certificate-vs-identity check failed, the implant is past
/// its kill date, or the implant has been retired.
/// <see cref="Reason"/> is the actionable cause; the caller maps it to a wire
/// status.
/// </summary>
public sealed class HandshakeException : DomainException
{
    public HandshakeReason Reason { get; }

    public HandshakeException(HandshakeReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }
}

/// <summary>
/// Why a task issuance was refused. Carried on <see cref="TaskRejectedException"/>
/// so the task endpoint can map each reason to a distinct HTTP status
/// (architecture.md Sec 10.3) without the core depending on the transport --
/// mirroring <see cref="HandshakeReason"/> and <see cref="DeployTokenRedeemReason"/>.
/// </summary>
public enum TaskRejectionReason
{
    /// <summary>
    /// The verb is not in the implant's class reduced verb set
    /// (architecture.md Sec 5.2). The implant's class is fixed at enrollment;
    /// this is the per-class capability gate.
    /// </summary>
    UnsupportedVerbForClass,

    /// <summary>
    /// The verb runs as a live channel and none of the implant's baked
    /// carriers holds a stream to run one on (architecture.md Sec 10.3): the
    /// task could queue but never be claimed. Refused at issuance so the
    /// operator reads the cause instead of watching a task sit queued.
    /// </summary>
    NoChannelCarrier,

    /// <summary>The implant id matched no enrolled implant.</summary>
    UnknownImplant,

    /// <summary>
    /// The implant belongs to a different engagement than the task
    /// (architecture.md Sec 3 -- cross-engagement access is impossible by
    /// construction).
    /// </summary>
    ImplantEngagementMismatch,

    /// <summary>
    /// The implant has been retired (architecture.md Sec 7). A retired
    /// implant is taken out of operation and is untaskable; the issuance is
    /// refused before the task is queued.
    /// </summary>
    ImplantRetired,

    /// <summary>
    /// The task falls outside the engagement's rules-of-engagement scope
    /// (architecture.md Sec 9 -- ROE guardrails): the verb is not a permitted
    /// verb or the implant is not a permitted target. Refused before the task is
    /// queued; the transport records the refusal naming the violated rule.
    /// </summary>
    RoeViolation,

    /// <summary>
    /// The engagement has been frozen for close-out or retired (architecture.md
    /// Sec 2 step 10). A closed engagement accepts no new tasking; the issuance
    /// is refused before the task is queued so the exported evidence package is
    /// the final account of what was tasked.
    /// </summary>
    EngagementClosed,

    /// <summary>
    /// The task input carries a task-reference token
    /// (<c>@task-&lt;id&gt;</c> / <c>$cred-&lt;id&gt;</c>, architecture.md
    /// Sec 15.3, ADR-005) that resolves to no task or credential of the
    /// engagement. Refused at issuance, before the queue, with the offender
    /// named -- a dangling reference reaching the implant reads as a
    /// mysterious failure there instead.
    /// </summary>
    UnknownTaskReference,

    /// <summary>
    /// A <c>module.load</c> names a registered module whose requirement rows
    /// (architecture.md Sec 15.2, ADR-017 -- the runtime half of the
    /// compatibility collapse) are not covered by the implant's session
    /// advertisement: the hosting implant cannot run what the module's
    /// execution half needs. Refused at issuance with the missing capability
    /// named, before the queue -- the load would only fail on the target
    /// after a round trip.
    /// </summary>
    ModuleRequirementNotMet,
}

/// <summary>
/// A task issuance was refused -- the verb is outside the implant's class
/// reduced verb set, the implant is unknown, it belongs to another engagement,
/// or it has been retired. <see cref="Reason"/> is the actionable cause; the
/// caller maps it to a wire status.
/// </summary>
public sealed class TaskRejectedException : DomainException
{
    public TaskRejectionReason Reason { get; }

    public TaskRejectedException(TaskRejectionReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }
}

/// <summary>
/// Why a child enrollment was refused. Carried on
/// <see cref="InvalidParentImplantException"/> so the enroll endpoint can map
/// each reason to a distinct wire status code (architecture.md Sec 5.2/9)
/// without the core depending on the wire protocol -- mirroring
/// <see cref="DeployTokenRedeemReason"/>.
/// </summary>
public enum InvalidParentImplantReason
{
    /// <summary>
    /// The parent implant id matched no enrolled implant. A child must derive
    /// from a real parent, so an unknown parent id refuses the enroll.
    /// </summary>
    Unknown,

    /// <summary>
    /// The parent belongs to a different engagement than the token redeemed
    /// (architecture.md Sec 3 -- a child enrols into the same engagement as its
    /// parent, and cross-engagement access is impossible by construction).
    /// </summary>
    EngagementMismatch,

    /// <summary>
    /// The parent has been retired (architecture.md Sec 7). A retired
    /// implant is out of operation and cannot derive children; the enroll is
    /// refused before the child is recorded.
    /// </summary>
    Retired,
}

/// <summary>
/// A child enrollment was refused -- the parent implant is unknown, belongs to
/// another engagement, or has been retired (architecture.md Sec 5.2).
/// <see cref="Reason"/> is the actionable cause; the caller maps it to a wire
/// status.
/// </summary>
public sealed class InvalidParentImplantException : DomainException
{
    public InvalidParentImplantReason Reason { get; }

    public InvalidParentImplantException(InvalidParentImplantReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }
}

/// <summary>
/// The engagement is closed for close-out -- frozen or retired (architecture.md
/// Sec 2 step 10). Thrown by the deployment paths (enrollment, deploy-token
/// mint) so a closed engagement accepts no new implants; the caller maps it to
/// a wire status. Distinct from the aggregate's own transition guards, which
/// reject an out-of-order freeze or retire.
/// </summary>
public sealed class EngagementClosedException : DomainException
{
    public EngagementClosedException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Why a redirector-node enrollment was refused. Carried on
/// <see cref="RedirectorEnrollException"/> so the control endpoint can answer
/// each cause with its own refusal without the core depending on the control
/// channel's wire shapes.
/// </summary>
public enum RedirectorEnrollReason
{
    /// <summary>
    /// No credential matched the presented secret (unknown, malformed, or
    /// wrong).
    /// </summary>
    Unknown,

    /// <summary>The matched credential had passed its hard expiry.</summary>
    Expired,

    /// <summary>
    /// The matched credential had already enrolled a node -- single-use by
    /// design, so a replay reads as spent, not unknown.
    /// </summary>
    Spent,

    /// <summary>The matched credential had been revoked.</summary>
    Revoked,
}

/// <summary>
/// A redirector-node enrollment was refused -- the presented credential is
/// unknown, expired, spent, or revoked (architecture.md Sec 8). The caller
/// closes the control connection with the reason.
/// </summary>
public sealed class RedirectorEnrollException : DomainException
{
    public RedirectorEnrollReason Reason { get; }

    public RedirectorEnrollException(RedirectorEnrollReason reason, string message)
        : base(message)
    {
        Reason = reason;
    }
}

/// <summary>
/// A redirector node's reconnection was refused -- the node id is unknown or
/// the node has been retired. Retirement is the revocation half for nodes:
/// the refusal at the next reconnect is the whole enforcement.
/// </summary>
public sealed class RedirectorNodeRefusedException : DomainException
{
    public RedirectorNodeRefusedException(string message)
        : base(message)
    {
    }
}
