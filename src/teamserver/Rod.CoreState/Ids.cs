namespace Rod.CoreState;

// Strongly typed identifiers for the engagement core (architecture.md Sec 3).
// Wrapping the underlying Guid in a distinct type stops an OperatorId being
// passed where an EngagementId is expected, and keeps the idiom uniform across
// every entity.

/// <summary>Identifies a global operator identity (one human user).</summary>
public readonly record struct OperatorId(Guid Value)
{
    public static OperatorId New() => new(Guid.NewGuid());

    /// <summary>
    /// The null operator, for system-initiated events no human operator
    /// performed (e.g. a staleness sweep closing a session).
    /// </summary>
    public static OperatorId Empty => new(Guid.Empty);

    public override string ToString() => Value.ToString("N");
}

/// <summary>Identifies an engagement -- the unit of isolation and authorization.</summary>
public readonly record struct EngagementId(Guid Value)
{
    public static EngagementId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses an engagement id from its string form. Accepts both the compact
    /// "N" format produced by <see cref="ToString"/> and the hyphenated Guid
    /// form; returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out EngagementId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new EngagementId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>Identifies a deploy token minted for an engagement.</summary>
public readonly record struct DeployTokenId(Guid Value)
{
    public static DeployTokenId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}

/// <summary>
/// Identifies a rendered launcher -- one persisted cut of the paste-ready
/// payload fetch one-liners, with its minted download credential. Engagement-
/// scoped operator working state, deletable with the row and nothing else.
/// </summary>
public readonly record struct LauncherId(Guid Value)
{
    public static LauncherId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    public static bool TryParse(string? text, out LauncherId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new LauncherId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies an implant -- a short-lived, disposable payload enrolled into one
/// engagement (architecture.md Sec 5). Ephemeral per engagement; disposable with
/// the operation.
/// </summary>
public readonly record struct ImplantId(Guid Value)
{
    public static ImplantId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses an implant id from its string form. Accepts the compact "N"
    /// format produced by <see cref="ToString"/> and the hyphenated Guid form;
    /// returns false on anything else. Used to read the binding back out of a
    /// certificate's URI SAN entries (architecture.md Sec 9).
    /// </summary>
    public static bool TryParse(string? text, out ImplantId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new ImplantId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a task -- a single dispatched verb to an implant, owned by an
/// operator and scoped to an engagement (architecture.md Sec 10.3). The task is
/// the unit operators task, implants execute, and the audit trail attributes.
/// </summary>
public readonly record struct TaskId(Guid Value)
{
    public static TaskId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a task id from its string form. Accepts both the compact "N"
    /// format produced by <see cref="ToString"/> and the hyphenated Guid form;
    /// returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out TaskId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new TaskId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a session -- one connected implant execution context in its
/// engagement (architecture.md Sec 4.1, Sec 10.3). An implant opens a session on
/// a successful handshake and closes it when the stream ends; an implant may have
/// many sessions over its life (reconnects, flaps). Disposable with the
/// engagement.
/// </summary>
public readonly record struct SessionId(Guid Value)
{
    public static SessionId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a session id from its string form. Accepts both the compact "N"
    /// format produced by <see cref="ToString"/> and the hyphenated Guid form;
    /// returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out SessionId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new SessionId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a caught reverse-shell session -- one accepted no-protocol
/// connection on a shellcatch listener in its engagement (architecture.md
/// Sec 8). Disposable with the engagement.
/// </summary>
public readonly record struct ShellSessionId(Guid Value)
{
    public static ShellSessionId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a shell session id from its string form. Accepts both the
    /// compact "N" format produced by <see cref="ToString"/> and the
    /// hyphenated Guid form; returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out ShellSessionId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new ShellSessionId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies an automation rule -- one engagement-scoped declarative
/// trigger/condition/action the automation engine fires (architecture.md
/// Sec 10.4). Disposable with the engagement.
/// </summary>
public readonly record struct AutomationRuleId(Guid Value)
{
    public static AutomationRuleId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a rule id from its string form. Accepts both the compact "N"
    /// format produced by <see cref="ToString"/> and the hyphenated Guid
    /// form; returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out AutomationRuleId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new AutomationRuleId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a webhook subscription -- one engagement-scoped channel the
/// notification forwarder pushes selected live events to (architecture.md
/// Sec 4.4). Disposable with the engagement.
/// </summary>
public readonly record struct WebhookSubscriptionId(Guid Value)
{
    public static WebhookSubscriptionId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a subscription id from its string form. Accepts both the
    /// compact "N" format produced by <see cref="ToString"/> and the
    /// hyphenated Guid form; returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out WebhookSubscriptionId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new WebhookSubscriptionId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a task snippet -- one engagement-scoped named sequence of
/// issue commands the operator console saves and replays through the
/// ordinary tasking path. Disposable with the engagement.
/// </summary>
public readonly record struct TaskSnippetId(Guid Value)
{
    public static TaskSnippetId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a snippet id from its string form. Accepts both the compact
    /// "N" format produced by <see cref="ToString"/> and the hyphenated
    /// Guid form; returns false on anything else.
    /// </summary>
    public static bool TryParse(string? text, out TaskSnippetId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new TaskSnippetId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a delivery campaign -- one engagement-scoped tracked lure
/// run (architecture.md Sec 11.5): a sending profile, a recipient list,
/// and a template, driven to per-recipient builds and tracked into
/// tasking. Disposable with the engagement.
/// </summary>
public readonly record struct CampaignId(Guid Value)
{
    public static CampaignId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a campaign id from its string form. Accepts both the compact
    /// "N" format and the hyphenated Guid form; returns false on anything
    /// else.
    /// </summary>
    public static bool TryParse(string? text, out CampaignId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new CampaignId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies one recipient row of a delivery campaign (architecture.md
/// Sec 11.5): the target whose lure link, baked credential, and evidence
/// timestamps the row carries. Disposable with the campaign.
/// </summary>
public readonly record struct CampaignRecipientId(Guid Value)
{
    public static CampaignRecipientId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");
}

/// <summary>
/// Identifies an enrolled redirector node (architecture.md Sec 8): one
/// machine of the deployment's forwarding capacity. Deployment-scoped -- a
/// node belongs to no engagement; attaching one of its fronts to a listener
/// is what grants engagement scope.
/// </summary>
public readonly record struct RedirectorNodeId(Guid Value)
{
    public static RedirectorNodeId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a redirector node id from its string form. Accepts both the
    /// compact "N" format and the hyphenated Guid form; returns false on
    /// anything else.
    /// </summary>
    public static bool TryParse(string? text, out RedirectorNodeId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new RedirectorNodeId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies a pre-provisioned redirector enrollment credential
/// (architecture.md Sec 8): the one-use secret an operator hands to a node
/// so it can enroll itself against the control plane. Deployment-scoped like
/// the node it mints.
/// </summary>
public readonly record struct RedirectorCredentialId(Guid Value)
{
    public static RedirectorCredentialId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a credential id from its string form. Accepts both the
    /// compact "N" format and the hyphenated Guid form; returns false on
    /// anything else.
    /// </summary>
    public static bool TryParse(string? text, out RedirectorCredentialId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new RedirectorCredentialId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies one collaboration comment (architecture.md Sec 15.3,
/// ADR-005): mutable process knowledge attached to an entity of the
/// engagement. Disposable with the engagement.
/// </summary>
public readonly record struct CommentId(Guid Value)
{
    public static CommentId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a comment id from its string form. Accepts both the compact
    /// "N" format and the hyphenated Guid form; returns false on anything
    /// else.
    /// </summary>
    public static bool TryParse(string? text, out CommentId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new CommentId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies one engagement-scoped chat channel (architecture.md
/// Sec 15.3, ADR-005): the operators' coordination room. Disposable
/// with the engagement.
/// </summary>
public readonly record struct ChatChannelId(Guid Value)
{
    public static ChatChannelId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a channel id from its string form. Accepts both the compact
    /// "N" format and the hyphenated Guid form; returns false on anything
    /// else.
    /// </summary>
    public static bool TryParse(string? text, out ChatChannelId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new ChatChannelId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies one message sent on an engagement chat channel
/// (architecture.md Sec 15.3, ADR-005). Disposable with the engagement.
/// </summary>
public readonly record struct ChatMessageId(Guid Value)
{
    public static ChatMessageId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");
}

/// <summary>
/// Identifies one harvested-credential row (architecture.md Sec 15.3,
/// ADR-005): the persisted landing of a credential-kind task's output,
/// addressable by task references. Disposable with the engagement.
/// </summary>
public readonly record struct CredentialId(Guid Value)
{
    public static CredentialId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a credential id from its string form. Accepts both the
    /// compact "N" format and the hyphenated Guid form; returns false on
    /// anything else.
    /// </summary>
    public static bool TryParse(string? text, out CredentialId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new CredentialId(guid);
            return true;
        }

        id = default;
        return false;
    }
}

/// <summary>
/// Identifies one recon asset -- a first-class target entity of the
/// unified entity model (architecture.md Sec 15.4): an address the recon
/// workbench or an operator surfaced, referenceable by the rest of the
/// model (a campaign's target selection names one by this id). Disposable
/// with the engagement.
/// </summary>
public readonly record struct ReconAssetId(Guid Value)
{
    public static ReconAssetId New() => new(Guid.NewGuid());

    public override string ToString() => Value.ToString("N");

    /// <summary>
    /// Parses a recon asset id from its string form. Accepts both the
    /// compact "N" format and the hyphenated Guid form; returns false on
    /// anything else.
    /// </summary>
    public static bool TryParse(string? text, out ReconAssetId id)
    {
        if (Guid.TryParse(text, out var guid))
        {
            id = new ReconAssetId(guid);
            return true;
        }

        id = default;
        return false;
    }
}
