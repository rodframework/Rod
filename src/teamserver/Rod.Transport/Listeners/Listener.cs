using Rod.CoreState;
using Rod.CoreState.Listeners;

namespace Rod.Transport.Listeners;

/// <summary>
/// One bound C2 ingress the teamserver terminates (architecture.md Sec 8).
/// Two tiers share this shape: the engagement-scoped listener a runtime
/// create binds for one engagement (enrollment through it checks the
/// presented token against <see cref="EngagementId"/>), and the startup-
/// configuration tier -- the operator front and any deliberately shared
/// ingress -- which leaves <see cref="EngagementId"/> null and carries no
/// implant ingress at all: enrollment and the payload fetch are refused on
/// it outright. A redirector fronts a listener;
/// a burned redirector is replaced without touching the backend.
///
/// The listener decouples the address Kestrel opens (<see cref="BindAddress"/>) from
/// the address implants are told to dial (<see cref="PublicEndpoint"/>). The bind
/// address is operational plumbing (which interface and port the process opens);
/// the public endpoint is the redirector or host-header the implant carries in its
/// profile. They are independent so the public endpoint can move -- a redirected
/// domain, a different host -- without reconfiguring or restarting the listener:
/// <see cref="Repoint"/> swaps the public endpoint at runtime (architecture.md
/// Sec 7/8), leaving the bound socket untouched. Repointing away from an
/// endpoint severs it -- the registry's public-endpoint lookup no longer resolves
/// it -- so a burned redirector is retired by pointing its listener elsewhere.
/// </summary>
public sealed class Listener
{
    public ListenerId Id { get; }
    public string Name { get; }

    /// <summary>
    /// The transport this listener terminates, by its wire name (the registry
    /// key a provider registers under -- "http", "https", "dns", "tcp",
    /// "doh", "shellcatch", or a later transport's own name). A
    /// string, not a closed
    /// enumeration: the registry is the authority for what a listener may
    /// name, so a transport added later needs no edit here.
    /// </summary>
    public string Transport { get; }
    public string BindAddress { get; }
    public string PublicEndpoint { get; private set; }

    /// <summary>
    /// Whose certificate the front presents, the fact a build's TLS roots
    /// must match (architecture.md Sec 9): "pinned" -- the default -- the
    /// engagement CA terminates the front and the artifacts it serves pin
    /// that CA; "public" a real-domain front whose publicly-trusted chain an
    /// operator-run edge terminates, served to artifacts that validate like
    /// ordinary clients. A property of the front, not the artifact: the
    /// listener owns the fact and the build inherits it, because the
    /// certificate is deployed where the listener is, not where the build
    /// form is. Only the https transport may name public.
    /// </summary>
    public string TrustPosture { get; }

    /// <summary>The engagement this listener answers for; null on the shared tier.</summary>
    public EngagementId? EngagementId { get; }

    /// <summary>
    /// The listener package this listener binds (ADR-025): on a
    /// package-backed listener the medium is an external process from the
    /// installed package, supervised over the bridge, and the transport
    /// field carries the package's own name. Null on a provider-backed
    /// listener (the in-tree families).
    /// </summary>
    public string? PackageName { get; }

    /// <summary>The bound package's version (ADR-025); null when
    /// provider-backed.</summary>
    public string? PackageVersion { get; }

    /// <summary>
    /// The bound package's declared seal tier (ADR-025): "sealed" or
    /// "id-only", the carrier posture the kernel enforced at resolve.
    /// Null when provider-backed.
    /// </summary>
    public string? SealTier { get; }

    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset? RepointedAt { get; private set; }
    public ListenerState State { get; private set; }

    /// <summary>
    /// The ordered front list (architecture.md Sec 8): attachments to
    /// enrolled redirector nodes the control plane provisions with forwarding
    /// rules. Empty for a hand-fronted listener. Index zero is the primary
    /// front -- the listener's <see cref="PublicEndpoint"/> reports it, so
    /// repointing is re-attaching or promoting the primary.
    /// </summary>
    public IReadOnlyList<ListenerFront> Fronts { get; private set; } = [];

    private Listener(
        ListenerId id,
        string name,
        string transport,
        string bindAddress,
        string publicEndpoint,
        EngagementId? engagementId,
        string trustPosture,
        DateTimeOffset createdAt,
        ListenerState state,
        IReadOnlyList<ListenerFront>? fronts = null,
        string? packageName = null,
        string? packageVersion = null,
        string? sealTier = null)
    {
        Id = id;
        Name = name;
        Transport = transport;
        BindAddress = bindAddress;
        PublicEndpoint = publicEndpoint;
        EngagementId = engagementId;
        TrustPosture = trustPosture;
        CreatedAt = createdAt;
        State = state;
        Fronts = fronts ?? [];
        PackageName = packageName;
        PackageVersion = packageVersion;
        SealTier = sealTier;
    }

    /// <summary>
    /// Factory for a listener at startup. The listener begins
    /// <see cref="ListenerState.Stopped"/>; <see cref="Start"/> moves it to
    /// <see cref="ListenerState.Running"/> once the host has bound its socket.
    /// </summary>
    public static Listener Define(
        ListenerId id,
        string name,
        string transport,
        string bindAddress,
        string publicEndpoint,
        DateTimeOffset at,
        EngagementId? engagementId = null,
        string trustPosture = "pinned",
        IReadOnlyList<ListenerFront>? fronts = null)
        => new(id, name, transport, bindAddress, publicEndpoint, engagementId, trustPosture, at, ListenerState.Stopped, fronts);

    /// <summary>
    /// Factory for a package-backed listener (ADR-025): the medium is an
    /// external process from the named installed package, supervised over
    /// the bridge. The transport field carries the package's own name -- a
    /// listener package is its own registry entry, not a provider's.
    /// </summary>
    public static Listener DefinePackaged(
        ListenerId id,
        string name,
        string packageName,
        string packageVersion,
        string sealTier,
        string bindAddress,
        string publicEndpoint,
        DateTimeOffset at,
        EngagementId engagementId)
        => new(
            id, name, packageName, bindAddress, publicEndpoint, engagementId, "pinned", at,
            ListenerState.Stopped,
            fronts: null,
            packageName,
            packageVersion,
            sealTier);

    /// <summary>
    /// Marks the listener as bound and accepting connections. Only legal from
    /// <see cref="ListenerState.Stopped"/>; a re-call on a running listener is a
    /// no-op. The host drives this from <c>UseRodListeners</c> after Kestrel opens
    /// the socket, so the registry reflects what is actually listening.
    /// </summary>
    public void Start()
    {
        if (State == ListenerState.Running)
            return;
        if (State != ListenerState.Stopped)
            throw new InvalidOperationException($"Listener {Id} cannot start from {State}.");

        State = ListenerState.Running;
    }

    /// <summary>
    /// The supervisor's health signal (ADR-025): the listener's process
    /// exited, so the listener is unhealthy while the restart schedule
    /// waits. Legal from Running; the kernel process is untouched.
    /// </summary>
    public void MarkUnhealthy()
    {
        if (State == ListenerState.Running)
            State = ListenerState.Unhealthy;
    }

    /// <summary>
    /// The respawn landed: the listener serves again. Legal from
    /// <see cref="ListenerState.Unhealthy"/>.
    /// </summary>
    public void MarkRunning()
    {
        if (State == ListenerState.Unhealthy)
            State = ListenerState.Running;
    }

    /// <summary>
    /// Swaps the public endpoint -- the redirector or host-header implants dial --
    /// without touching the bound socket (architecture.md Sec 7/8). The bind
    /// address is unchanged, so a live listener keeps serving; only the address
    /// implants are told to dial moves. This is how a burned redirector is
    /// replaced without backend change: repoint to a fresh redirector and the old
    /// endpoint stops resolving. Severing a redirector outright is the same op --
    /// point its listener at the new endpoint, and the old one no longer maps to
    /// anything. Validates the new endpoint is non-blank.
    /// </summary>
    public void Repoint(string publicEndpoint, DateTimeOffset at)
    {
        if (string.IsNullOrWhiteSpace(publicEndpoint))
            throw new ArgumentException("Public endpoint is required.", nameof(publicEndpoint));

        PublicEndpoint = publicEndpoint;
        RepointedAt = at;
    }

    /// <summary>
    /// Attaches a front. A primary attach (or the first front on a listener
    /// with none) inserts at index zero and repoints the listener's public
    /// endpoint to the front's -- the re-attach form of repointing
    /// (architecture.md Sec 8); a non-primary attach appends and leaves the
    /// reported endpoint alone. The DNS family is the exception: its public
    /// endpoint is the zone, the dial's other half, so the front carries the
    /// resolver and the record never follows.
    /// </summary>
    public void AttachFront(ListenerFront front, bool primary, DateTimeOffset at)
    {
        var list = Fronts.ToList();
        if (list.Count == 0 || primary)
        {
            list.Insert(0, front);
            if (EndpointFollowsPrimary)
            {
                PublicEndpoint = front.PublicEndpoint;
                RepointedAt = at;
            }
        }
        else
        {
            list.Add(front);
        }

        Fronts = list;
    }

    /// <summary>
    /// Detaches a front. Detaching the primary promotes the next front, and
    /// the reported endpoint follows it (the DNS family excepted, as on
    /// attach); detaching the last front leaves the endpoint where it was --
    /// the string stays meaningful for a listener that falls back to a
    /// hand-deployed front. Returns false when the id matches no front.
    /// </summary>
    public bool DetachFront(Guid frontId, DateTimeOffset at)
    {
        var index = FindFrontIndex(frontId);
        if (index < 0)
            return false;

        var list = Fronts.ToList();
        list.RemoveAt(index);
        Fronts = list;
        if (index == 0 && list.Count > 0 && EndpointFollowsPrimary)
        {
            PublicEndpoint = list[0].PublicEndpoint;
            RepointedAt = at;
        }

        return true;
    }

    /// <summary>
    /// Promotes a front to primary: it moves to index zero and the reported
    /// endpoint follows (the DNS family excepted). This is the rotation op
    /// for enrolled fronts -- swapping the front new builds bake without
    /// touching the bind or the other fronts' rules. Returns false when the
    /// id matches no front.
    /// </summary>
    public bool PromoteFront(Guid frontId, DateTimeOffset at)
    {
        var index = FindFrontIndex(frontId);
        if (index < 0)
            return false;
        if (index == 0)
            return true;

        var list = Fronts.ToList();
        var front = list[index];
        list.RemoveAt(index);
        list.Insert(0, front);
        Fronts = list;
        if (EndpointFollowsPrimary)
        {
            PublicEndpoint = front.PublicEndpoint;
            RepointedAt = at;
        }

        return true;
    }

    // The endpoint-follows-primary rule's family exception (architecture.md
    // Sec 8): the DNS family's public endpoint is the zone -- the front
    // carries the resolver instead, so the record's half never moves.
    private bool EndpointFollowsPrimary
        => !string.Equals(Transport, "dns", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(Transport, "doh", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Sets the front list wholesale, the restore path's op: the stored
    /// definition is the truth being restored, and its public endpoint
    /// already names the primary, so no repoint fires here.
    /// </summary>
    public void RestoreFronts(IReadOnlyList<ListenerFront> fronts)
        => Fronts = fronts;

    /// <summary>
    /// The front attaching to the given node, if this listener has one --
    /// the rule-push path's lookup when a node's rule set changes because a
    /// listener it fronts changed.
    /// </summary>
    public ListenerFront? FrontFor(RedirectorNodeId node)
        => Fronts.FirstOrDefault(f => f.NodeId == node);

    private int FindFrontIndex(Guid frontId)
    {
        for (var i = 0; i < Fronts.Count; i++)
        {
            if (Fronts[i].FrontId == frontId)
                return i;
        }

        return -1;
    }
}
