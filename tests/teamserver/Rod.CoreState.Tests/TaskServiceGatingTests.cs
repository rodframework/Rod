using Rod.CoreState.Application;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;
using Rod.CoreState.Tasks;
using Task = System.Threading.Tasks.Task;

namespace Rod.CoreState.Tests;

/// <summary>
/// Checks of the task-issuance gate (architecture.md Sec 5.2, Sec 10.3). The
/// implant's class reduced verb set is the authority for what it may run: an
/// allowed verb is queued, an unsupported one is refused before queueing, and
/// the implant's engagement binding is enforced at issue time too. Drives
/// <see cref="TaskService"/> against the in-memory repositories the rest of the
/// core-state tests use.
/// </summary>
public class TaskServiceGatingTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch;

    private static async Task<Implant> EnrollAsync(
        InMemoryImplantRepository implants,
        EngagementId engagement,
        ImplantClass @class)
    {
        var implant = Implant.Enroll(
            ImplantId.New(), engagement, Now.AddDays(30), @class, Now);
        await implants.SaveAsync(implant);
        return implant;
    }

    // No engagement records are stored, so the ROE lookup resolves nothing and
    // the profile in force is the unrestricted default -- these tests exercise
    // the class gate, not the scope gate (RoeGateTests covers that).
    private static TaskService NewService(InMemoryImplantRepository implants)
        => new(new InMemoryTaskRepository(), implants, new InMemoryEngagementRepository(), TimeProvider.System);

    [Theory]
    [InlineData(ImplantClass.Implant, "shell.exec")]
    [InlineData(ImplantClass.Implant, "file.pull")]
    [InlineData(ImplantClass.Implant, "tunnel.forward")]
    [InlineData(ImplantClass.WebShell, "shell.exec")]
    [InlineData(ImplantClass.Pivot, "tunnel.forward")]
    public async Task IssueAsync_AcceptsAVerbInFromClassSet(ImplantClass @class, string verb)
    {
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, @class);
        var service = NewService(implants);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), verb, "arg"));

        Assert.Equal(verb, issued.Verb);
        Assert.Equal(implant.Id, issued.ImplantId);
    }

    [Theory]
    [InlineData(ImplantClass.Ephemeral, "file.push")]
    [InlineData(ImplantClass.Pivot, "shell.exec")]
    public async Task IssueAsync_RejectsAVerbOutsideTheClassSet(ImplantClass @class, string verb)
    {
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, @class);
        var service = NewService(implants);

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(
                new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), verb, "arg")));

        Assert.Equal(TaskRejectionReason.UnsupportedVerbForClass, ex.Reason);
    }

    [Fact]
    public async Task IssueAsync_RejectsUnknownImplant()
    {
        var service = NewService(new InMemoryImplantRepository());

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(
                new IssueTaskCommand(EngagementId.New(), ImplantId.New(), OperatorId.New(), "shell.exec", "arg")));

        Assert.Equal(TaskRejectionReason.UnknownImplant, ex.Reason);
    }

    [Fact]
    public async Task IssueAsync_RejectsImplantFromAnotherEngagement()
    {
        var implants = new InMemoryImplantRepository();
        var implant = await EnrollAsync(implants, EngagementId.New(), ImplantClass.Implant);
        var service = NewService(implants);

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(
                new IssueTaskCommand(EngagementId.New(), implant.Id, OperatorId.New(), "shell.exec", "arg")));

        Assert.Equal(TaskRejectionReason.ImplantEngagementMismatch, ex.Reason);
    }

    [Fact]
    public async Task IssueAsync_RejectsRetiredImplant()
    {
        // A retired implant is out of operation and untaskable (architecture.md
        // Sec 7). The refusal happens before the verb gate, so even a verb
        // in the implant's class set is refused once the implant is retired.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        implant.Retire(Now);
        var service = NewService(implants);

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(
                new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "shell.exec", "arg")));

        Assert.Equal(TaskRejectionReason.ImplantRetired, ex.Reason);
    }

    // An implant stamped with its build's baked carrier set (the enrollment
    // derivation), for the carrier-gate checks below.
    private static async Task<Implant> EnrollWithCarriersAsync(
        InMemoryImplantRepository implants,
        EngagementId engagement,
        IReadOnlyList<string>? carriers)
    {
        var implant = Implant.EnrollChild(
            ImplantId.New(), engagement, Now.AddDays(30), ImplantClass.Implant, Now,
            carriers: carriers);
        await implants.SaveAsync(implant);
        return implant;
    }

    [Fact]
    public async Task IssueAsync_RejectsAChannelVerbWhenNoBakedCarrierServesOne()
    {
        // The carrier gate (architecture.md Sec 10.3): an artifact whose
        // every carrier declares no channel support at all can never claim a
        // channel task, so the refusal lands at issuance instead of leaving
        // the task queued forever. (DNS itself now serves store-and-forward
        // channels, so it no longer lands here -- the message-pipe family's
        // unknown carriers do.)
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollWithCarriersAsync(implants, engagement, new[] { "unknown-carrier" });
        var service = NewService(implants);

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(
                new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "shell.interact", "")));

        Assert.Equal(TaskRejectionReason.NoChannelCarrier, ex.Reason);
    }

    [Fact]
    public async Task IssueAsync_AllowsAChannelVerbOnADnsOnlyImplant()
    {
        // The DNS carrier serves store-and-forward channels (architecture.md
        // Sec 10.3): input rides the TXT answers, output chunks up as
        // queries -- a DNS-only artifact claims the channel verbs.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollWithCarriersAsync(implants, engagement, new[] { "dns" });
        var service = NewService(implants);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "shell.interact", ""));

        Assert.Equal("shell.interact", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_AllowsAChannelVerbWhenABakedCarrierHoldsAStream()
    {
        // A stream-mode web build bakes both web carriers: the envelope
        // cycle its front serves and the WebSocket stream its mode holds,
        // so the channel verb is claimable.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollWithCarriersAsync(
            implants, engagement, new[] { "envelope", "beacon-stream" });
        var service = NewService(implants);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "shell.interact", ""));

        Assert.Equal("shell.interact", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_AllowsAChannelVerbWhenCarriersAreUndeclared()
    {
        // Null is the permissive shape (a legacy implant, an unrecognized
        // build): the dispatch-time claim evaluation alone decides, exactly
        // as before the stamp existed.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollWithCarriersAsync(implants, engagement, carriers: null);
        var service = NewService(implants);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "tunnel.forward", "10.0.0.1 80"));

        Assert.Equal("tunnel.forward", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_AllowsAChannelVerbOnAnEnvelopeOnlyImplant()
    {
        // The store-and-forward discipline is not a bake-time choice: the
        // envelope carrier itself claims channel verbs, carried on every
        // poll cycle the artifact runs.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollWithCarriersAsync(
            implants, engagement, new[] { "envelope" });
        var service = NewService(implants);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "shell.interact", ""));

        Assert.Equal("shell.interact", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_AllowsOneShotTaskingOnAnEnvelopeOnlyImplant()
    {
        // The carrier gate touches channel verbs only: one-shot tasking is
        // exactly as dispatchable over the envelope as it ever was.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollWithCarriersAsync(implants, engagement, new[] { "envelope" });
        var service = NewService(implants);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "shell.exec", "whoami"));

        Assert.Equal("shell.exec", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_DefaultResolverIsTheStrictClassTable()
    {
        // The default capability resolver (architecture.md Sec 5.2/10.3) is the
        // per-class reduced verb set alone -- it admits no contract-and-dispatch-
        // only verb (evasion, exploit) on its own. That path opens when the
        // capabilities layer wires a registry-backed resolver in (architecture.md
        // Sec 10.2); core state alone stays strict, so this test host and the
        // core-state unit tests keep the behavior they had before .
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        var service = NewService(implants);

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(
                new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "evasion.avoid", "arg")));

        Assert.Equal(TaskRejectionReason.UnsupportedVerbForClass, ex.Reason);
    }

    [Fact]
    public async Task IssueAsync_AdmitsAVerbTheCapabilityResolverAllows()
    {
        // The task gate consults the capability resolver (architecture.md Sec
        // 10.3): a resolver that admits a verb the class set does not -- standing
        // in for the tradecraft-backed resolver a registered module satisfies --
        // lets the verb through. This is the mechanic in isolation: the
        // resolver, not the class table alone, is the gate authority.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        var service = new TaskService(
            new InMemoryTaskRepository(),
            implants,
            new InMemoryEngagementRepository(),
            TimeProvider.System,
            bus: null,
            capabilities: new AllowingResolver("evasion.avoid"),
            wake: null);

        var issued = await service.IssueAsync(
            new IssueTaskCommand(engagement, implant.Id, OperatorId.New(), "evasion.avoid", "arg"));

        Assert.Equal("evasion.avoid", issued.Verb);
    }

    // The runtime half of the compatibility collapse (architecture.md
    // Sec 15.2, ADR-017): a module.load naming a registered module checks the
    // module's requirement rows against the live session's handshake
    // advertisement. The staged-content hash the transport appends rides the
    // arguments' tail, exactly as a real issuance carries it.
    private static TaskService NewRequiringService(
        InMemoryImplantRepository implants,
        ISessionRegistry sessions,
        string moduleName,
        params string[] requires)
        => new(
            new InMemoryTaskRepository(),
            implants,
            new InMemoryEngagementRepository(),
            TimeProvider.System,
            bus: null,
            capabilities: new RequiringResolver(moduleName, requires),
            wake: null,
            references: null,
            harvester: null,
            sessions: sessions);

    private static async Task<InMemorySessionRegistry> SessionAdvertisingAsync(
        Implant implant, params string[] capabilities)
    {
        var sessions = new InMemorySessionRegistry();
        await sessions.OpenAsync(implant, capabilities, Now);
        return sessions;
    }

    [Fact]
    public async Task IssueAsync_RefusesAModuleLoadTheSessionAdvertisementDoesNotCover()
    {
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        var sessions = await SessionAdvertisingAsync(implant, "shell.exec", "file.pull");
        var service = NewRequiringService(implants, sessions, "hives", "plugin-loader/exec-v1");

        var ex = await Assert.ThrowsAsync<TaskRejectedException>(
            () => service.IssueAsync(new IssueTaskCommand(
                engagement, implant.Id, OperatorId.New(), "module.load", "hives sha256:00")));

        Assert.Equal(TaskRejectionReason.ModuleRequirementNotMet, ex.Reason);
        Assert.Contains("plugin-loader", ex.Message);
        Assert.Contains("hives", ex.Message);
    }

    [Fact]
    public async Task IssueAsync_AdmitsAModuleLoadTheSessionAdvertisementCovers()
    {
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        var sessions = await SessionAdvertisingAsync(implant, "shell.exec", "module.load", "file.pull");
        var service = NewRequiringService(implants, sessions, "hives", "plugin-loader/exec-v1", "exfil-chunks");

        var issued = await service.IssueAsync(new IssueTaskCommand(
            engagement, implant.Id, OperatorId.New(), "module.load", "hives sha256:00"));

        Assert.Equal("module.load", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_QueueSAModuleLoadWithNoActiveSession_UnderTheStoreAdvisory()
    {
        // An offline implant has no advertisement to check against: the queued
        // task keeps the store's install-time advisory posture, and the gate
        // re-arms when a session opens.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        var service = NewRequiringService(implants, new InMemorySessionRegistry(), "hives", "plugin-loader/exec-v1");

        var issued = await service.IssueAsync(new IssueTaskCommand(
            engagement, implant.Id, OperatorId.New(), "module.load", "hives sha256:00"));

        Assert.Equal("module.load", issued.Verb);
    }

    [Fact]
    public async Task IssueAsync_AModuleLoadNamingNoRegisteredModuleIsUngated()
    {
        // A handle no registered module carries has no rows to check -- the
        // gate reads requirements, not names.
        var implants = new InMemoryImplantRepository();
        var engagement = EngagementId.New();
        var implant = await EnrollAsync(implants, engagement, ImplantClass.Implant);
        var sessions = await SessionAdvertisingAsync(implant, "shell.exec");
        var service = NewRequiringService(implants, sessions, "hives", "plugin-loader/exec-v1");

        var issued = await service.IssueAsync(new IssueTaskCommand(
            engagement, implant.Id, OperatorId.New(), "module.load", "operator-binary sha256:00"));

        Assert.Equal("module.load", issued.Verb);
    }

    // A resolver standing in for the registry-backed one: the class table plus
    // one named module's requirement rows.
    private sealed class RequiringResolver : ITaskCapabilityResolver
    {
        private readonly string _moduleName;
        private readonly IReadOnlyList<string> _requires;

        public RequiringResolver(string moduleName, string[] requires)
        {
            _moduleName = moduleName;
            _requires = requires;
        }

        public bool IsDispatchable(ImplantClass @class, string verb)
            => ImplantClassCapabilities.Allows(@class, verb);

        public IReadOnlyList<string>? ModuleRequires(string moduleName)
            => string.Equals(moduleName, _moduleName, StringComparison.OrdinalIgnoreCase) ? _requires : null;
    }

    // A resolver that admits exactly one verb regardless of class -- the
    // stand-in for the registry-backed resolver the capabilities layer supplies
    // when a module is registered for a no-class-gate verb.
    private sealed class AllowingResolver : ITaskCapabilityResolver
    {
        private readonly string _verb;

        public AllowingResolver(string verb) => _verb = verb;

        public bool IsDispatchable(ImplantClass @class, string verb)
            => string.Equals(verb, _verb, StringComparison.OrdinalIgnoreCase);

        public IReadOnlyList<string>? ModuleRequires(string moduleName) => null;
    }
}
