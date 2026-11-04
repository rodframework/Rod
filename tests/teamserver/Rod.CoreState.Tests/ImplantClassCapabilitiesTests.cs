using Rod.CoreState.Implants;

namespace Rod.CoreState.Tests;

/// <summary>
/// Checks of <see cref="ImplantClassCapabilities"/> -- the per-class reduced
/// verb set the teamserver gates tasking on (architecture.md Sec 5.2). Each
/// class advertises the verbs its operational purpose justifies; a full
/// implant carries the full core set plus the tunnel set, the recon set, the
/// lateral set, the persist set, the collect set, and the exfil set, every
/// other class a subset (and no recon, lateral, persist, collect, or exfil
/// verbs) -- the pivot class carries exactly the tunnel set.
/// </summary>
public class ImplantClassCapabilitiesTests
{
    [Theory]
    [InlineData(ImplantClass.Implant, "shell.exec")]
    [InlineData(ImplantClass.Implant, "shell.interact")]
    [InlineData(ImplantClass.Implant, "file.push")]
    [InlineData(ImplantClass.Implant, "file.pull")]
    [InlineData(ImplantClass.Implant, "proc.kill")]
    [InlineData(ImplantClass.Implant, "tunnel.bind")]
    [InlineData(ImplantClass.Implant, "tunnel.forward")]
    [InlineData(ImplantClass.Implant, "tunnel.socks")]
    [InlineData(ImplantClass.Implant, "recon.portscan")]
    [InlineData(ImplantClass.Implant, "recon.hostenum")]
    [InlineData(ImplantClass.Implant, "recon.service")]
    [InlineData(ImplantClass.Implant, "recon.ps")]
    [InlineData(ImplantClass.Implant, "lateral.move")]
    [InlineData(ImplantClass.Implant, "lateral.token")]
    [InlineData(ImplantClass.Implant, "lateral.exec_remote")]
    [InlineData(ImplantClass.Implant, "persist.install")]
    [InlineData(ImplantClass.Implant, "persist.remove")]
    [InlineData(ImplantClass.Implant, "persist.list")]
    [InlineData(ImplantClass.Implant, "collect.cred")]
    [InlineData(ImplantClass.Implant, "collect.keylog")]
    [InlineData(ImplantClass.Implant, "collect.screenshot")]
    [InlineData(ImplantClass.Implant, "exfil.push")]
    [InlineData(ImplantClass.Implant, "exfil.stage")]
    [InlineData(ImplantClass.Implant, "module.load")]
    [InlineData(ImplantClass.Implant, "module.unload")]
    [InlineData(ImplantClass.Implant, "module.list")]
    [InlineData(ImplantClass.WebShell, "shell.exec")]
    [InlineData(ImplantClass.Ephemeral, "shell.exec")]
    [InlineData(ImplantClass.Pivot, "tunnel.bind")]
    [InlineData(ImplantClass.Pivot, "tunnel.forward")]
    [InlineData(ImplantClass.Pivot, "tunnel.socks")]
    [InlineData(ImplantClass.Browser, "browser.fingerprint")]
    [InlineData(ImplantClass.Browser, "browser.cookies")]
    [InlineData(ImplantClass.Browser, "browser.dom")]
    [InlineData(ImplantClass.Browser, "browser.screenshot")]
    [InlineData(ImplantClass.Browser, "browser.redirect")]
    [InlineData(ImplantClass.Browser, "browser.prompt")]
    public void Allows_AdmitsTheReducedVerbSetForTheClass(ImplantClass @class, string verb)
        => Assert.True(ImplantClassCapabilities.Allows(@class, verb));

    [Theory]
    [InlineData(ImplantClass.WebShell, "file.push", "a web-shell does not push")]
    [InlineData(ImplantClass.WebShell, "recon.hostenum", "recon is a long-haul class activity")]
    [InlineData(ImplantClass.WebShell, "lateral.token", "lateral movement is a long-haul class activity")]
    [InlineData(ImplantClass.WebShell, "persist.list", "persistence is a long-haul class activity")]
    [InlineData(ImplantClass.WebShell, "exfil.push", "collection and exfiltration are long-haul class activities")]
    [InlineData(ImplantClass.WebShell, "recon.ps", "process listing is a long-haul class activity")]
    [InlineData(ImplantClass.WebShell, "tunnel.forward", "tunneling joins the full class's core operations and the pivot set")]
    [InlineData(ImplantClass.WebShell, "module.load", "module support is the long-haul class's")]
    [InlineData(ImplantClass.Ephemeral, "file.push", "an ephemeral does not push")]
    [InlineData(ImplantClass.Ephemeral, "recon.service", "recon is a long-haul class activity")]
    [InlineData(ImplantClass.Ephemeral, "lateral.exec_remote", "lateral movement is a long-haul class activity")]
    [InlineData(ImplantClass.Ephemeral, "persist.remove", "persistence is a long-haul class activity")]
    [InlineData(ImplantClass.Ephemeral, "collect.cred", "collection and exfiltration are long-haul class activities")]
    [InlineData(ImplantClass.Ephemeral, "collect.screenshot", "collection and exfiltration are long-haul class activities")]
    [InlineData(ImplantClass.Ephemeral, "tunnel.forward", "tunneling joins the full class's core operations and the pivot set")]
    [InlineData(ImplantClass.Pivot, "shell.exec", "a pivot forwards, it does not shell")]
    [InlineData(ImplantClass.Pivot, "recon.portscan", "recon is a long-haul class activity")]
    [InlineData(ImplantClass.Pivot, "lateral.move", "lateral movement is a long-haul class activity")]
    [InlineData(ImplantClass.Pivot, "persist.install", "persistence is a long-haul class activity")]
    [InlineData(ImplantClass.Pivot, "exfil.stage", "collection and exfiltration are long-haul class activities")]
    [InlineData(ImplantClass.Browser, "shell.exec", "a hooked browser steers the page, it does not shell")]
    [InlineData(ImplantClass.Browser, "file.pull", "file transfer belongs to a process footprint, not a page")]
    [InlineData(ImplantClass.Browser, "recon.portscan", "recon is a long-haul class activity")]
    [InlineData(ImplantClass.Browser, "collect.cred", "credential collection is a long-haul class activity")]
    [InlineData(ImplantClass.Browser, "exfil.push", "exfiltration is a long-haul class activity")]
    [InlineData(ImplantClass.Browser, "module.load", "module support is the long-haul class's")]
    public void Allows_DeniesAVerbOutsideTheClassSet(ImplantClass @class, string verb, string rationale)
    {
        _ = rationale; // documents the case; not asserted.
        Assert.False(ImplantClassCapabilities.Allows(@class, verb));
    }

    [Fact]
    public void Allows_MatchesCaseInsensitively()
        => Assert.True(ImplantClassCapabilities.Allows(ImplantClass.Implant, "SHELL.EXEC"));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Allows_RejectsABlankVerb(string? verb)
        => Assert.False(ImplantClassCapabilities.Allows(ImplantClass.Implant, verb));

    [Fact]
    public void For_TheImplantClass_ReturnsTheFullCoreTunnelReconLateralPersistCollectExfilAndModuleSet()
    {
        // The Implant class is the primary long-haul one: it carries the full core set
        // plus the tunnel set, the recon set, the lateral set, the persist set,
        // the collect set, the exfil set, and the module family, since tunneling
        // is a core operation (architecture.md Sec 14), recon, lateral movement,
        // persistence, collection, and exfiltration are long-haul activities
        // (architecture.md Sec 5.2, Sec 10.1), and the plugin seam rides the
        // long-haul class alone (Sec 5.4). Every other class carries a subset
        // for its purpose.
        var verbs = ImplantClassCapabilities.For(ImplantClass.Implant);
        Assert.Equal(
            new[]
            {
                "shell.exec", "shell.interact", "file.push", "file.pull", "fs.list", "proc.kill",
                "beacon.sleep",
                "tunnel.bind", "tunnel.forward", "tunnel.socks",
                "recon.portscan", "recon.hostenum", "recon.service", "recon.ps",
                "lateral.move", "lateral.token", "lateral.exec_remote",
                "persist.install", "persist.remove", "persist.list",
                "collect.cred", "collect.keylog", "collect.screenshot",
                "collect.minidump",
                "inject.shellcode",
                "exfil.push", "exfil.stage",
                "module.load", "module.unload", "module.list",
            },
            verbs);
    }

    [Fact]
    public void For_ReturnsTheSharedSet_NotACopyPerCall()
    {
        // The same read-only reference is returned for a class, so callers
        // cannot mutate it and there is no per-call allocation.
        Assert.Same(
            ImplantClassCapabilities.For(ImplantClass.Implant),
            ImplantClassCapabilities.For(ImplantClass.Implant));
    }

    [Fact]
    public void Ungated_IsExactlyTheEvasionAndExploitContractVerbs()
    {
        // The contract-only verbs no class gates (architecture.md Sec 5.2,
        // Sec 10.2): the evasion and exploit categories in their entirety,
        // decided per deployment rather than per class.
        Assert.Equal(
            new[] { "evasion.avoid", "evasion.unload", "exploit.invoke", "exploit.module" },
            ImplantClassCapabilities.Ungated);
    }

    [Fact]
    public void Ungated_VerbsAppearInNoClassSet()
    {
        // The whole point of the ungated list: no class table entry carries any
        // of these verbs, so the only way a baked artifact may run one is the
        // ungated contract list riding along in the bake (the task gate admits
        // them through the registry-backed resolver instead, Sec 10.3).
        foreach (ImplantClass @class in Enum.GetValues(typeof(ImplantClass)))
        {
            foreach (var verb in ImplantClassCapabilities.Ungated)
                Assert.False(ImplantClassCapabilities.Allows(@class, verb));
        }
    }

    [Fact]
    public void For_EveryClassReturnsVerbs_PivotCarriesExactlyTheTunnelSet()
    {
        // Every class carries at least one verb. Pivot is the tunneling class
        // (architecture.md Sec 5.2): exactly the tunnel set -- enough to
        // forward traffic for hosts that cannot run their own implant and
        // front the chained contacts that ride it (Sec 5.2's implant-side
        // half), and nothing a long-haul full-class footprint justifies.
        foreach (ImplantClass @class in Enum.GetValues(typeof(ImplantClass)))
            Assert.NotEmpty(ImplantClassCapabilities.For(@class));
        Assert.Equal(
            new[] { "tunnel.bind", "tunnel.forward", "tunnel.socks" },
            ImplantClassCapabilities.For(ImplantClass.Pivot));
    }

    [Fact]
    public void For_TheBrowserClass_ReturnsExactlyTheHookSet()
    {
        // The hooked-browser class (architecture.md Sec 5.2, Sec 10.1): the
        // read-and-steer verbs a hooked page justifies, and nothing past
        // them -- input capture and browser-exploit chaining are out-of-tree
        // capability contracts, never core verbs.
        Assert.Equal(
            new[]
            {
                "browser.fingerprint", "browser.cookies", "browser.dom",
                "browser.screenshot", "browser.redirect", "browser.prompt",
            },
            ImplantClassCapabilities.For(ImplantClass.Browser));
    }
}
