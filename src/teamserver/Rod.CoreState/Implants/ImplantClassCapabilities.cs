using Rod.CoreState.Engagements;

namespace Rod.CoreState.Implants;

/// <summary>
/// The reduced capability verb set each <see cref="ImplantClass"/> may run
/// (architecture.md Sec 5.2). Implants differ by operational purpose, not by a
/// "device flavor": a web-shell executes over HTTP but holds no tunnel, an
/// ephemeral is one-shot, and a pivot forwards traffic for hosts that cannot
/// run their own implant. The Implant class carries the full core set plus
/// the tunnel set, the recon set, the lateral set, the persist set, the
/// collect set, and the exfil set; tunneling joins the Implant class's core
/// operations, and recon, lateral movement, persistence, collection,
/// and exfiltration are long-haul activities. These sets are
/// the server's authority for what a class is allowed
/// to do: task issuance gates on them (architecture.md Sec 10.3), and the build
/// pipeline bakes them into each artifact so the generated payload is
/// self-describing.
/// </summary>
/// <remarks>
/// The values live in core state -- the inner ring both the build pipeline and
/// the capabilities layer may depend on -- so the rule is defined once and read by
/// every layer that needs it, without a cross-layer dependency. The standard,
/// documented categories run concrete handlers on the reference implant; the
/// sensitive categories (Sec 13) stay contract-only in this repository.
/// </remarks>
public static class ImplantClassCapabilities
{
    /// <summary>
    /// The verbs a class of implant is permitted to run. The Implant class carries the
    /// full core set plus the recon set, the lateral set, the persist set, the
    /// collect set, and the exfil set; every other class carries the subset its
    /// operational purpose justifies (architecture.md Sec 5.2). Stored read-only
    /// and case-normalized so <see cref="Allows"/> can match case-insensitively
    /// without re-allocating.
    /// </summary>
    private static readonly IReadOnlyDictionary<ImplantClass, IReadOnlyList<string>> ByClass =
        new Dictionary<ImplantClass, IReadOnlyList<string>>
        {
            // The primary long-haul implant: the whole core baseline plus the
            // tunnel set, the recon set, the lateral set, the persist set, the
            // collect set, and the exfil set (architecture.md Sec 10.1, Sec 14).
            // Tunneling is a core operation, and recon, lateral movement,
            // persistence, collection, and exfiltration are all long-haul
            // activities that justify a long-haul footprint and no other class.
            [ImplantClass.Implant] = new[]
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

            // A script in a web root: code execution over HTTP, no file transfer
            // and no interactive PTY.
            [ImplantClass.WebShell] = new[] { "shell.exec" },

            // A short-lived, TTL'd implant from a one-liner bootstrap: enough for
            // one-off execution and nothing more.
            [ImplantClass.Ephemeral] = new[] { "shell.exec" },

            // The tunneling class: an artifact that represents hosts which
            // cannot run their own implant (network/OT gear) and forwards their
            // traffic (architecture.md Sec 5.2). It carries exactly the tunnel
            // set -- a pivot forwards, it does not shell -- so a Pivot-class
            // build is the minimal tunneling artifact and nothing else. The
            // set includes the chain bind (Sec 5.2's pivot-model implant-side
            // half): fronting chained contacts is the seat a pivot exists to
            // hold.
            [ImplantClass.Pivot] = new[] { "tunnel.bind", "tunnel.forward", "tunnel.socks" },

            // The hooked-browser class (architecture.md Sec 5.2, Sec 10.1):
            // the read-and-steer verbs a hooked page justifies. Everything
            // past them -- input capture, browser-exploit chaining -- arrives
            // as an out-of-tree capability contract, never a core verb.
            [ImplantClass.Browser] = new[]
            {
                "browser.fingerprint", "browser.cookies", "browser.dom",
                "browser.screenshot", "browser.redirect", "browser.prompt",
            },
        };

    /// <summary>
    /// The verbs <paramref name="class"/> is permitted to run, in declared
    /// order. Returned read-only so callers cannot mutate the shared set.
    /// </summary>
    public static IReadOnlyCollection<string> For(ImplantClass @class)
        => ByClass[@class];

    /// <summary>
    /// The contract-only verbs no class gates (architecture.md Sec 5.2, Sec
    /// 10.2): the evasion and exploit categories in their entirety. Which class
    /// runs one is decided when an operator deploys the out-of-tree module, not
    /// by a baked-in class rule, so they sit outside the per-class table. The
    /// build pipeline bakes them alongside the class set so an artifact that
    /// carries an out-of-tree handler advertises the verb at handshake; the
    /// advertised set is still the baked verbs intersected with the compiled
    /// handlers (architecture.md Sec 5.3), so an artifact without the handler
    /// never claims the verb.
    /// </summary>
    public static readonly IReadOnlyList<string> Ungated = new[]
    {
        "evasion.avoid", "evasion.unload", "exploit.invoke", "exploit.module",
    };

    /// <summary>
    /// Whether any class's reduced set carries <paramref name="verb"/>: the verb
    /// is class-gated (architecture.md Sec 5.2) and only the classes whose set
    /// lists it may run it. Verbs no class gates -- the ungated contract set,
    /// and brand-new verbs an out-of-tree module registers -- answer false,
    /// which is what lets the registry-backed resolver widen dispatch for
    /// exactly those (Sec 10.3) without re-gating a verb another class owns.
    /// Verb matching is case-insensitive, matching <see cref="Allows"/>.
    /// </summary>
    public static bool GatedToAnyClass(string? verb)
    {
        if (string.IsNullOrWhiteSpace(verb))
            return false;

        foreach (var set in ByClass.Values)
        {
            for (var i = 0; i < set.Count; i++)
            {
                if (string.Equals(set[i], verb, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Whether <paramref name="class"/> may run <paramref name="verb"/>. Verb
    /// matching is case-insensitive: capability verbs are namespaced strings
    /// (<c>namespace.action</c>) and the registry already resolves them that way.
    /// An empty or whitespace verb is never allowed -- the task entity requires a
    /// verb, and a class advertising nothing cannot run a blank one.
    /// </summary>
    public static bool Allows(ImplantClass @class, string? verb)
    {
        if (string.IsNullOrWhiteSpace(verb))
            return false;

        var set = ByClass[@class];
        for (var i = 0; i < set.Count; i++)
        {
            if (string.Equals(set[i], verb, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
