using Rod.Audit;
using Rod.BuildPipeline.PayloadBuild;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Pki;
using Rod.Transport.Listeners;
using Rod.Transport.Listeners.Providers;

namespace Rod.Transport.Payloads;

/// <summary>
/// Shared parsing and validation for a payload-build request body: the wire
/// DTO (<see cref="Endpoints.PayloadEndpoints.BuildPayloadRequest"/>) into the
/// build pipeline's <see cref="BuildRequest"/>. Both build paths -- the
/// synchronous <c>POST /payloads</c> and the background
/// <c>POST /payload-jobs</c> -- accept the same body and must refuse the same
/// things, so the validation lives here once. Every refusal is an operator
/// mistake the build must not silently paper over (a payload that phones
/// nowhere, a low-and-slow ask built interactive).
/// </summary>
internal static class PayloadBuildRequestParser
{
    private static readonly TimeSpan DefaultSleep = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultJitter = TimeSpan.FromSeconds(10);

    // Upper bound for operator-supplied sleep/jitter: a beacon interval beyond a
    // year is nonsense, and an unbounded double would overflow
    // TimeSpan.FromSeconds into a 500. The clamp keeps the request a clean 4xx
    // class instead.
    private const double MaxDurationSeconds = 31_536_000; // 1 year

    /// <summary>
    /// Parses the body into a <see cref="BuildRequest"/>, or returns an error
    /// string naming the first refusal. Every cross-reference resolves
    /// against the payload store here so the build contract carries a verified
    /// reference, never a raw operator string; a named listener resolves to
    /// its public endpoint the same way. The teamserver's CA is baked into the
    /// profile as the pin the artifact's first contact validates against.
    /// A build against a wireguard listener also mints here: the per-artifact
    /// X25519 pair (the private half bakes, the public half registers on the
    /// listener's router) and the provisioned server key's public half --
    /// the material the transport layer alone holds.
    /// </summary>
    public static async Task<(BuildRequest? Request, string? Error)> ParseAsync(
        Endpoints.PayloadEndpoints.BuildPayloadRequest body,
        EngagementId engagementId,
        OperatorId requestedBy,
        IListenerRegistry listeners,
        IImplantCertificateAuthority ca,
        Rod.Audit.IPayloadStore payloads,
        CancellationToken cancellationToken,
        Listeners.WireGuard.WireGuardOptions? wireGuard = null,
        Listeners.WireGuard.WireGuardTunnelRegistry? wireGuardTunnels = null,
        bool mintWireGuard = true)
    {
        // Language and class come in as strings and parse to the enums; anything
        // that does not parse is a 400. The defaults keep a minimal request
        // valid (the in-tree Rust unit, an Implant-class build, linux/amd64).
        if (!TryParseLanguage(body.Language, out var language))
            return (null, "Language is not recognized.");
        // The stager class is retired with the .NET trees: delivery rides the
        // launcher one-liners (the disk families plus the in-memory memfd
        // family), which fetch the payload over the same token-gated route a
        // loader ever used. The refusal names the retired spelling before the
        // enum parse, which no longer knows it.
        if (string.Equals(body.Class?.Trim(), "stager", StringComparison.OrdinalIgnoreCase))
            return (null,
                "The stager class is retired; deliver the payload through the launcher one-liners (launchers render them per payload).");
        // The browser class's artifact is a rendered hook script the
        // teamserver itself serves (architecture.md Sec 5.2, Sec 8), not a
        // compiled build a unit produces -- the hooks mint renders it, so
        // the build contract refuses the spelling outright.
        if (string.Equals(body.Class?.Trim(), "browser", StringComparison.OrdinalIgnoreCase))
            return (null,
                "The browser class is a served hook script, not a compiled artifact; mint it through the engagement's hooks endpoint.");
        if (!TryParseClass(body.Class, out var @class))
            return (null, "Implant class is not recognized.");
        // The kind names the delivery tier: the implant (the default, the
        // full product) or the loader that fetches and runs a payload
        // from memory. The loader gates live below, after the endpoint
        // resolves -- they read the front the bake dials.
        if (!PayloadKinds.TryParse(body.Kind, out var kind))
            return (null, "Kind must be 'implant' (the default) or 'loader'.");
        // The format axis carries the deployment shapes (architecture.md
        // Sec 6). The in-tree Rust unit produces the executable spellings
        // for the desktop legs (synonyms over the same native binary) and
        // the android carrier's pair: 'so' (the bare library an
        // engagement's own carrier app loads) and 'apk' (the packaged
        // installable). The dll and shellcode shapes stay contract slots
        // -- the parser names them so a request can be refused with the
        // delivery story, not a bare parse error.
        if (!ArtifactFormats.TryParse(body.Format, out var format))
            return (null, "Format must be one of 'exe' (the default), 'exe-trimmed', 'aot', 'apk', 'dll', 'so', or 'shellcode'.");
        // The loader tier gates its own shape further down (a Linux
        // executable alone); these gates name the implant tier's answer.
        if (kind != PayloadKind.Loader)
        {
            var targetOs = (body.TargetOs ?? "linux").Trim().ToLowerInvariant();
            var isAndroid = targetOs == "android";
            if (format == ArtifactFormat.Apk && !isAndroid)
                return (null,
                    "The 'apk' format is the android carrier package; build an android target for it.");
            if (format == ArtifactFormat.SharedObject && !isAndroid)
                return (null,
                    "The 'so' format is the android carrier library; build an android target for it "
                    + "(the loader and injection deliveries on Unix stay contract slots).");
            if (format is ArtifactFormat.Dll or ArtifactFormat.Shellcode)
                return (null,
                    $"The '{ArtifactFormats.Name(format)}' format is a contract slot the in-tree Rust unit does not produce "
                    + "-- it names the loader and injection deliveries; build 'exe' or 'aot' for now.");
            if (isAndroid && format is not (ArtifactFormat.SharedObject or ArtifactFormat.Apk))
                return (null,
                    "An android target deploys through the carrier library or its package; build format 'so' or 'apk'.");
        }
        // The endpoint list is what the baked implant dials, so a malformed
        // entry must not reach the build: it would not fail there -- it would
        // produce a payload that phones nowhere, the silent kind of failure
        // an operator discovers on target. A named listener supplies the
        // endpoint from its own record, so an operator stops typing URLs.
        var endpoint = await ResolveEndpointAsync(
            body, engagementId, listeners, cancellationToken, wireGuard, wireGuardTunnels, mintWireGuard);
        if (endpoint.Error is { } refusal)
            return (null, refusal);
        if (endpoint.Value is { } dialable && !IsDialableEndpoint(dialable))
            return (null,
                $"Endpoint must be a schemed dial the implant can serve -- http(s)://, tcp://, dns://, or doh:// -- got '{dialable}'.");
        // The TLS trust posture is the front's fact, not the request's: the
        // named listener records whose certificate it presents (the
        // engagement CA, or a real-domain chain an operator-run edge
        // terminates), and the build inherits it as the roots it bakes
        // (architecture.md Sec 9). A typed DNS dial names no listener and
        // carries no TLS posture -- pinned stands. A request that still
        // spells a posture may only agree with the front; the knob moved to
        // the listener, and a contradiction here would bake roots the front
        // cannot verify against.
        var trust = endpoint.Trust ?? "pinned";
        if (body.Trust is { } asked && !string.IsNullOrWhiteSpace(asked))
        {
            var normalized = asked.Trim().ToLowerInvariant();
            if (normalized is not ("pinned" or "public"))
                return (null, "Trust must be 'pinned' or 'public'.");
            if (!string.Equals(normalized, trust, StringComparison.OrdinalIgnoreCase))
                return (null,
                    $"The front presents a '{trust}' certificate; set the posture on the listener, not the build "
                    + "-- a build's roots follow the certificate the front actually serves.");
        }

        if (body.FallbackEndpoints is { Count: > 0 } fallbacks)
        {
            var frontFamily = SchemeFamily(endpoint.Value);
            // Loaded only when an https fallback needs its front resolved;
            // the engagement's listener count is small either way.
            IReadOnlyList<Rod.Transport.Listeners.Listener>? fronts = null;
            foreach (var fallback in fallbacks)
            {
                if (string.IsNullOrWhiteSpace(fallback))
                    continue;
                if (!IsDialableEndpoint(fallback))
                    return (null,
                        $"Each fallback endpoint must be a schemed dial (http(s)://, tcp://, dns://, doh://), got '{fallback}'.");
                if (frontFamily is { } family && SchemeFamily(fallback) != family)
                    return (null,
                        $"Each fallback endpoint must dial the front's own scheme family -- the '{endpoint.Value}' front walks {FamilyShapes(family)} fallbacks only, got '{fallback}'.");
                // An https fallback walks under the same roots as the front:
                // the artifact bakes one root set, so a fallback presenting
                // the other certificate posture is a dead entry the family
                // check alone would pass. Only a dial that names one of this
                // engagement's listeners can be checked -- a typed address
                // (a redirector this teamserver cannot see) stays the
                // operator's call.
                if (frontFamily == "web"
                    && fallback.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    fronts ??= await listeners.ListAsync(cancellationToken);
                    var named = fronts.FirstOrDefault(l => NamesFront(fallback, l));
                    if (named is not null
                        && !string.Equals(named.TrustPosture, trust, StringComparison.OrdinalIgnoreCase))
                        return (null,
                            $"The fallback '{fallback}' names {named.Name}, a '{named.TrustPosture}' front, while this build rides '{trust}' roots -- pick fallbacks that share the front's certificate posture.");
                }
            }
        }

        // A public posture needs a TLS dial to ride: the primary or any
        // fallback must be https, where the front's publicly-trusted chain is
        // presented (an operator-run edge in front of the teamserver holds
        // the certificate for the real domain). The listener gate refuses
        // this pairing at creation, so reaching here means the endpoint
        // moved after the fact -- a repoint away from the https address.
        if (trust == "public"
            && endpoint.Value?.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase) != true
            && body.FallbackEndpoints?.Any(f =>
                f.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase)) != true)
            return (null,
                "This front's posture is 'public' but its dial is no longer https (a repoint moved it?) -- "
                + "point the listener back at the edge's https address, or set its posture to pinned.");

        // The contact mode rides the beacon profile into the artifact: stream
        // (persistent, interactive) or poll (low-and-slow contacts). Poll is
        // the default -- every family carries it, and a held connection is a
        // standing detection signal an operator should opt into, not out of.
        // A typo must not silently build the interactive shape for an
        // operator who asked for low-and-slow, so anything else is a 400.
        var mode = body.Mode?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(mode))
            mode = "poll";
        if (mode is not ("stream" or "poll"))
            return (null, "Mode must be 'stream' or 'poll'.");

        // The contact the baked artifact runs derives from the enroll front:
        // an http(s) front carries the envelope POST cycle or the WebSocket
        // stream on its own port (the baked mode picks the client), the
        // socket family the held-or-cycled connection, and the DNS family
        // its TXT poll -- a datagram exchange with no stream to hold, so a
        // stream-mode build against a DNS front is refused rather than baked
        // as a contact the family cannot serve.
        if (TypedPollOnlyScheme(endpoint.Value) is { } typedCarrier && mode != "poll")
            return (null,
                $"The {typedCarrier} carrier is one-answer-one-poll; build it mode 'poll' "
                + "(the interactive verbs ride the polls store-and-forward), or name a web front for a live stream.");
        if (endpoint.Transport is "dns" or "doh" or "wireguard" && mode != "poll")
            return (null,
                $"The {endpoint.Transport} carrier is one-answer-one-poll; build it mode 'poll' "
                + "(the interactive verbs ride the polls store-and-forward), or name a web front for a live stream.");

        // The wireguard carriage ships in the Rust reference implant behind
        // its cargo feature; a build in another language against a
        // wireguard listener would bake a dial that implant cannot serve.
        // A community unit that ports the carriage reopens the pairing.
        if (endpoint.WireGuard is { } && language != Language.Rust)
            return (null,
                "The wireguard carriage ships in the Rust reference implant; build language 'rust' "
                + "against a wireguard listener.");

        // The baked token's scope rides the same request: how many implants
        // the artifact's credential may enroll (0 = unlimited), and how long
        // the mint stays redeemable. Absent values default at mint time
        // (single use, the artifact's kill window).
        if (body.TokenMaxUses is < 0 or > 10_000)
            return (null, "TokenMaxUses must be between 0 (unlimited) and 10000.");
        if (body.TokenLifetimeSeconds is < 60 or > 2_592_000)
            return (null, "TokenLifetimeSeconds must be between 60 and 2592000 (30 days).");

        // The kill date is the artifact's optional time fuse. A pinned date in
        // the past can only be a mistake -- the artifact would refuse to run
        // the moment it landed -- so it is refused here rather than silently
        // baked; unset means open-ended (no fuse).
        if (body.KillDate is { } pinned && pinned <= DateTimeOffset.UtcNow)
            return (null, "KillDate must be in the future; leave it empty for an open-ended artifact.");

        // The loader tier's own gates. The loader is a no_std dialer
        // by design (architecture.md Sec 6, staging): it speaks plain HTTP
        // to a literal IPv4, carries no TLS and no resolver, and runs on the
        // two Linux arches its crate compiles. Every refusal names the shape
        // it wants rather than failing inside cargo with less to act on.
        if (kind == PayloadKind.Loader)
        {
            if (language != Language.Rust)
                return (null, "The loader tier is the in-tree Rust unit's artifact; set language to Rust or leave it empty.");
            if (format is not (ArtifactFormat.SingleFileExe or ArtifactFormat.TrimmedExe or ArtifactFormat.NativeAot))
                return (null, "The loader is a native executable; build it with the default 'exe' format.");
            var os = (body.TargetOs ?? "linux").Trim().ToLowerInvariant();
            var arch = (body.TargetArch ?? "amd64").Trim().ToLowerInvariant();
            if (os != "linux")
                return (null,
                    "The loader is a Linux memfd shape; a Windows or Android target delivers through its own artifact (the launcher one-liners, the carrier package).");
            if (arch is not ("amd64" or "x64" or "x86_64" or "arm64" or "aarch64"))
                return (null, "The loader compiles for linux amd64 and arm64 only.");
            // The dial: cleartext HTTP on a literal IPv4. A hostname needs a
            // resolver and an https front needs TLS -- both implant-tier
            // machinery this tier refuses to carry. The stage rides sealed
            // under the per-build key, the same posture as the cleartext
            // contact, so the plain transport costs nothing but leaves the
            // front's spelling narrow on purpose.
            if (!endpoint.Value!.Trim().StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                return (null,
                    "The loader dials a cleartext http front (no TLS in the tier); pick an http listener.");
            // The stage reference: this engagement's own stored payload, and
            // not another loader -- the loader delivers the implant tier,
            // and a chain of dialers is a footprint, not a capability.
            if (body.DeliversPayloadId is not { } deliversText)
                return (null, "A loader build names the stored payload it delivers (deliversPayloadId).");
            if (!Guid.TryParse(deliversText, out var deliversValue))
                return (null, "DeliversPayloadId is not a valid identifier.");
            var delivered = await payloads.FindAsync(deliversValue, engagementId.Value, cancellationToken);
            if (delivered is null)
                return (null, "DeliversPayloadId does not name a payload in this engagement.");
            if (delivered.DeliversPayloadId is not null)
                return (null, "DeliversPayloadId names a loader; the loader delivers the implant tier, not another loader.");
            return (new BuildRequest(
                engagementId,
                requestedBy,
                language,
                @class,
            new TargetProfile(body.TargetOs ?? "linux", body.TargetArch ?? "amd64"),
            BuildTransport(body, endpoint.Value!, ExportCaPem(ca),
                trust == "public" ? TlsTrust.Public : TlsTrust.Pinned),
            ParseDuration(body.SleepSeconds, DefaultSleep),
            ParseDuration(body.JitterSeconds, DefaultJitter),
            body.KillDate,
            mode,
            Format: format,
            Kind: kind,
            DeliversPayloadId: deliversValue,
            WireGuardPrivateKey: endpoint.WireGuard?.ArtifactPrivate,
            WireGuardArtifactPublicKey: endpoint.WireGuard?.ArtifactPublic,
            WireGuardServerPublicKey: endpoint.WireGuard?.ServerPublic), null);
        }

        // The loader class retired with the .NET trees, so no build carries a
        // fetched-payload reference anymore; a request naming one is a leftover from
        // the retired flow and is refused with the current delivery answer.
        if (body.Stage2PayloadId is not null)
        {
            return (null,
                "stage2PayloadId rides the retired stager vocabulary; the staged answer is the loader tier "
                + "(kind 'loader' with deliversPayloadId), or the launcher one-liners for a plain fetch.");
        }
        return (new BuildRequest(
            engagementId,
            requestedBy,
            language,
            @class,
            new TargetProfile(body.TargetOs ?? "linux", body.TargetArch ?? "amd64"),
            // Non-null by construction: every resolution path either returns
            // a dial or an error, and the error returned above.
            BuildTransport(body, endpoint.Value!, ExportCaPem(ca),
                trust == "public" ? TlsTrust.Public : TlsTrust.Pinned),
            ParseDuration(body.SleepSeconds, DefaultSleep),
            ParseDuration(body.JitterSeconds, DefaultJitter),
            body.KillDate,
            mode,
            Format: format,
            WireGuardPrivateKey: endpoint.WireGuard?.ArtifactPrivate,
            WireGuardArtifactPublicKey: endpoint.WireGuard?.ArtifactPublic,
            WireGuardServerPublicKey: endpoint.WireGuard?.ServerPublic), null);
    }

    // Exports the teamserver CA as the PEM the artifact pins: the implant's
    // enroll client validates the server it dials against this anchor (the
    // dev CA is self-signed and in no system store; a production CA is
    // known only to this teamserver).
    private static string ExportCaPem(IImplantCertificateAuthority ca)
    {
        var der = ca.GetCaCertificate().Export(
            System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
        return "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END CERTIFICATE-----\n";
    }

    // Resolves the endpoint the baked artifact dials: the listener's public
    // endpoint when the request names one (refusing anything that is not
    // this engagement's own listener), the DNS family's typed dial
    // otherwise -- the fronting seam a listener record cannot yet express.
    // The refusal is returned as a string; the value is null only when the
    // error is set. Transport reports the named listener's transport (null
    // for a typed dial) -- the fact the beacon resolution below needs, so
    // a derived contact matches the front it rides. WireGuard carries the
    // minted per-artifact pair and the listener's server key beside the
    // dial (null on every other family).
    private static async Task<(string? Value, string? Transport, string? Trust, WireGuardMaterial? WireGuard, string? Error)> ResolveEndpointAsync(
        Endpoints.PayloadEndpoints.BuildPayloadRequest body,
        EngagementId engagementId,
        IListenerRegistry listeners,
        CancellationToken cancellationToken,
        Listeners.WireGuard.WireGuardOptions? wireGuard = null,
        Listeners.WireGuard.WireGuardTunnelRegistry? wireGuardTunnels = null,
        bool mintWireGuard = true)
    {
        if (body.ListenerId is not { } listenerIdText)
        {
            var typed = body.Endpoint?.Trim();
            // The typed DNS dial is gone: fronting a dns or doh listener is
            // the front list's job now -- the primary front names the
            // resolver implants dial, the listener's record keeps the zone
            // (architecture.md Sec 8). A typed address this teamserver
            // cannot verify only ever baked an artifact that might never
            // enroll; the front is the verifiable shape.
            if (string.IsNullOrEmpty(typed))
                return (null, null, null, null, "Name a listener for the front the implant dials.");
            return (null, null, null, null,
                "A typed endpoint names nothing this teamserver can verify -- name a listener. " +
                "Fronting a dns or doh listener is its front list's job: attach a front and the " +
                "baked dial derives from it.");
        }

        if (body.Endpoint is not null)
            return (null, null, null, null, "Name either listenerId or endpoint, not both.");
        if (!Guid.TryParse(listenerIdText, out var listenerValue))
            return (null, null, null, null, "ListenerId is not a valid identifier.");

        var listener = await listeners.FindAsync(new ListenerId(listenerValue), cancellationToken);
        if (listener is null)
            return (null, null, null, null, "ListenerId does not name a listener.");
        if (listener.EngagementId is null)
            return (null, null, null, null,
                "ListenerId names a shared-tier listener; an implant dials its own engagement's listener.");
        if (listener.EngagementId != engagementId)
            return (null, null, null, null, "ListenerId names another engagement's listener.");

        // The socket family's enroll arm (Sec 8, enrollment over the stream
        // contact): a tcp listener is enroll-nameable -- the opening exchange
        // on the socket carries the EnrollRequest frames -- and the baked
        // endpoint is the transport's own dial: the host:port under tcp://.
        if (listener.Transport == "tcp")
            return WithTrust(SocketDial(listener.PublicEndpoint), listener.TrustPosture);

        // The optional WireGuard transport's build material (Sec 8, Sec 15.3
        // ADR-004 as amended): the dial is the listener's host:port under
        // wg://, and the build mints its per-artifact X25519 pair here --
        // the private half bakes, the public half registers on the
        // listener's router as the peer whose tunnel sessions the artifact's
        // contacts ride, and the provisioned server key's public half rides
        // beside as the peer the artifact initiates against.
        if (listener.Transport == "wireguard")
        {
            var minted = MintWireGuard(listener, wireGuard, wireGuardTunnels, mintWireGuard);
            if (minted.Error is { } wgError)
                return (null, null, null, null, wgError);
            return (Listeners.WireGuard.WireGuardDial.Of(listener), "wireguard", listener.TrustPosture, minted.Material, null);
        }

        // The DNS family's enroll arm (Sec 8, enrollment over DNS -- the
        // full-independence step for a DNS-only target): the enroll body
        // uploads as chunked TXT queries and the answer chunks back down,
        // so a dns or doh listener is enroll-nameable -- a wildcard bind
        // names no resolver an implant can dial.
        if (listener.Transport is "dns" or "doh")
        {
            var dial = DnsDial(listener);
            if (dial.Error is { } dnsError)
                return (null, null, null, null, dnsError);
            return (dial.Dial, listener.Transport, listener.TrustPosture, null, null);
        }

        if (TransportProviders.Find(listener.Transport) is not KestrelEndpointProvider)
            return (null, null, null, null,
                $"The {listener.Transport} transport does not serve enrollment; build against an HTTP-shaped listener.");

        // The public endpoint may be the bare host:port redirector shape; the
        // listener's transport names the scheme the implant dials.
        var publicEndpoint = listener.PublicEndpoint.Trim();
        if (Uri.TryCreate(publicEndpoint, UriKind.Absolute, out var absolute)
            && (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps))
            return (publicEndpoint, listener.Transport, listener.TrustPosture, null, null);
        var scheme = TransportProviders.Find(listener.Transport)?.PublicEndpointScheme ?? "https";
        return ($"{scheme}://{publicEndpoint}", listener.Transport, listener.TrustPosture, null, null);
    }

    // The per-artifact WireGuard material a wireguard build mints and
    // carries: the artifact's private half (bakes into the profile), its
    // public half (registers on the listener's router, records on the
    // stored payload so a restart re-registers), and the listener's
    // provisioned server key as its public half (the peer the artifact's
    // tunnel initiates against).
    private sealed record WireGuardMaterial(
        byte[] ArtifactPrivate, byte[] ArtifactPublic, byte[] ServerPublic);

    // Mints one build's WireGuard pair and registers the public half on the
    // listener's router. The refusals name the deployment fixes: no enabled
    // transport, no provisioned key under the listener's name, no live
    // router to register on (the listener's socket is what keeps one). The
    // validation shape (mint false) checks the deployment's readiness and
    // resolves the dial without minting -- a stored build profile parsed at
    // creation time must not register a peer whose private half is
    // discarded: the router matches handshakes by bounded trial decryption
    // over its whole peer set, so dead peers tax every live handshake.
    private static (WireGuardMaterial? Material, string? Error) MintWireGuard(
        Rod.Transport.Listeners.Listener listener,
        Listeners.WireGuard.WireGuardOptions? options,
        Listeners.WireGuard.WireGuardTunnelRegistry? tunnels,
        bool mint)
    {
        if (options is null || tunnels is null)
            return (null, "The WireGuard transport is not enabled on this teamserver.");
        if (options.TryPrivateKey(listener.Name) is not { } serverPrivate)
            return (null,
                $"Listener '{listener.Name}' carries no provisioned WireGuard server key; provision its base64 "
                + $"X25519 private key under WireGuard:ListenerKeys:{listener.Name} before building against it.");
        if (!mint)
            return (null, null);
        var artifactPrivate = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var artifactPublic = Listeners.WireGuard.WireGuardNative.PublicKey(artifactPrivate);
        var serverPublic = Listeners.WireGuard.WireGuardNative.PublicKey(serverPrivate);
        try
        {
            tunnels.RegisterPeer(listener.Id, artifactPublic);
        }
        catch (InvalidOperationException ex)
        {
            return (null,
                $"The wireguard listener '{listener.Name}' did not accept the build's peer registration: {ex.Message}");
        }
        return (new WireGuardMaterial(artifactPrivate, artifactPublic, serverPublic), null);
    }

    // Threads the socket family's dial through the five-part resolution (a
    // raw-TCP front carries no TLS posture -- its dial is cleartext -- but
    // the listener's record still names one, and the build reads it).
    private static (string? Value, string? Transport, string? Trust, WireGuardMaterial? WireGuard, string? Error) WithTrust(
        (string? Value, string? Transport, WireGuardMaterial? WireGuard, string? Error) socket, string? trust)
        => (socket.Value, socket.Transport, trust, socket.WireGuard, socket.Error);

    // Builds the malleable transport profile off the request body
    // (architecture.md Sec 7). Endpoint and uri path are the always-set
    // positional fields; the malleable knobs default when the operator omits
    // them, so a minimal build request stays valid. Headers arrive as a flat
    // name/value map and are applied verbatim; an empty or null map adds none.
    private static TransportProfile BuildTransport(
        Endpoints.PayloadEndpoints.BuildPayloadRequest body,
        string endpoint,
        string caPem,
        TlsTrust tlsTrust)
    {
        var profile = new TransportProfile(
            endpoint,
            body.UriPath ?? "/beacon")
        {
            // The pinned teamserver CA rides every build.
            CaPem = caPem,
            // Which roots the TLS dials trust: the CA above alone, or the
            // public set for a real-domain front.
            TlsTrust = tlsTrust,
        };

        if (!string.IsNullOrWhiteSpace(body.EnrollPath))
            profile = profile with { EnrollPath = body.EnrollPath };
        if (!string.IsNullOrWhiteSpace(body.UserAgent))
            profile = profile with { UserAgent = body.UserAgent };
        if (body.Headers is { Count: > 0 } headers)
            profile = profile with { Headers = headers };
        if (body.RequestTimeoutSeconds is { } timeoutSeconds and >= 0)
            profile = profile with { RequestTimeout = TimeSpan.FromSeconds(timeoutSeconds) };
        if (body.Envelope is { } envelope
            && Enum.TryParse<TransportEnvelope>(envelope, ignoreCase: true, out var parsed))
        {
            profile = profile with { Envelope = parsed };
        }
        // Contact protection is its own knob, independent of the enroll-body
        // envelope (architecture.md Sec 8/9): on by default, and only an
        // explicit opt-out rides -- the lab-debug plaintext frame.
        if (body.ContactProtection is false)
            profile = profile with { ContactProtection = false };
        if (body.FallbackEndpoints is { Count: > 0 } fallbacks)
        {
            // The fallback list is the egress walk order (architecture.md Sec 8):
            // blanks are dropped rather than rejected so a trailing separator in
            // an operator's list is not a 400, and the surviving order is baked
            // verbatim.
            var cleaned = fallbacks
                .Where(f => !string.IsNullOrWhiteSpace(f))
                .Select(f => f.Trim())
                .ToArray();
            if (cleaned.Length > 0)
                profile = profile with { FallbackEndpoints = cleaned };
        }

        return profile;
    }

    // Case-insensitive enum parse off the request string, with a fallback when
    // the field is absent so a minimal request stays valid.
    private static bool TryParseLanguage(string? text, out Language language)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            language = Language.Rust; // the in-tree reference unit is Rust (Sec 12.2).
            return true;
        }
        return Enum.TryParse(text, ignoreCase: true, out language);
    }

    private static bool TryParseClass(string? text, out ImplantClass @class)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            @class = ImplantClass.Implant;
            return true;
        }
        return Enum.TryParse(text, ignoreCase: true, out @class);
    }

    private static TimeSpan ParseDuration(double? seconds, TimeSpan fallback)
        => seconds is { } value && value >= 0
            ? TimeSpan.FromSeconds(Math.Min(value, MaxDurationSeconds))
            : fallback;


    // An endpoint the implant can dial: an absolute http(s) URL, or the
    // socket, DNS, and WireGuard families' dials (architecture.md Sec 8 --
    // a tcp-, dns-, doh-, or wg-schemed enroll endpoint runs the frame,
    // chunk, or tunnel exchange its module dials, and the egress walk
    // treats every entry as a URL). A bare host or a typo'd scheme strands
    // the payload on target.
    private static bool IsDialableEndpoint(string text)
        => Uri.TryCreate(text.Trim(), UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp
                || uri.Scheme == Uri.UriSchemeHttps
                || uri.Scheme.Equals("tcp", StringComparison.OrdinalIgnoreCase)
                || uri.Scheme.Equals("dns", StringComparison.OrdinalIgnoreCase)
                || uri.Scheme.Equals("doh", StringComparison.OrdinalIgnoreCase)
                || uri.Scheme.Equals("wg", StringComparison.OrdinalIgnoreCase));

    // The egress-walk families (architecture.md Sec 8): the web pair, the
    // DNS pair, the raw socket, and the WireGuard tunnel. One build rides
    // one protocol -- the fallback list is the front's own family in walk
    // order, never a mix, and the TLS posture spans the walk (the artifact
    // bakes one root set) -- so a cross-family entry is refused rather
    // than baked.
    private static string? SchemeFamily(string? endpoint)
    {
        var trimmed = endpoint?.Trim();
        if (trimmed is null || trimmed.Length == 0)
            return null;
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return "web";
        if (trimmed.StartsWith("dns://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("doh://", StringComparison.OrdinalIgnoreCase))
            return "dns";
        if (trimmed.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
            return "tcp";
        if (trimmed.StartsWith("wg://", StringComparison.OrdinalIgnoreCase))
            return "wg";
        return null;
    }

    // Whether a web-family dial names this listener: verbatim, or completed
    // under the transport's scheme -- the two shapes the picker bakes.
    private static bool NamesFront(string fallback, Rod.Transport.Listeners.Listener listener)
    {
        var trimmed = fallback.Trim();
        if (string.Equals(trimmed, listener.PublicEndpoint.Trim(), StringComparison.OrdinalIgnoreCase))
            return true;
        var scheme = listener.Transport is "https" or "mtls" ? "https" : "http";
        return string.Equals(trimmed, $"{scheme}://{listener.PublicEndpoint.Trim()}", StringComparison.OrdinalIgnoreCase);
    }

    // The shapes one family's fallbacks dial, for a refusal that teaches.
    private static string FamilyShapes(string family) => family switch
    {
        "web" => "http(s)://",
        "dns" => "dns:// or doh://",
        "tcp" => "tcp://",
        "wg" => "wg://",
        _ => "the front's scheme",
    };

    // The DNS carrier a typed endpoint's scheme names, so a stream-mode
    // build cannot bake a datagram poll. The socket schemes are absent:
    // both their shapes bake.
    private static string? TypedPollOnlyScheme(string? endpoint)
    {
        var trimmed = endpoint?.Trim();
        if (trimmed is null || trimmed.Length < 7)
            return null;
        foreach (var scheme in new[] { "dns://", "doh://" })
        {
            if (trimmed.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
                return scheme[..^3];
        }
        return null;
    }

    // The DNS family's baked dial (Sec 8), shared by the enroll and beacon
    // arms: the listener's own bind as the resolver plus its zone, the dial
    // shape the implant's DNS client parses. A wildcard bind names no
    // dialable resolver, so it is refused with the fix rather than baked as
    // one.
    private static (string? Dial, string? Error) DnsDial(Rod.Transport.Listeners.Listener listener)
    {
        var scheme = listener.Transport == "doh" ? "doh" : "dns";
        var zone = listener.PublicEndpoint.Trim().TrimEnd('.').ToLowerInvariant();
        if (zone.Length == 0)
            return (null, $"A {scheme} listener carries no zone in its public endpoint; the zone is the dial's other half.");

        // The primary front names the resolver implants dial (architecture.md
        // Sec 8): an enrolled node the control plane provisions, whose
        // address is the front's own public endpoint -- the zone stays the
        // listener record's.
        if (listener.Fronts.FirstOrDefault() is { } front)
            return ($"{scheme}://{front.PublicEndpoint.Trim()}/{zone}", null);

        var bind = listener.BindAddress.Trim();
        if (bind.StartsWith("0.0.0.0:") || bind.StartsWith("[::]:") || bind.StartsWith(":::"))
            return (null,
                $"A wildcard-bound {scheme} listener names no resolver an implant can dial; bind it "
                + "to a concrete interface, or attach a front (an enrolled redirector node) whose "
                + $"address implants dial -- the front is the {scheme} family's fronting shape.");
        return ($"{scheme}://{bind}/{zone}", null);
    }

    // The socket family's baked dial (Sec 8, enrollment over the stream
    // contact): the raw-TCP listener's host:port public endpoint completes
    // under tcp://.
    private static (string? Value, string? Transport, WireGuardMaterial? WireGuard, string? Error) SocketDial(string publicEndpoint)
    {
        var trimmed = publicEndpoint.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var dial) && dial.Scheme == "tcp")
            return (trimmed, "tcp", null, null);
        return ($"tcp://{trimmed}", "tcp", null, null);
    }
}
