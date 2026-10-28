using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;

namespace Rod.BuildPipeline.PayloadBuild;

/// <summary>
/// The payload-build request schema -- the teamserver half of the build contract
/// (architecture.md Sec 6). Carries everything a build unit needs to compile a
/// self-contained, per-implant artifact: the engagement and operator it is
/// scoped and attributed to, the implant class, the target OS/arch, and the
/// transport and beacon profiles.
///
/// The per-implant material is the baked profile itself: each artifact is
/// unique because its profile is, and a lost implant self-terminates at its
/// kill date. No key material crosses this contract -- the implant's
/// cryptographic identity is the keypair it generates at first run, bound by
/// the CA-signed leaf at enroll (architecture.md Sec 9). The build contract is
/// the language-neutrality boundary, so a build unit consumes these params
/// without any teamserver-language coupling.
/// </summary>
/// <param name="TokenSecret">
/// The enrollment credential baked into the artifact's profile: the artifact
/// deploys with zero run-time arguments, the token spends itself at enroll,
/// and the operator never handles the plaintext. Null keeps the artifact
/// credential-free (the manual-mint shape: the secret rides run-time flags).
/// A deployment credential, not key material -- the implant's cryptographic
/// identity is still the keypair it generates at first run.
/// </param>
/// <param name="TokenId">
/// The minted token's id, for reporting and revocation. Never baked; build
/// units ignore it.
/// </param>
/// <param name="EnvelopeKeyId">
/// The id of the per-artifact AES-GCM envelope key, minted with the token when
/// the profile's envelope is <c>AesGcm</c>. Baked beside the key so the
/// teamserver can find its half of the pair; null on every other envelope.
/// </param>
/// <param name="EnvelopeKey">
/// The per-artifact AES-256 envelope key itself: baked into the artifact (the
/// implant encrypts its enroll body with it) and recorded beside the stored
/// payload (the teamserver decrypts with it). Null on every other envelope.
/// </param>
/// <param name="Format">
/// The artifact form factor the unit emits for this build (architecture.md
/// Sec 6): the single-file executable default, the trimmed executable, the
/// native AOT binary, or the shared/shellcode shapes the contract carries
/// for loader and injection deliveries. Defaults to the single-file
/// executable -- the shape every build produced before the format axis
/// existed.
/// </param>
/// <param name="Kind">
/// Which tier of the delivery stack this build produces: the implant (the
/// default, the full product) or the loader that fetches and runs a
/// stage from memory. Defaults to the implant.
/// </param>
/// <param name="DeliversPayloadId">
/// The stored payload this loader build delivers: the loader bakes the
/// fetch reference, and the fetch route serves this artifact's bytes sealed
/// under the build's <c>EnvelopeKey</c> pair (the stage seal -- on a loader
/// build that pair is the seal, minted unconditionally). Null on every
/// implant build; required on every loader build.
/// </param>
/// <param name="WireGuardPrivateKey">
/// The artifact's WireGuard X25519 private half (32 bytes), minted per
/// artifact by a build against a wireguard listener and baked into the
/// profile; its public counterpart registers on the listener's router and
/// rides <paramref name="WireGuardArtifactPublicKey"/> for the stored
/// payload record. Null on every non-wireguard build.
/// </param>
/// <param name="WireGuardServerPublicKey">
/// The wireguard listener's provisioned server key, public half (32
/// bytes) -- the peer the artifact's tunnel initiates against. Null on
/// every non-wireguard build.
/// </param>
public sealed record BuildParams(
    EngagementId EngagementId,
    OperatorId RequestedBy,
    ImplantClass Class,
    TargetProfile Target,
    TransportProfile Transport,
    BeaconProfile Beacon,
    string? TokenSecret = null,
    Guid? TokenId = null,
    int? TokenMaxUses = null,
    Guid? EnvelopeKeyId = null,
    byte[]? EnvelopeKey = null,
    ArtifactFormat Format = ArtifactFormat.SingleFileExe,
    PayloadKind Kind = PayloadKind.Implant,
    Guid? DeliversPayloadId = null,
    byte[]? WireGuardPrivateKey = null,
    byte[]? WireGuardArtifactPublicKey = null,
    byte[]? WireGuardServerPublicKey = null,
    IReadOnlyList<ExtensionOverlay>? Extensions = null);
