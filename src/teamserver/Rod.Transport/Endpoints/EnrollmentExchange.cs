using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Campaigns;
using Rod.CoreState.Deployment;
using Rod.Transport.Listeners;
using Rod.Transport.Payloads;
using Rod.V1;

namespace Rod.Transport.Endpoints;

// The JSON enroll exchange, split from its HTTP route (architecture.md
// Sec 8) the same way the envelope contact core split from its own: the
// body shapes (raw JSON, base64-wrapped, AES-GCM-wrapped), the public-key
// gate, the shared scoped flow, and the outcome marshal live here, while
// the route owns routing and CORS and the listener bridge's route-forward
// carriage owns its socket and calls this exchange with the listener it
// already knows -- no local port to resolve, the scope is the peer.

/// <summary>
/// One enroll request's answer, in the route's own wire vocabulary: the
/// HTTP status and the JSON body bytes (camelCase, web defaults -- the
/// same bytes the route has always answered, so a client cannot tell
/// which face served it).
/// </summary>
internal readonly record struct EnrollmentAnswer(int Status, byte[] Body, string ContentType)
{
    public static EnrollmentAnswer Json<T>(int status, T value)
        => new(
            status,
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value, System.Text.Json.JsonSerializerOptions.Web),
            "application/json; charset=utf-8");
}

/// <summary>
/// The transport-independent half of <c>POST /implants/enroll</c>.
/// </summary>
internal sealed class EnrollmentExchange
{
    private readonly EnrollmentService _enrollment;
    private readonly IDeployTokenService _tokens;
    private readonly TimeProvider _clock;
    private readonly IAuditStore _audit;
    private readonly IPayloadStore _payloads;
    private readonly ICampaignStore _campaigns;
    private readonly EnvelopeContactKeys _contactKeys;

    public EnrollmentExchange(
        EnrollmentService enrollment,
        IDeployTokenService tokens,
        TimeProvider clock,
        IAuditStore audit,
        IPayloadStore payloads,
        ICampaignStore campaigns,
        EnvelopeContactKeys contactKeys)
    {
        _enrollment = enrollment;
        _tokens = tokens;
        _clock = clock;
        _audit = audit;
        _payloads = payloads;
        _campaigns = campaigns;
        _contactKeys = contactKeys;
    }

    /// <summary>
    /// Runs one enroll exchange: the request body bytes in (any of the
    /// malleable profile's shapes), the scoped ingress the request arrived
    /// on (null keeps the exchange token-scoped only -- the harness shape),
    /// the route's answer out.
    /// </summary>
    public async Task<EnrollmentAnswer> HandleAsync(
        byte[] requestBody,
        Listener? ingress,
        CancellationToken cancellationToken)
    {
        var body = await ReadRequestAsync(requestBody, cancellationToken);
        if (body is null)
            return EnrollmentAnswer.Json(
                400, new Problem("Request body is not an enroll request (raw JSON, a base64-wrapped JSON string, or an AES-GCM-wrapped one)."));

        // The implant's own public key (DER SubjectPublicKeyInfo, base64 over
        // JSON): a Tier 0 obligation the server accepts and validates -- an
        // ECDSA key an implant generates and keeps the private half of.
        byte[]? clientPublicKey = null;
        if (!string.IsNullOrWhiteSpace(body.PublicKey))
        {
            try
            {
                clientPublicKey = Convert.FromBase64String(body.PublicKey);
                using var validated = System.Security.Cryptography.ECDsa.Create();
                validated.ImportSubjectPublicKeyInfo(clientPublicKey, out _);
            }
            catch (FormatException)
            {
                return EnrollmentAnswer.Json(400, new Problem("Public key is not valid base64."));
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return EnrollmentAnswer.Json(400, new Problem("Public key is not a recognizable SubjectPublicKeyInfo."));
            }
        }

        var outcome = await ScopedEnrollment.EnrollAsync(
            new EnrollWireFields(
                body.DeployTokenSecret,
                body.Class,
                clientPublicKey,
                body.ParentImplantId,
                body.Hostname,
                body.Os,
                body.Arch,
                body.Username,
                body.KillDate,
                body.SleepSeconds,
                body.JitterSeconds),
            ingress,
            _enrollment,
            _tokens,
            _payloads,
            _campaigns,
            _contactKeys,
            _audit,
            _clock,
            cancellationToken);

        if (!outcome.Accepted)
            return MarshalRefusal(outcome);

        var enrolled = outcome.Enrolled!;
        return EnrollmentAnswer.Json(200, new EnrollmentEndpoints.EnrollmentResponse(
            EnrollStatus.Ok,
            enrolled.ImplantId.ToString(),
            enrolled.EngagementId.ToString(),
            "",
            enrolled.CaChain.Select(Convert.ToBase64String).ToArray(),
            enrolled.ParentImplantId?.ToString()));
    }

    // Shapes a refusal for the wire: the token states answer the
    // EnrollmentResponse body the implant reads (401, no distinction between
    // unknown, foreign, and spent); the problem causes answer the Problem
    // body an operator reads (400 malformed, 409 a closed engagement).
    private static EnrollmentAnswer MarshalRefusal(ScopedEnrollmentOutcome outcome)
        => outcome.Problem is { } problem
            ? EnrollmentAnswer.Json(outcome.ProblemStatus, new Problem(problem))
            : EnrollmentAnswer.Json(
                401,
                new EnrollmentEndpoints.EnrollmentResponse(outcome.Status, null, null, null, null, null));

    // Reads the enroll body in any of the shapes the malleable transport
    // profile allows (architecture.md Sec 7): the raw JSON document, a single
    // base64 string wrapping it (the base64 envelope), or a single base64
    // string wrapping AES-256-GCM ciphertext under the artifact's per-build
    // envelope key (the AesGcm envelope). Anything that matches no shape
    // returns null for a 400.
    private async Task<EnrollmentEndpoints.EnrollRequest?> ReadRequestAsync(
        byte[] requestBody, CancellationToken cancellationToken)
    {
        var raw = System.Text.Encoding.UTF8.GetString(requestBody).Trim();
        if (raw.Length == 0)
            return null;

        // A leading quote means the body is a JSON string -- an envelope.
        // Which one depends on the decoded bytes: the R1 magic names the
        // AES-Gcm shape (resolve the key by the id it prefixes, decrypt);
        // anything else is the base64 envelope's inner JSON.
        if (raw[0] == '"')
        {
            string? wrapped;
            try
            {
                wrapped = System.Text.Json.JsonSerializer.Deserialize<string>(raw);
            }
            catch (System.Text.Json.JsonException)
            {
                return null;
            }
            if (string.IsNullOrEmpty(wrapped))
                return null;

            if (AesGcmEnvelope.TryReadKeyId(wrapped) is { } keyId)
            {
                // The key lives beside the stored payload it was minted with;
                // a deleted payload takes its key along, and that artifact's
                // envelopes stop being decodable.
                var carrier = await _payloads.FindByEnvelopeKeyAsync(keyId, cancellationToken);
                if (carrier?.EnvelopeKey is not { } key)
                    return null;
                var plaintext = AesGcmEnvelope.TryUnwrap(
                    wrapped, carrier.EnvelopeKeyId!.Value, key, AesGcmEnvelope.Aad);
                if (plaintext is null)
                    return null;
                raw = System.Text.Encoding.UTF8.GetString(plaintext);
            }
            else
            {
                try
                {
                    raw = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(wrapped));
                }
                catch (FormatException)
                {
                    return null;
                }
            }
        }

        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<EnrollmentEndpoints.EnrollRequest>(raw,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }
}
