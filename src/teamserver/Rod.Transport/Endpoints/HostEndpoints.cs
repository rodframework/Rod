using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Implants;
using Rod.CoreState.Operators;
using Rod.CoreState.Sessions;

namespace Rod.Transport.Endpoints;

/// <summary>
/// The operator-facing host endpoints -- the device dimension of the target
/// intel layer (architecture.md Sec 11.2). A host is not an entity: it is the
/// grouping the implants' own enrollment hostname stamp defines, read-side.
/// These routes carry that picture: the grouped listing (which implants share
/// a host, what the crew has labeled and noted about it) and the attributed
/// notes and labels operators write about a host -- facts recorded as audit
/// events and read back from the same trail, so they ride the hash chain with
/// no host store to keep consistent.
///
/// Host facts key on the normalized hostname (trimmed, case-folded), the same
/// join every intel view applies; a fact may name a host no implant reported
/// yet (one recon has seen but nothing occupies), because the note organizes
/// the picture, and the picture spans more than the fleet. Scoped by
/// engagement (architecture.md Sec 3): the engagement id in the path binds
/// every read and write.
/// </summary>
public static class HostEndpoints
{
    // A hostname is bounded by the DNS name length; a note is a sentence or
    // three (the implant-note cap); a label is a marker (the implant-label
    // cap). Same bounds as their implant-side twins so one vocabulary reads
    // the same everywhere.
    private const int MaxHostChars = 253;
    private const int MaxNoteChars = 8 * 1024;
    private const int MaxLabelChars = 64;
    private const int MaxLabelsPerHost = 32;

    // The host-fact payload codec: a small camelCase JSON object naming the
    // host alongside the fact. The audit record's field set is frozen (the
    // chain's canonical form), so the host rides the payload string the way
    // artifact bindings ride "Name;ContentType" -- but structured, because a
    // host fact has two parts to keep unambiguous.
    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    internal sealed record HostFactPayload(string Host, string? Text, string? Label);

    public static IEndpointRouteBuilder MapHostEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Operator-facing: the host picture and the facts operators write
        // about a host require an authenticated operator session; the writes
        // additionally hold the task scope, like every engagement mutation.
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/hosts")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));
        group.MapGet("/", ListHostsAsync).WithName(nameof(ListHostsAsync));
        group.MapGet("/{host}/notes", ListHostNotesAsync).WithName(nameof(ListHostNotesAsync));
        group.MapPost("/{host}/notes", AddHostNoteAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(AddHostNoteAsync));
        group.MapGet("/{host}/labels", ListHostLabelsAsync).WithName(nameof(ListHostLabelsAsync));
        group.MapPost("/{host}/labels", SetHostLabelAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(SetHostLabelAsync));
        group.MapDelete("/{host}/labels/{label}", ClearHostLabelAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName(nameof(ClearHostLabelAsync));
        return endpoints;
    }

    private static async Task<IResult> ListHostsAsync(
        string engagementId,
        IEngagementRepository engagements,
        IImplantRepository implants,
        ISessionRegistry sessions,
        IAuditStore audit,
        CancellationToken cancellationToken)
    {
        var engagement = await ResolveEngagementAsync(engagementId, engagements, cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));

        var engagementKey = new EngagementId(engagement.Value);
        var enrolled = await implants.ListByEngagementAsync(engagementKey, cancellationToken);
        var online = (await sessions.ListActiveAsync(engagementKey, cancellationToken))
            .Select(s => s.ImplantId)
            .ToHashSet();

        // The host facts operators wrote: labels reduced per host, notes
        // counted, and every host a fact names -- including one no implant
        // reported. A payload that does not parse is skipped, not fatal: the
        // trail is the record and a malformed line must not blank the view.
        var hostFacts = ParseHostFacts(await audit.ListAsync(engagement.Value, cancellationToken));
        var labelsByHost = ReduceLabels(hostFacts);
        var noteCounts = new Dictionary<string, int>();
        foreach (var fact in hostFacts.Where(f => f.Kind == AuditEventKind.HostNoteAdded))
            noteCounts[fact.Host] = noteCounts.GetValueOrDefault(fact.Host) + 1;

        // The fact half: every host a label or note names gets an entry --
        // including one no implant reported, because recon can see what
        // nothing occupies.
        var hosts = new SortedDictionary<string, HostResponse>(StringComparer.Ordinal);
        var factHosts = labelsByHost.Keys
            .Concat(noteCounts.Keys)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(h => h, StringComparer.Ordinal);
        foreach (var host in factHosts)
        {
            hosts[host] = new HostResponse(
                Host: host,
                Labels: labelsByHost.GetValueOrDefault(host, [])
                    .Select(l => l.Label)
                    .ToArray(),
                NoteCount: noteCounts.GetValueOrDefault(host),
                ImplantIds: [],
                OnlineCount: 0,
                Os: null,
                Arch: null,
                Username: null,
                FirstSeenAt: null);
        }

        // The fleet half: implants group under their reported hostname; one
        // that reported none cannot be grouped and stays in the ungrouped
        // list rather than pinned to an invented host.
        var ungrouped = new List<string>();
        foreach (var implant in enrolled.OrderBy(i => i.CreatedAt))
        {
            var key = NormalizeHost(implant.Hostname);
            if (key is null)
            {
                ungrouped.Add(implant.Id.ToString());
                continue;
            }

            if (!hosts.TryGetValue(key, out var host))
            {
                host = new HostResponse(
                    key, [], 0, [], 0, null, null, null, null);
                hosts[key] = host;
            }

            host = host with
            {
                ImplantIds = [.. host.ImplantIds, implant.Id.ToString()],
                OnlineCount = host.OnlineCount + (online.Contains(implant.Id) ? 1 : 0),
                Os = host.Os ?? implant.Os,
                Arch = host.Arch ?? implant.Arch,
                Username = host.Username ?? implant.Username,
                FirstSeenAt = host.FirstSeenAt ?? implant.CreatedAt,
            };
            hosts[key] = host;
        }

        return Results.Ok(new HostsResponse([.. hosts.Values], [.. ungrouped]));
    }

    private static async Task<IResult> ListHostNotesAsync(
        string engagementId,
        string host,
        IEngagementRepository engagements,
        IAuditStore audit,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        var engagement = await ResolveEngagementAsync(engagementId, engagements, cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        var key = NormalizeHost(host);
        if (key is null)
            return Results.BadRequest(new Problem("Host name is required."));

        var notes = ParseHostFacts(await audit.ListAsync(engagement.Value, cancellationToken))
            .Where(f => f.Kind == AuditEventKind.HostNoteAdded
                && string.Equals(f.Host, key, StringComparison.Ordinal))
            .ToArray();

        // Resolve the notes' authors to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in notes.Select(f => f.OperatorId).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        return Results.Ok(notes
            .Select(f => new HostNoteResponse(
                f.EventId.ToString(),
                f.Host,
                new OperatorId(f.OperatorId).ToString(),
                handles.GetValueOrDefault(f.OperatorId, f.OperatorId.ToString()),
                f.Text ?? string.Empty,
                f.At))
            .ToArray());
    }

    private static async Task<IResult> AddHostNoteAsync(
        string engagementId,
        string host,
        AddHostNoteRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IAuditStore audit,
        IOperatorRepository operators,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var author = user.TryGetOperatorId();
        if (author is null)
            return Results.Unauthorized();
        var engagement = await ResolveEngagementAsync(engagementId, engagements, cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        var key = NormalizeHost(host);
        if (key is null)
            return Results.BadRequest(new Problem("Host name is required."));
        if (string.IsNullOrWhiteSpace(body.Text))
            return Results.BadRequest(new Problem("Note text is required."));
        if (body.Text.Length > MaxNoteChars)
            return Results.Json(
                new Problem($"Note text exceeds {MaxNoteChars} characters."),
                statusCode: StatusCodes.Status413PayloadTooLarge);

        // The note is the operator's attributed action on the engagement
        // (architecture.md Sec 11.2): a HostNoteAdded event whose payload
        // names the host and carries the text. The implant and task ids stay
        // unused -- a host is not an implant, and the note annotates rather
        // than tasks.
        var at = clock.GetUtcNow();
        var noteId = Guid.NewGuid();
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: noteId,
                engagementId: engagement.Value,
                operatorId: author.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "host-note",
                kind: AuditEventKind.HostNoteAdded,
                payload: JsonSerializer.Serialize(new HostFactPayload(key, body.Text, null), PayloadOptions),
                output: null,
                outcome: "added",
                at: at),
            cancellationToken);

        // The writer is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var writer = await operators.FindAsync(author.Value, cancellationToken);

        return Results.Created(
            $"/engagements/{engagementId}/hosts/{key}/notes",
            new HostNoteResponse(
                noteId.ToString(),
                key,
                author.Value.ToString(),
                writer?.Handle ?? author.Value.ToString(),
                body.Text,
                at));
    }

    private static async Task<IResult> ListHostLabelsAsync(
        string engagementId,
        string host,
        IEngagementRepository engagements,
        IAuditStore audit,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        var engagement = await ResolveEngagementAsync(engagementId, engagements, cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        var key = NormalizeHost(host);
        if (key is null)
            return Results.BadRequest(new Problem("Host name is required."));

        var reduced = ReduceLabels(ParseHostFacts(await audit.ListAsync(engagement.Value, cancellationToken)))
            .GetValueOrDefault(key, []);

        // Resolve the labels' setters to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in reduced.Select(l => l.OperatorId).Where(id => id != Guid.Empty).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        return Results.Ok(reduced
            .Select(l => new HostLabelResponse(
                l.Label,
                new OperatorId(l.OperatorId).ToString(),
                handles.GetValueOrDefault(l.OperatorId, l.OperatorId.ToString()),
                l.At))
            .ToArray());
    }

    private static async Task<IResult> SetHostLabelAsync(
        string engagementId,
        string host,
        SetHostLabelRequest body,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IAuditStore audit,
        IOperatorRepository operators,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var actor = user.TryGetOperatorId();
        if (actor is null)
            return Results.Unauthorized();
        var engagement = await ResolveEngagementAsync(engagementId, engagements, cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        var key = NormalizeHost(host);
        if (key is null)
            return Results.BadRequest(new Problem("Host name is required."));
        var label = body.Label?.Trim();
        if (string.IsNullOrWhiteSpace(label))
            return Results.BadRequest(new Problem("Label text is required."));
        if (label.Length > MaxLabelChars)
            return Results.BadRequest(new Problem($"Label text exceeds {MaxLabelChars} characters."));

        // The cap reads the reduced set, so a re-set of a carried label or a
        // slot an earlier clear freed never trips it -- the implant-label
        // rule on the host key.
        var facts = ParseHostFacts(await audit.ListAsync(engagement.Value, cancellationToken));
        var current = ReduceLabels(facts).GetValueOrDefault(key, []);
        if (current.Count >= MaxLabelsPerHost
            && !current.Any(l => string.Equals(l.Label, label, StringComparison.OrdinalIgnoreCase)))
        {
            return Results.Json(
                new Problem($"A host carries at most {MaxLabelsPerHost} labels."),
                statusCode: StatusCodes.Status422UnprocessableEntity);
        }

        var at = clock.GetUtcNow();
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: actor.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "host-label",
                kind: AuditEventKind.HostLabeled,
                payload: JsonSerializer.Serialize(new HostFactPayload(key, null, label), PayloadOptions),
                output: null,
                outcome: "set",
                at: at),
            cancellationToken);

        // The setter is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var setter = await operators.FindAsync(actor.Value, cancellationToken);

        return Results.Created(
            $"/engagements/{engagementId}/hosts/{key}/labels",
            new HostLabelResponse(label, actor.Value.ToString(), setter?.Handle ?? actor.Value.ToString(), at));
    }

    private static async Task<IResult> ClearHostLabelAsync(
        string engagementId,
        string host,
        string label,
        ClaimsPrincipal user,
        IEngagementRepository engagements,
        IAuditStore audit,
        TimeProvider clock,
        CancellationToken cancellationToken)
    {
        var actor = user.TryGetOperatorId();
        if (actor is null)
            return Results.Unauthorized();
        var engagement = await ResolveEngagementAsync(engagementId, engagements, cancellationToken);
        if (engagement is null)
            return Results.NotFound(new Problem("Engagement does not exist."));
        var key = NormalizeHost(host);
        if (key is null)
            return Results.BadRequest(new Problem("Host name is required."));

        // Idempotent like the implant-side clear: every operator action
        // appends, and the last-wins reduction decides the live set.
        await audit.AppendAsync(
            AuditEvent.Fact(
                eventId: Guid.NewGuid(),
                engagementId: engagement.Value,
                operatorId: actor.Value.Value,
                implantId: Guid.Empty,
                taskId: Guid.Empty,
                verb: "host-label",
                kind: AuditEventKind.HostLabeled,
                payload: JsonSerializer.Serialize(new HostFactPayload(key, null, label), PayloadOptions),
                output: null,
                outcome: "cleared",
                at: clock.GetUtcNow()),
            cancellationToken);

        return Results.NoContent();
    }

    // The engagement id every route binds, or null when it does not resolve
    // -- the 404 ladder every engagement-scoped read holds.
    private static async Task<Guid?> ResolveEngagementAsync(
        string engagementId,
        IEngagementRepository engagements,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(engagementId, out var engagementValue))
            return null;

        var engagement = await engagements.FindAsync(new EngagementId(engagementValue), cancellationToken);
        return engagement is null ? null : engagementValue;
    }

    // The host key: trimmed and case-folded -- hostnames are case-insensitive
    // by convention, so "WEB01" and "web01" are one host in every view. Null
    // when the name carries nothing.
    internal static string? NormalizeHost(string? host)
    {
        var key = host?.Trim().ToLowerInvariant();
        return string.IsNullOrWhiteSpace(key) ? null : key;
    }

    // One parsed host fact off the trail: the event plus its decoded payload.
    // Notes and labels arrive as the same JSON shape with one of the two
    // content fields set.
    internal readonly record struct HostFact(
        AuditEventKind Kind,
        Guid EventId,
        Guid OperatorId,
        string Host,
        string? Text,
        string? Label,
        string Outcome,
        DateTimeOffset At);

    internal static List<HostFact> ParseHostFacts(IReadOnlyList<AuditEvent> trail)
    {
        var facts = new List<HostFact>();
        foreach (var e in trail)
        {
            if (e.Kind is not (AuditEventKind.HostNoteAdded or AuditEventKind.HostLabeled))
                continue;

            HostFactPayload? payload;
            try
            {
                payload = JsonSerializer.Deserialize<HostFactPayload>(e.Payload, PayloadOptions);
            }
            catch (JsonException)
            {
                continue; // Not a fact this view can read; the trail keeps it.
            }

            if (payload?.Host is not { Length: > 0 })
                continue;

            facts.Add(new HostFact(
                e.Kind, e.EventId, e.OperatorId, payload.Host, payload.Text, payload.Label, e.Outcome, e.At));
        }

        return facts;
    }

    // The last-wins label reduction per host, keyed on the normalized host:
    // the implant-label discipline lifted one key up. Markers compare
    // case-insensitively ("web" and "Web" are one label) with the last
    // spelling kept; a label-less fact (a note) is not the reduction's input.
    internal static Dictionary<string, List<(string Label, Guid OperatorId, DateTimeOffset At)>> ReduceLabels(
        List<HostFact> facts)
    {
        var byHost = new Dictionary<
            string,
            Dictionary<string, (string Label, Guid OperatorId, DateTimeOffset At)>>(StringComparer.Ordinal);
        foreach (var fact in facts)
        {
            if (fact.Label is null)
                continue;

            if (!byHost.TryGetValue(fact.Host, out var labels))
            {
                labels = new Dictionary<string, (string Label, Guid OperatorId, DateTimeOffset At)>(
                    StringComparer.OrdinalIgnoreCase);
                byHost[fact.Host] = labels;
            }

            if (string.Equals(fact.Outcome, "cleared", StringComparison.OrdinalIgnoreCase))
                labels.Remove(fact.Label);
            else
                labels[fact.Label] = (fact.Label, fact.OperatorId, fact.At);
        }

        var reduced = new Dictionary<string, List<(string Label, Guid OperatorId, DateTimeOffset At)>>(StringComparer.Ordinal);
        foreach (var (host, labels) in byHost)
            reduced[host] = [.. labels.Values];
        return reduced;
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    // The grouped host picture: what the crew's picture holds for one host.
    // ImplantIds/OnlineCount/FirstSeenAt come from the fleet grouping (null
    // dimensions for a host only a fact names); Labels/NoteCount from the
    // trail.
    public sealed record HostResponse(
        string Host,
        string[] Labels,
        int NoteCount,
        string[] ImplantIds,
        int OnlineCount,
        string? Os,
        string? Arch,
        string? Username,
        DateTimeOffset? FirstSeenAt);

    // The hosts listing: grouped hosts plus the implants that reported no
    // hostname -- they cannot be grouped, so they stay listed rather than
    // pinned to an invented host.
    public sealed record HostsResponse(
        HostResponse[] Hosts,
        string[] UngroupedImplantIds);

    // One note about a host: the audit event's id (a note is its event), the
    // host it describes, the writing operator and its handle (resolved at
    // read time; the bare id stands in when the account no longer resolves),
    // the text, and when.
    public sealed record HostNoteResponse(
        string NoteId,
        string Host,
        string Author,
        string AuthorHandle,
        string Text,
        DateTimeOffset At);

    // One label a host currently carries: the marker text, the operator whose
    // set action last won the reduction and its handle (resolved at read
    // time; the bare id stands in when the account no longer resolves), and
    // when.
    public sealed record HostLabelResponse(
        string Label,
        string SetBy,
        string SetByHandle,
        DateTimeOffset SetAt);

    public sealed record AddHostNoteRequest(string Text);

    public sealed record SetHostLabelRequest(string Label);
}
