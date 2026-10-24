using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.CoreState;
using Rod.CoreState.Collaboration;
using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.Operators.Collaboration;

namespace Rod.Operators.Endpoints;

/// <summary>
/// The engagement's comment surface (architecture.md Sec 15.3, ADR-005):
/// add, read, edit, and delete the mutable process knowledge attached to a
/// task, implant, artifact, file, the engagement, or an operator. Hosted by
/// the operator layer (transport may not reference it); scoped by the route
/// engagement; the edit and delete window is the service's rule. Comments
/// ride the timeline and SSE as ordinary events and never enter the audit
/// chain.
/// </summary>
public static class CommentEndpoints
{
    public static IEndpointRouteBuilder MapCommentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/comments")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));
        group.MapPost(string.Empty, CreateAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("CreateComment");
        group.MapGet(string.Empty, ListAsync).WithName("ListComments");
        group.MapPatch("/{commentId}", EditAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("EditComment");
        group.MapDelete("/{commentId}", DeleteAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("DeleteComment");
        return endpoints;
    }

    private static async Task<IResult> CreateAsync(
        string engagementId,
        CommentRequest? body,
        ClaimsPrincipal user,
        CommentService comments,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        // An unknown engagement is a routing problem (404); everything the
        // service refuses after that is a well-formed request the server
        // declines (422).
        if (user.TryGetOperatorId() is not { } operatorId)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return Results.NotFound(new Problem("Unknown engagement."));
        if (body is null || string.IsNullOrWhiteSpace(body.Body))
            return Results.BadRequest(new Problem("A comment needs a body."));
        if (!TryParseSubject(body, out var subjectKind, out var subjectId, out var subjectError))
            return Results.BadRequest(new Problem(subjectError));

        Comment comment;
        try
        {
            comment = await comments.CreateAsync(
                engagement, subjectKind, subjectId, operatorId, body.Body, cancellationToken);
        }
        catch (CommentRejectedException ex)
        {
            return Results.Json(new Problem(ex.Message), statusCode: 422);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new Problem(ex.Message));
        }

        // The author is the principal itself; resolve the handle with the
        // tolerance the listing applies (the bare id when the account no
        // longer resolves).
        var author = await operators.FindAsync(operatorId, cancellationToken);

        return Results.Created(
            $"/engagements/{engagement}/comments/{comment.Id}",
            CommentResponse.Of(comment, editable: true, author?.Handle ?? operatorId.ToString()));
    }

    private static async Task<IResult> ListAsync(
        string engagementId,
        string? subjectKind,
        string? subjectId,
        ClaimsPrincipal user,
        CommentService comments,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return Results.NotFound(new Problem("Unknown engagement."));

        // The panel read is per subject; the engagement-wide feed is the
        // merged timeline's job, which pages.
        if (string.IsNullOrWhiteSpace(subjectKind) || string.IsNullOrWhiteSpace(subjectId))
            return Results.BadRequest(new Problem("A subject kind and subject id are required."));
        if (!Enum.TryParse<CommentSubjectKind>(subjectKind, ignoreCase: true, out var kind))
            return Results.BadRequest(new Problem($"Unknown subject kind '{subjectKind}'."));
        if (!Guid.TryParse(subjectId, out var subject))
            return Results.BadRequest(new Problem("Subject id is not a valid identifier."));

        var items = await comments.ListBySubjectAsync(engagement, kind, subject, cancellationToken);

        // Resolve the rows' authors to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in items.Select(c => c.AuthorId.Value).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        var editableFor = user.TryGetOperatorId();
        return Results.Ok(new CommentListResponse(
            items.Select(c => CommentResponse.Of(
                c,
                editable: editableFor is { } viewer && comments.IsEditable(c, viewer),
                handles.GetValueOrDefault(c.AuthorId.Value, c.AuthorId.Value.ToString())))
                .ToArray()));
    }

    private static async Task<IResult> EditAsync(
        string engagementId,
        string commentId,
        CommentRequest? body,
        ClaimsPrincipal user,
        CommentService comments,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (user.TryGetOperatorId() is not { } operatorId)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return Results.NotFound(new Problem("Unknown engagement."));
        if (!CommentId.TryParse(commentId, out var id))
            return Results.BadRequest(new Problem("Comment id is not a valid identifier."));
        if (body is null || string.IsNullOrWhiteSpace(body.Body))
            return Results.BadRequest(new Problem("A comment needs a body."));

        Comment? comment;
        try
        {
            comment = await comments.EditAsync(engagement, id, operatorId, body.Body, cancellationToken);
        }
        catch (CommentRejectedException ex)
        {
            return Results.Json(new Problem(ex.Message), statusCode: 422);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new Problem(ex.Message));
        }

        if (comment is null)
            return Results.NotFound(new Problem("Comment does not exist in this engagement."));

        // The author's handle, resolved with the same tolerance the listing
        // applies.
        var author = await operators.FindAsync(comment.AuthorId, cancellationToken);

        return Results.Ok(CommentResponse.Of(comment, editable: true, author?.Handle ?? comment.AuthorId.ToString()));
    }

    private static async Task<IResult> DeleteAsync(
        string engagementId,
        string commentId,
        ClaimsPrincipal user,
        CommentService comments,
        IEngagementRepository engagements,
        CancellationToken cancellationToken)
    {
        if (user.TryGetOperatorId() is not { } operatorId)
            return Results.Unauthorized();
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return Results.BadRequest(new Problem("Engagement id is not a valid identifier."));
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return Results.NotFound(new Problem("Unknown engagement."));
        if (!CommentId.TryParse(commentId, out var id))
            return Results.BadRequest(new Problem("Comment id is not a valid identifier."));

        try
        {
            var deleted = await comments.DeleteAsync(engagement, id, operatorId, cancellationToken);
            return deleted is null
                ? Results.NotFound(new Problem("Comment does not exist in this engagement."))
                : Results.NoContent();
        }
        catch (CommentRejectedException ex)
        {
            return Results.Json(new Problem(ex.Message), statusCode: 422);
        }
    }

    private static bool TryParseSubject(CommentRequest body, out CommentSubjectKind kind, out Guid subjectId, out string error)
    {
        kind = default;
        subjectId = Guid.Empty;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(body.SubjectKind) || !Enum.TryParse<CommentSubjectKind>(body.SubjectKind, ignoreCase: true, out kind))
        {
            error = $"Unknown subject kind '{body.SubjectKind}'.";
            return false;
        }

        if (!Guid.TryParse(body.SubjectId, out subjectId))
        {
            error = "Subject id is not a valid identifier.";
            return false;
        }

        return true;
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record CommentRequest(string? SubjectKind, string? SubjectId, string? Body);

    /// <summary>
    /// One comment. <paramref name="Editable"/> is the caller's read of the
    /// edit window (the author, inside the window); the mutation path
    /// enforces it authoritatively.
    /// </summary>
    public sealed record CommentResponse(
        string Id,
        string SubjectKind,
        string SubjectId,
        string AuthorId,
        // The writing operator's handle, resolved at read time -- the member
        // role cannot walk the operator roster to map the id client-side, so
        // the read names the actor itself. The bare id stands in when the
        // account no longer resolves.
        string AuthorHandle,
        string Body,
        DateTimeOffset CreatedAt,
        DateTimeOffset? EditedAt,
        bool Editable)
    {
        public static CommentResponse Of(Comment c, bool editable, string authorHandle)
            => new(
                c.Id.ToString(),
                c.SubjectKind.ToString().ToLowerInvariant(),
                c.SubjectId.ToString(),
                c.AuthorId.ToString(),
                authorHandle,
                c.Body,
                c.CreatedAt,
                c.EditedAt,
                editable);
    }

    public sealed record CommentListResponse(IReadOnlyList<CommentResponse> Items);
}
