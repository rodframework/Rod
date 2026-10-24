using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Collaboration;
using Rod.CoreState.Engagements;
using Rod.CoreState.Operators;
using Rod.Operators.Collaboration;

namespace Rod.Operators.Endpoints;

/// <summary>
/// The engagement's chat surface (architecture.md Sec 15.3, ADR-005): the
/// coordination channels and their messages. Hosted by the operator layer;
/// scoped by the route engagement. Messages ride the timeline and SSE as
/// ordinary events and never enter the audit chain; they are append-only,
/// a correction being a new message.
/// </summary>
public static class ChatEndpoints
{
    public static IEndpointRouteBuilder MapChatEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints
            .MapGroup("/engagements/{engagementId}/chat")
            .RequireAuthorization().AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Read));
        group.MapGet("/channels", ListChannelsAsync).WithName("ListChatChannels");
        group.MapPost("/channels", CreateChannelAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("CreateChatChannel");
        group.MapGet("/channels/{channelId}/messages", ListMessagesAsync).WithName("ListChatMessages");
        group.MapPost("/channels/{channelId}/messages", SendAsync).AddEndpointFilter(new EngagementAccessFilter(EngagementAccessRequirement.Write))
            .WithName("SendChatMessage");
        return endpoints;
    }

    private static async Task<IResult> ListChannelsAsync(
        string engagementId,
        ChatService chat,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        var (error, engagement) = await BindAsync(engagementId, engagements, cancellationToken);
        if (error is not null)
            return error;

        var channels = await chat.ListChannelsAsync(engagement, cancellationToken);

        // Resolve the channels' creators to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in channels.Select(c => c.CreatedBy.Value).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        return Results.Ok(new ChatChannelListResponse(
            channels.Select(c => ChatChannelResponse.Of(
                c,
                handles.GetValueOrDefault(c.CreatedBy.Value, c.CreatedBy.Value.ToString())))
                .ToArray()));
    }

    private static async Task<IResult> CreateChannelAsync(
        string engagementId,
        CreateChannelRequest? body,
        ClaimsPrincipal user,
        ChatService chat,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (user.TryGetOperatorId() is not { } operatorId)
            return Results.Unauthorized();
        var (error, engagement) = await BindAsync(engagementId, engagements, cancellationToken);
        if (error is not null)
            return error;
        if (body is null || string.IsNullOrWhiteSpace(body.Name))
            return Results.BadRequest(new Problem("A channel needs a name."));

        ChatChannel channel;
        try
        {
            channel = await chat.CreateChannelAsync(engagement, body.Name, operatorId, cancellationToken);
        }
        catch (ChatRejectedException ex)
        {
            return Results.Json(new Problem(ex.Message), statusCode: 422);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new Problem(ex.Message));
        }

        // The creator is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var creator = await operators.FindAsync(operatorId, cancellationToken);

        return Results.Created(
            $"/engagements/{engagement}/chat/channels/{channel.Id}",
            ChatChannelResponse.Of(channel, creator?.Handle ?? operatorId.ToString()));
    }

    private static async Task<IResult> ListMessagesAsync(
        string engagementId,
        string channelId,
        int? limit,
        string? cursor,
        ChatService chat,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        var (error, engagement) = await BindAsync(engagementId, engagements, cancellationToken);
        if (error is not null)
            return error;
        if (!ChatChannelId.TryParse(channelId, out var channel))
            return Results.BadRequest(new Problem("Channel id is not a valid identifier."));
        if (await chat.FindChannelAsync(engagement, channel, cancellationToken) is null)
            return Results.NotFound(new Problem("Channel does not exist in this engagement."));

        var boundLimit = limit ?? 50;
        if (boundLimit is < 1 or > 200)
            return Results.BadRequest(new Problem("limit must be between 1 and 200."));

        DateTimeOffset? before = null;
        Guid? beforeId = null;
        if (cursor is not null)
        {
            if (!TimestampIdCursor.TryDecode(cursor, out var afterTicks, out var afterId))
                return Results.BadRequest(new Problem("cursor is not a valid page cursor for this listing."));
            before = new DateTimeOffset(afterTicks, TimeSpan.Zero);
            beforeId = afterId;
        }

        var page = await chat.ListMessagesPageAsync(channel, boundLimit, before, beforeId, cancellationToken);
        var nextCursor = page.HasMore && page.Items.Count > 0
            ? TimestampIdCursor.Encode(page.Items[0].SentAt, page.Items[0].Id.Value)
            : null;

        // Resolve the page's authors to handles once per request, the
        // tolerance the audit read applies (the bare id when the account no
        // longer resolves): the member role cannot walk the operator roster
        // to do it client-side, so the read names the actor itself.
        var handles = new Dictionary<Guid, string>();
        foreach (var id in page.Items.Select(m => m.AuthorId.Value).Distinct())
        {
            var op = await operators.FindAsync(new OperatorId(id), cancellationToken);
            handles[id] = op?.Handle ?? id.ToString();
        }

        return Results.Ok(new ChatMessageListResponse(
            page.Items.Select(m => ChatMessageResponse.Of(
                m,
                handles.GetValueOrDefault(m.AuthorId.Value, m.AuthorId.Value.ToString())))
                .ToArray(),
            nextCursor));
    }

    private static async Task<IResult> SendAsync(
        string engagementId,
        string channelId,
        SendMessageRequest? body,
        ClaimsPrincipal user,
        ChatService chat,
        IEngagementRepository engagements,
        IOperatorRepository operators,
        CancellationToken cancellationToken)
    {
        if (user.TryGetOperatorId() is not { } operatorId)
            return Results.Unauthorized();
        var (error, engagement) = await BindAsync(engagementId, engagements, cancellationToken);
        if (error is not null)
            return error;
        if (!ChatChannelId.TryParse(channelId, out var channel))
            return Results.BadRequest(new Problem("Channel id is not a valid identifier."));
        var found = await chat.FindChannelAsync(engagement, channel, cancellationToken);
        if (found is null)
            return Results.NotFound(new Problem("Channel does not exist in this engagement."));
        if (body is null || string.IsNullOrWhiteSpace(body.Body))
            return Results.BadRequest(new Problem("A chat message needs a body."));

        ChatMessage message;
        try
        {
            message = await chat.SendAsync(engagement, found, operatorId, body.Body, cancellationToken);
        }
        catch (ChatRejectedException ex)
        {
            return Results.Json(new Problem(ex.Message), statusCode: 422);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new Problem(ex.Message));
        }

        // The sender is the principal itself; resolve the handle with the
        // tolerance the listing applies.
        var author = await operators.FindAsync(operatorId, cancellationToken);

        return Results.Created(
            $"/engagements/{engagement}/chat/channels/{channel}/messages/{message.Id}",
            ChatMessageResponse.Of(message, author?.Handle ?? operatorId.ToString()));
    }

    private static async Task<(IResult? Error, EngagementId Engagement)> BindAsync(
        string engagementId,
        IEngagementRepository engagements,
        CancellationToken cancellationToken)
    {
        if (!EngagementId.TryParse(engagementId, out var engagement))
            return (Results.BadRequest(new Problem("Engagement id is not a valid identifier.")), engagement);
        if (await engagements.FindAsync(engagement, cancellationToken) is null)
            return (Results.NotFound(new Problem("Unknown engagement.")), engagement);
        return (null, engagement);
    }

    // --- DTOs. camelCase JSON is the framework default; records stay clean. ---

    public sealed record CreateChannelRequest(string? Name);

    public sealed record SendMessageRequest(string? Body);

    public sealed record ChatChannelResponse(
        string Id,
        string Name,
        string CreatedBy,
        // The creating operator's handle, resolved at read time -- the member
        // role cannot walk the operator roster to map the id client-side, so
        // the read names the actor itself. The bare id stands in when the
        // account no longer resolves.
        string CreatedByHandle,
        DateTimeOffset CreatedAt)
    {
        public static ChatChannelResponse Of(ChatChannel c, string createdByHandle)
            => new(c.Id.ToString(), c.Name, c.CreatedBy.ToString(), createdByHandle, c.CreatedAt);
    }

    public sealed record ChatMessageResponse(
        string Id,
        string ChannelId,
        string AuthorId,
        // The sending operator's handle, resolved at read time -- the member
        // role cannot walk the operator roster to map the id client-side, so
        // the read names the actor itself. The bare id stands in when the
        // account no longer resolves.
        string AuthorHandle,
        string Body,
        DateTimeOffset SentAt)
    {
        public static ChatMessageResponse Of(ChatMessage m, string authorHandle)
            => new(m.Id.ToString(), m.ChannelId.ToString(), m.AuthorId.ToString(), authorHandle, m.Body, m.SentAt);
    }

    public sealed record ChatChannelListResponse(IReadOnlyList<ChatChannelResponse> Items);

    public sealed record ChatMessageListResponse(IReadOnlyList<ChatMessageResponse> Items, string? NextCursor);
}
