using System.Buffers.Binary;
using System.Net.Http.Json;
using System.Text;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Implants;
using Rod.Transport.Endpoints;
using Rod.V1;
using Task = System.Threading.Tasks.Task;
using static Rod.Integration.Tests.TestSupport;

namespace Rod.Integration.Tests;

/// <summary>
/// Acceptance: an implant with no egress of its own enrolls and keeps its
/// session by riding a parent implant's tunnel.bind channel, with every
/// hop's records attributed (architecture.md Sec 5.2, the pivot model's
/// implant-side half; Sec 8). Drives the server half through a real
/// Kestrel endpoint with a contract-faithful fake parent: the operator
/// issues <c>tunnel.bind</c>, the parent's channel reports its listener and
/// carries each chained contact's bytes as the bind grammar's packets, and
/// the teamserver serves each contact through it -- the child enrolls (the
/// carrying parent recorded as its lineage, the frame's own claim
/// overridden), handshakes, and runs its own tasking, every arc attributed
/// to the child while the carriage's records attribute to the parent.
/// </summary>
public class ChainContactRoundTripTests
{
    [Fact]
    public async Task ChainedContact_EnrollsHandshakesAndRunsTasking_ThroughTheParent()
    {
        await using var env = await TestEnv.StartAsync();
        var implants = env.Host.Services.GetRequiredService<IImplantRepository>();
        var audit = env.Host.Services.GetRequiredService<IAuditStore>();

        var parent = await EngagementSetup.EnrollOwnedImplantAsync(env.Host);

        // The parent's held session -- the carriage the chain rides.
        using var beacon = await WsBeaconClient.ConnectAsync(
            env.HttpPort, parent.Id.ToString(), new[] { "tunnel.bind" });
        Assert.Equal(HandshakeStatus.Ok, (await beacon.ReceiveHandshakeAsync()).Status);

        // The operator opens the chain link like any other task. Port 0 asks
        // the implant to pick; the bound packet reports the actual address.
        await AuthenticatedHost.LoginAsync(env.Http);
        var issued = await env.Http.PostAsJsonAsync(
            $"/engagements/{parent.EngagementId}/tasks",
            new
            {
                ImplantId = parent.Id.ToString(),
                Verb = "tunnel.bind",
                Arguments = "127.0.0.1 0",
            });
        issued.EnsureSuccessStatusCode();
        var issuedBody = await issued.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(issuedBody);

        var bindRequest = await NextTaskRequestAsync(beacon, issuedBody!.TaskId);
        Assert.Equal("tunnel.bind", bindRequest.Verb);
        Assert.Equal("127.0.0.1 0", bindRequest.Arguments);

        // The link reports its listener, then accepts a connection: the
        // first packet carries the actual address, the second announces the
        // contact the child is about to run on it.
        await beacon.SendFramesAsync(new[]
        {
            BytesOutputFrame(bindRequest.TaskId, Packet(1, 0, "127.0.0.1:47001")),
            BytesOutputFrame(bindRequest.TaskId, Packet(2, 1, "127.0.0.1:51000")),
        });

        // The hop's audit lands attributed to the parent, bound to the bind
        // task (Sec 5.2): the carriage's record, ahead of anything the child
        // carries over it.
        await WaitUntilAsync(async () =>
        {
            var trail = await audit.ListAsync(parent.EngagementId.Value, CancellationToken.None);
            return trail.Any(e => e.Kind == AuditEventKind.ChainHopOpened);
        });

        // The child's enrollment: a deploy token of the same engagement, the
        // EnrollRequest frame promoted into the contact's opening message.
        // The frame claims no parent -- the carrying parent is what the
        // server records, the authority the carriage itself is.
        var secret = await EngagementSetup.MintDeployTokenAsync(env.Http, parent.EngagementId.ToString());
        await beacon.SendFramesAsync(new[]
        {
            BytesOutputFrame(
                bindRequest.TaskId,
                Packet(3, 1, ContactMessage(new Frame
                {
                    Kind = FrameKind.EnrollRequest,
                    Payload = ByteString.CopyFrom(new Rod.V1.EnrollRequest
                    {
                        DeployTokenSecret = secret,
                        Hostname = "chain-child",
                        Os = "linux",
                        Arch = "amd64",
                    }.ToByteArray()),
                }))),
        });

        // The contact's answer rides back down the same channel: one data
        // packet carrying the EnrollResponse message.
        var enrollReply = await NextContactMessageAsync(beacon, bindRequest.TaskId, 1);
        var enrollFrame = ParseFrames(enrollReply)[0];
        Assert.Equal(FrameKind.EnrollResponse, enrollFrame.Kind);
        var enrollment = Rod.V1.EnrollResponse.Parser.ParseFrom(enrollFrame.Payload);
        Assert.Equal(EnrollStatus.Ok, enrollment.Status);
        Assert.True(ImplantId.TryParse(enrollment.ImplantId, out var childId));

        // The lineage is recorded from the carriage: the child's row names
        // the parent, and its enrollment audit carries the parent in its
        // payload -- the per-hop attribution the acceptance names.
        var child = await implants.FindAsync(childId, CancellationToken.None);
        Assert.NotNull(child);
        Assert.Equal(parent.Id, child!.ParentImplantId);
        await WaitUntilAsync(async () =>
        {
            var trail = await audit.ListAsync(parent.EngagementId.Value, CancellationToken.None);
            return trail.Any(e =>
                e.Kind == AuditEventKind.ImplantEnrolled
                && e.ImplantId == childId.Value
                && e.Payload.Contains($"parent={parent.Id}"));
        });

        // The child's session: the handshake opens it, and the carrier the
        // presence stamps is the chain -- the badge the roster reads. The
        // child speaks the poll cadence -- one contact per cycle, a fresh
        // connection each time (the next id) -- exactly the shape a raw-TCP
        // poll client of the parent's listener would run.
        await beacon.SendFramesAsync(new[]
        {
            BytesOutputFrame(bindRequest.TaskId, Packet(2, 2, "127.0.0.1:51001")),
            BytesOutputFrame(
                bindRequest.TaskId,
                Packet(3, 2, HandshakeContact(childId))),
        });
        var handshakeReply = await NextContactMessageAsync(beacon, bindRequest.TaskId, 2);
        var handshakeFrame = ParseFrames(handshakeReply)[0];
        var handshake = HandshakeResponse.Parser.ParseFrom(handshakeFrame.Payload);
        Assert.Equal(HandshakeStatus.Ok, handshake.Status);

        var sessions = env.Host.Services
            .GetRequiredService<Rod.CoreState.Sessions.ISessionRegistry>();
        await WaitUntilAsync(async () =>
        {
            var active = await sessions.GetActiveAsync(childId, CancellationToken.None);
            return active is not null;
        });
        var childSession = await sessions.GetActiveAsync(childId, CancellationToken.None);
        Assert.Equal(TransportCapabilitiesForChain, childSession!.LastCarrier);

        // Tasking the child runs over the same contact: the operator's task
        // for the child claims through the chain, its frame rides the
        // contact's answer, its result attributes to the child.
        var tasked = await env.Http.PostAsJsonAsync(
            $"/engagements/{parent.EngagementId}/tasks",
            new
            {
                ImplantId = childId.ToString(),
                Verb = "shell.exec",
                Arguments = "uptime",
            });
        tasked.EnsureSuccessStatusCode();
        var taskedBody = await tasked.Content.ReadFromJsonAsync<TaskIssuedBody>();
        Assert.NotNull(taskedBody);

        // The child's next contact claims the queued tasking: the answer's
        // frames carry the handshake response and the dispatched request,
        // the poll cycle's ordinary composition.
        await beacon.SendFramesAsync(new[]
        {
            BytesOutputFrame(bindRequest.TaskId, Packet(2, 3, "127.0.0.1:51002")),
            BytesOutputFrame(
                bindRequest.TaskId,
                Packet(3, 3, HandshakeContact(childId))),
        });
        var taskingReply = ParseFrames(await NextContactMessageAsync(beacon, bindRequest.TaskId, 3));
        var claimed = taskingReply
            .Where(f => f.Kind == FrameKind.Unspecified)
            .Select(f => TaskRequest.Parser.ParseFrom(f.Payload))
            .First(r => r.TaskId == taskedBody!.TaskId);
        // The chained child runs its own tasking -- no fronting marking: it
        // has a process and a session of its own (Sec 5.2's two halves).
        Assert.False(claimed.HasTargetImplantId);

        await beacon.SendFramesAsync(new[]
        {
            BytesOutputFrame(bindRequest.TaskId, Packet(2, 4, "127.0.0.1:51003")),
            BytesOutputFrame(
                bindRequest.TaskId,
                Packet(3, 4, ContactMessage(
                    HandshakeFrameOf(childId),
                    new Frame
                    {
                        Payload = ByteString.CopyFrom(new TaskResult
                        {
                            TaskId = claimed.TaskId,
                            Outcome = TaskOutcome.Succeeded,
                            Output = "up 1 day",
                        }.ToByteArray()),
                    }))),
        });

        await WaitUntilAsync(async () =>
        {
            var trail = await audit.ListAsync(parent.EngagementId.Value, CancellationToken.None);
            return trail.Any(e =>
                e.Kind == AuditEventKind.TaskCompleted
                && e.ImplantId == childId.Value
                && e.TaskId == Guid.Parse(claimed.TaskId));
        });

        // The contact ends -- the parent's listener saw the connection close
        // -- and the hop's closing record lands beside its opening one. The
        // bind task's own completion closes the link.
        await beacon.SendFramesAsync(new[] { BytesOutputFrame(bindRequest.TaskId, Packet(4, 1, "")) });
        await WaitUntilAsync(async () =>
        {
            var trail = await audit.ListAsync(parent.EngagementId.Value, CancellationToken.None);
            return trail.Any(e => e.Kind == AuditEventKind.ChainHopClosed);
        });

        await beacon.SendFramesAsync(new[]
        {
            ResultFrame(new TaskResult
            {
                TaskId = bindRequest.TaskId,
                Outcome = TaskOutcome.Succeeded,
                Output = "chain bind closed: 2 contacts",
            }),
        });
        await WaitUntilAsync(async () =>
        {
            var trail = await audit.ListAsync(parent.EngagementId.Value, CancellationToken.None);
            return trail.Any(e =>
                e.Kind == AuditEventKind.TaskCompleted
                && e.TaskId == Guid.Parse(bindRequest.TaskId));
        });
    }

    private const string TransportCapabilitiesForChain = "chain";

    // --- the bind grammar, mirrored from the implant-side handler ---------

    private const byte KindBound = 1;
    private const byte KindOpen = 2;
    private const byte KindData = 3;
    private const byte KindClose = 4;

    private static byte[] Packet(byte kind, uint connection, string payload)
        => Packet(kind, connection, Encoding.UTF8.GetBytes(payload));

    private static byte[] Packet(byte kind, uint connection, byte[] payload)
    {
        var packet = new byte[7 + payload.Length];
        packet[0] = kind;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(1, 4), connection);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(5, 2), (ushort)payload.Length);
        payload.CopyTo(packet, 7);
        return packet;
    }

    // The poll contact's opening handshake frame -- every cycle opens with
    // one, the poll cadence the raw-TCP family keeps.
    private static Frame HandshakeFrameOf(ImplantId childId)
        => new()
        {
            Payload = ByteString.CopyFrom(new HandshakeRequest
            {
                Version = new ProtocolVersion { Major = 1, Minor = 0 },
                ImplantId = childId.ToString(),
            }.ToByteArray()),
        };

    private static byte[] HandshakeContact(ImplantId childId)
        => ContactMessage(HandshakeFrameOf(childId));

    /// <summary>
    /// One self-delimited contact message (the message-pipe framing the
    /// chained contact speaks): the varint body length, then the framed
    /// envelope body -- the same bytes a raw-TCP contact would carry.
    /// </summary>
    private static byte[] ContactMessage(params Frame[] frames)
    {
        var body = EnvelopeFraming.Encode(frames);
        var message = new byte[5 + body.Length];
        var value = (ulong)body.Length;
        var index = 0;
        while (value >= 0x80)
        {
            message[index++] = (byte)(value | 0x80);
            value >>= 7;
        }
        message[index++] = (byte)value;
        body.CopyTo(message, index);
        return message[..(index + body.Length)];
    }

    private static byte[] ParseContactMessage(byte[] message)
    {
        // The varint prefix in, the envelope body out.
        var index = 0;
        long length = 0;
        var shift = 0;
        while (true)
        {
            var read = message[index++];
            length |= (long)(read & 0x7f) << shift;
            if ((read & 0x80) == 0)
                break;
            shift += 7;
        }
        return message[index..(int)(index + length)];
    }

    private static List<Frame> ParseFrames(byte[] message)
        => EnvelopeFraming.Parse(ParseContactMessage(message));

    // Reads the next data packet the link carried downstream for one
    // connection -- the contact's answer to whatever the test last sent up.
    private static async Task<byte[]> NextContactMessageAsync(
        WsBeaconClient beacon, string taskId, uint connection)
    {
        while (true)
        {
            var frame = await beacon.ReceiveFrameAsync();
            if (frame.Kind != FrameKind.ChannelInput)
                continue;
            var input = ChannelInput.Parser.ParseFrom(frame.Payload);
            if (input.TaskId != taskId || input.Data.Length < 7)
                continue;
            if (input.Data.Span[0] != KindData)
                continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(input.Data.Span.Slice(1, 4)) != connection)
                continue;
            var length = BinaryPrimitives.ReadUInt16LittleEndian(input.Data.Span.Slice(5, 2));
            return input.Data.Span.Slice(7, length).ToArray();
        }
    }

    private static async Task<TaskRequest> NextTaskRequestAsync(WsBeaconClient beacon, string taskId)
    {
        while (true)
        {
            var frame = await beacon.ReceiveFrameAsync();
            if (frame.Kind != FrameKind.Unspecified)
                continue;
            var request = TaskRequest.Parser.ParseFrom(frame.Payload);
            if (request.TaskId == taskId)
                return request;
        }
    }

    private static Frame BytesOutputFrame(string taskId, byte[] data)
        => new()
        {
            Payload = ByteString.CopyFrom(new ChannelOutput
            {
                TaskId = taskId,
                Data = ByteString.CopyFrom(data),
            }.ToByteArray()),
            Kind = FrameKind.ChannelOutput,
        };

    private static Frame ResultFrame(TaskResult result)
        => new() { Payload = ByteString.CopyFrom(result.ToByteArray()) };

    private sealed class TaskIssuedBody
    {
        public string TaskId { get; set; } = "";
    }
}
