using Google.Protobuf;
using Rod.V1;

namespace Rod.Protocol.Tests;

/// <summary>
/// Schema-contract tests over the generated rod.v1 bindings: each pinned
/// property is a wire contract beyond what protobuf itself guarantees --
/// optional-field presence semantics, the arms' additive shape -- as the
/// messages the runtime round-trips.
/// </summary>
public class FrameRoundTrip
{
    // Staged tasking (architecture.md Sec 10, the typed arm): the optional
    // marker on TaskRequest, the demand, and the chunk run. The unset case is
    // the Tier 0 fallback property stated in extending/implants.md -- an
    // ordinary task round-trips with the arm's field absent, not zero or
    // defaulted, so an implant that never reads it sees exactly the task it
    // always saw.

    [Fact]
    public void TaskRequest_StagedBytes_RoundTrips()
    {
        var staged = new TaskRequest
        {
            TaskId = "t-1",
            Verb = "file.push",
            Arguments = "/tmp/tool.bin sha256:abc",
            StagedBytes = 10 * 1024 * 1024,
        };

        var restoredStaged = TaskRequest.Parser.ParseFrom(staged.ToByteArray());
        Assert.True(restoredStaged.HasStagedBytes);
        Assert.Equal(10UL * 1024 * 1024, restoredStaged.StagedBytes);

        var inline = new TaskRequest { TaskId = "t-2", Verb = "shell.exec", Arguments = "id" };
        var restoredInline = TaskRequest.Parser.ParseFrom(inline.ToByteArray());
        Assert.False(restoredInline.HasStagedBytes);
    }

    [Fact]
    public void TaskRequest_TargetImplantId_MarksFrontedTasking()
    {
        // The fronting arm (architecture.md Sec 5.2): set only on a frame a
        // server fronts to a fronting-capable implant; absent on every frame
        // any other implant receives, which is what keeps the arm additive.
        var fronted = new TaskRequest
        {
            TaskId = "t-1",
            Verb = "tunnel.forward",
            Arguments = "host.example 443",
            TargetImplantId = "child",
        };

        var restoredFronted = TaskRequest.Parser.ParseFrom(fronted.ToByteArray());
        Assert.True(restoredFronted.HasTargetImplantId);
        Assert.Equal("child", restoredFronted.TargetImplantId);

        var own = new TaskRequest { TaskId = "t-2", Verb = "shell.exec", Arguments = "id" };
        var restoredOwn = TaskRequest.Parser.ParseFrom(own.ToByteArray());
        Assert.False(restoredOwn.HasTargetImplantId);
    }

    [Fact]
    public void StagedPullAndChunk_RoundTrip()
    {
        var pull = new StagedPull { TaskId = "t-1" };
        var restoredPull = StagedPull.Parser.ParseFrom(pull.ToByteArray());
        Assert.Equal("t-1", restoredPull.TaskId);
        Assert.False(restoredPull.HasOffset);
        Assert.False(restoredPull.HasPrefixSha256);

        var chunk = new StagedChunk
        {
            TaskId = "t-1",
            Sequence = 19,
            Terminal = true,
            Data = ByteString.CopyFrom(new byte[] { 0x01, 0x02 }),
        };
        var restoredChunk = StagedChunk.Parser.ParseFrom(chunk.ToByteArray());
        Assert.Equal("t-1", restoredChunk.TaskId);
        Assert.Equal(19UL, restoredChunk.Sequence);
        Assert.True(restoredChunk.Terminal);
        Assert.Equal(chunk.Data, restoredChunk.Data);
        Assert.False(restoredChunk.HasOffset);
    }

    // The byte-offset resume arm (architecture.md Sec 15.3, ADR-010): a
    // resuming demand names the bytes it holds and proves them by hash; the
    // run's chunks carry their absolute byte position. The unset cases keep
    // the fresh-demand and arrival-order shapes every staged-capable implant
    // already speaks.
    [Fact]
    public void StagedResume_FieldsRoundTrip()
    {
        var resumed = new StagedPull
        {
            TaskId = "t-1",
            Offset = 3 * 512 * 1024,
            PrefixSha256 = ByteString.CopyFrom(new byte[32]),
        };
        var restored = StagedPull.Parser.ParseFrom(resumed.ToByteArray());
        Assert.True(restored.HasOffset);
        Assert.Equal(3UL * 512 * 1024, restored.Offset);
        Assert.True(restored.HasPrefixSha256);
        Assert.Equal(32, restored.PrefixSha256.Length);

        var placed = new StagedChunk
        {
            TaskId = "t-1",
            Sequence = 0,
            Terminal = false,
            Data = ByteString.CopyFrom(new byte[] { 0x03 }),
            Offset = 3 * 512 * 1024,
        };
        var restoredPlaced = StagedChunk.Parser.ParseFrom(placed.ToByteArray());
        Assert.True(restoredPlaced.HasOffset);
        Assert.Equal(3UL * 512 * 1024, restoredPlaced.Offset);
    }

    // The both-side verification half: the implant's computed payload hash on
    // a staged task's result, absent on every ordinary result.
    [Fact]
    public void TaskResult_PayloadSha256_RoundTrips()
    {
        var staged = new TaskResult
        {
            TaskId = "t-1",
            Outcome = TaskOutcome.Succeeded,
            Output = "/tmp/tool.bin: 1024 bytes written",
            PayloadSha256 = "a3f5b9".PadRight(64, '0'),
        };
        var restoredStaged = TaskResult.Parser.ParseFrom(staged.ToByteArray());
        Assert.True(restoredStaged.HasPayloadSha256);
        Assert.Equal(staged.PayloadSha256, restoredStaged.PayloadSha256);

        var ordinary = new TaskResult { TaskId = "t-2", Outcome = TaskOutcome.Succeeded, Output = "ok" };
        var restoredOrdinary = TaskResult.Parser.ParseFrom(ordinary.ToByteArray());
        Assert.False(restoredOrdinary.HasPayloadSha256);
    }

    // The upload arm of the resume (architecture.md Sec 15.3, ADR-010): an
    // offset-bearing chunk places itself and declares the whole artifact's
    // hash, and the seam report answers with the server's held count. The
    // unset case is the legacy chunk every community implant sends -- the
    // strict sequence discipline's shape, unchanged on the wire.
    [Fact]
    public void ExfilResume_FieldsRoundTrip()
    {
        var resumable = new ExfilChunk
        {
            TaskId = "t-1",
            Name = "loot.bin",
            ContentType = "application/octet-stream",
            Sequence = 0,
            Terminal = false,
            Data = ByteString.CopyFrom(new byte[] { 0x07 }),
            Offset = 2 * 512 * 1024,
            PayloadSha256 = ByteString.CopyFrom(new byte[32]),
        };
        var restored = ExfilChunk.Parser.ParseFrom(resumable.ToByteArray());
        Assert.True(restored.HasOffset);
        Assert.Equal(2UL * 512 * 1024, restored.Offset);
        Assert.True(restored.HasPayloadSha256);
        Assert.Equal(32, restored.PayloadSha256.Length);

        var legacy = new ExfilChunk
        {
            TaskId = "t-1",
            Name = "loot.bin",
            ContentType = "application/octet-stream",
            Sequence = 3,
            Terminal = true,
            Data = ByteString.CopyFrom(new byte[] { 0x08 }),
        };
        var restoredLegacy = ExfilChunk.Parser.ParseFrom(legacy.ToByteArray());
        Assert.False(restoredLegacy.HasOffset);
        Assert.False(restoredLegacy.HasPayloadSha256);

        var progress = new Frame
        {
            Kind = FrameKind.ExfilProgress,
            Payload = ByteString.CopyFrom(new ExfilProgress
            {
                TaskId = "t-1",
                Name = "loot.bin",
                HeldBytes = 512 * 1024,
            }.ToByteArray()),
        };
        var restoredProgress = Frame.Parser.ParseFrom(progress.ToByteArray());
        Assert.Equal(FrameKind.ExfilProgress, restoredProgress.Kind);
        var seam = ExfilProgress.Parser.ParseFrom(restoredProgress.Payload);
        Assert.Equal("loot.bin", seam.Name);
        Assert.Equal(512UL * 1024, seam.HeldBytes);
    }

    // Handshake messages: the first payload exchanged on a
    // Contact stream must round-trip with version, identity, and capabilities
    // intact -- these are what the server gates presence on.

    [Fact]
    public void HandshakeRequest_RoundTrips()
    {
        var original = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            ImplantId = "imp-42",
            Capabilities = { "shell.exec", "file.push", "file.pull" },
        };

        var restored = HandshakeRequest.Parser.ParseFrom(original.ToByteArray());

        Assert.Equal(1, restored.Version.Major);
        Assert.Equal(0, restored.Version.Minor);
        Assert.Equal("imp-42", restored.ImplantId);
        Assert.Equal(original.Capabilities, restored.Capabilities);
    }

    [Fact]
    public void HandshakeResponse_RoundTrips()
    {
        var original = new HandshakeResponse
        {
            Status = HandshakeStatus.Ok,
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            EngagementId = "eng-7",
        };

        var restored = HandshakeResponse.Parser.ParseFrom(original.ToByteArray());

        Assert.Equal(HandshakeStatus.Ok, restored.Status);
        Assert.Equal(1, restored.Version.Major);
        Assert.Equal("eng-7", restored.EngagementId);
    }

    // The receive-ack arm (architecture.md Sec 10.3 -- the dispatch strand):
    // the optional handshake advertisement and its echo, plus the ack frame
    // itself. The unset case is the evolution rule -- an implant that never
    // advertises leaves the field absent, and a server that does not echo
    // leaves the response absent, so each side sees exactly the semantics it
    // asked for.

    [Fact]
    public void Handshake_TaskAcks_RoundTrip()
    {
        var advertised = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            ImplantId = "imp-42",
            TaskAcks = true,
        };
        var restoredAdvertised = HandshakeRequest.Parser.ParseFrom(advertised.ToByteArray());
        Assert.True(restoredAdvertised.HasTaskAcks);
        Assert.True(restoredAdvertised.TaskAcks);

        var silent = new HandshakeRequest
        {
            Version = new ProtocolVersion { Major = 1, Minor = 0 },
            ImplantId = "imp-42",
        };
        var restoredSilent = HandshakeRequest.Parser.ParseFrom(silent.ToByteArray());
        Assert.False(restoredSilent.HasTaskAcks);

        var echoed = new HandshakeResponse
        {
            Status = HandshakeStatus.Ok,
            TaskAcks = true,
        };
        var restoredEcho = HandshakeResponse.Parser.ParseFrom(echoed.ToByteArray());
        Assert.True(restoredEcho.HasTaskAcks);
        Assert.True(restoredEcho.TaskAcks);

        var unechoed = new HandshakeResponse { Status = HandshakeStatus.Ok };
        var restoredUnechoed = HandshakeResponse.Parser.ParseFrom(unechoed.ToByteArray());
        Assert.False(restoredUnechoed.HasTaskAcks);
    }

    [Fact]
    public void TaskAck_RoundTrips()
    {
        var original = new Frame
        {
            Kind = FrameKind.TaskAck,
            Payload = ByteString.CopyFrom(new TaskAck { TaskId = "t-1" }.ToByteArray()),
        };

        var restoredFrame = Frame.Parser.ParseFrom(original.ToByteArray());
        Assert.Equal(FrameKind.TaskAck, restoredFrame.Kind);

        var restored = TaskAck.Parser.ParseFrom(restoredFrame.Payload);
        Assert.Equal("t-1", restored.TaskId);
    }
}
