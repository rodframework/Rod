using Google.Protobuf.Reflection;

namespace Rod.Protocol.Tests;

/// <summary>
/// The freeze snapshot of rod.proto's wire surface (ADR-019, executed at
/// v1.0.0): every message's field numbers, every enum's values, and the
/// reserved range Frame carries. The pin is exact on purpose -- a compliant
/// additive change updates this snapshot in the same change that updates
/// extending/implants.md's tier statement (evolution rule 3), and any
/// renumber, reuse, or rename fails here outright. The snapshot is read
/// from the compiled descriptor, the same truth every stack serializes
/// against, so comments and formatting in the .proto source stay free.
/// </summary>
public class ProtoSurfaceTests
{
    private static FileDescriptorProto Proto()
        => FileDescriptorProto.Parser.ParseFrom(global::Rod.V1.RodReflection.Descriptor.SerializedData);

    [Fact]
    public void MessageFieldNumbers_AreTheFrozenSnapshot()
    {
        var actual = string.Join("\n", Proto().MessageType
            .OrderBy(m => m.Name, StringComparer.Ordinal)
            .Select(m =>
            {
                var fields = string.Join(" ", m.Field
                    .OrderBy(f => f.Number)
                    .Select(f => $"{f.Name}={f.Number}"));
                // The descriptor's ReservedRange end is exclusive; show the
                // closed interval the .proto source writes.
                var reserved = m.ReservedRange
                    .OrderBy(r => r.Start)
                    .Select(r => r.Start == r.End - 1 ? $"{r.Start}" : $"{r.Start}-{r.End - 1}")
                    .ToList();
                return reserved.Count == 0
                    ? $"{m.Name}: {fields}"
                    : $"{m.Name}: {fields} reserved={string.Join(",", reserved)}";
            }));

        Assert.Equal("""
            ChannelInput: task_id=1 data=2 eof=3
            ChannelOutput: task_id=1 data=2
            EnrollRequest: deploy_token_secret=1 class=2 public_key=3 parent_implant_id=4 hostname=5 os=6 arch=7 username=8 kill_date=9 sleep_seconds=10 jitter_seconds=11
            EnrollResponse: status=1 implant_id=2 engagement_id=3 leaf_certificate=4 ca_chain=5 parent_implant_id=6 envelope_key_id=7 envelope_key=8
            ExfilChunk: task_id=1 name=2 content_type=3 sequence=4 terminal=5 data=6 offset=7 payload_sha256=8
            ExfilProgress: task_id=1 name=2 held_bytes=3
            Frame: payload=2 kind=3 reserved=1
            HandshakeRequest: version=1 implant_id=2 capabilities=3 replay_nonces=4 task_acks=5 sleep_seconds=6 jitter_seconds=7
            HandshakeResponse: status=1 version=2 engagement_id=3 replay_nonces=4 task_acks=5
            ProtocolVersion: major=1 minor=2
            StagedChunk: task_id=1 sequence=2 terminal=3 data=4 offset=5
            StagedPull: task_id=1 offset=2 prefix_sha256=3
            TaskAck: task_id=1
            TaskRequest: task_id=1 verb=2 arguments=3 signature=4 staged_bytes=5 task_nonce=6 target_implant_id=7
            TaskResult: task_id=1 outcome=2 output=3 payload_sha256=4
            """, actual);
    }

    [Fact]
    public void EnumValues_AreTheFrozenSnapshot()
    {
        var actual = string.Join("\n", Proto().EnumType
            .OrderBy(e => e.Name, StringComparer.Ordinal)
            .Select(e => $"{e.Name}: " + string.Join(" ", e.Value
                .OrderBy(v => v.Number)
                .Select(v => $"{v.Name}={v.Number}"))));

        Assert.Equal("""
            EnrollStatus: ENROLL_STATUS_UNSPECIFIED=0 ENROLL_STATUS_OK=1 ENROLL_STATUS_BAD_TOKEN=2 ENROLL_STATUS_EXPIRED=3 ENROLL_STATUS_SPENT=4
            FrameKind: FRAME_KIND_UNSPECIFIED=0 FRAME_KIND_TASK_RESULT=1 FRAME_KIND_EXFIL_CHUNK=2 FRAME_KIND_STAGED_PULL=3 FRAME_KIND_CHANNEL_OUTPUT=4 FRAME_KIND_CHANNEL_INPUT=5 FRAME_KIND_TASK_ACK=6 FRAME_KIND_ENROLL_REQUEST=7 FRAME_KIND_ENROLL_RESPONSE=8 FRAME_KIND_EXFIL_PROGRESS=9
            HandshakeStatus: HANDSHAKE_STATUS_UNSPECIFIED=0 HANDSHAKE_STATUS_OK=1 HANDSHAKE_STATUS_VERSION_MISMATCH=2 HANDSHAKE_STATUS_UNKNOWN_IMPLANT=3 HANDSHAKE_STATUS_IDENTITY_MISMATCH=4 HANDSHAKE_STATUS_KILL_DATE_EXPIRED=5 HANDSHAKE_STATUS_IMPLANT_RETIRED=6
            TaskOutcome: TASK_OUTCOME_UNSPECIFIED=0 TASK_OUTCOME_SUCCEEDED=1 TASK_OUTCOME_FAILED=2
            """, actual);
    }
}
