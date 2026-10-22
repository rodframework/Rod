using Google.Protobuf;
using Rod.V1;

namespace Rod.Transport.Endpoints;

// The plain-HTTP envelope framing (architecture.md Sec 8, the implant-reach
// escape hatch): the same rod.v1 Frames the live carriages carry, marshaled as
// varint-length-delimited sequences in ordinary HTTP request/response bodies.
// The delimiter is the protobuf canonical delimited-stream prefix -- an
// unsigned 32-bit varint length before each marshaled Frame -- so any language
// with an HTTP client and a protobuf codec speaks it without a gRPC stack
// (extending/implants.md).

/// <summary>
/// Encodes and decodes envelope bodies: a varint-length-delimited sequence of
/// rod.v1 <see cref="Frame"/> messages. All reads are bounded -- a frame over
/// <see cref="MaxFrameBytes"/>, a sequence over <see cref="MaxFrames"/>, a body
/// over <see cref="MaxBodyBytes"/>, or any truncated or unparseable delimiter
/// is refused rather than buffered.
/// </summary>
internal static class EnvelopeFraming
{
    /// <summary>
    /// The per-frame cap: the budget every carrier enforces, so a frame
    /// legal on one transport is legal on the other.
    /// </summary>
    public const int MaxFrameBytes = 2 * 1024 * 1024;

    /// <summary>
    /// The frame-count flood guard for one request: a poll contact carries a
    /// handshake plus a bounded run of results and chunks, and anything past
    /// this is a flood, not a contact.
    /// </summary>
    public const int MaxFrames = 1024;

    /// <summary>
    /// The whole-body cap for one request: bounds the reassembly and parse cost
    /// of a single POST regardless of how legal each frame is. A resumable
    /// exfil run larger than this ceiling spans contacts -- the shared
    /// per-task reassembly holds the placed bytes across them
    /// (extending/implants.md).
    /// </summary>
    public const int MaxBodyBytes = 16 * 1024 * 1024;

    /// <summary>
    /// Copies the request body into memory, refusing a body over
    /// <see cref="MaxBodyBytes"/> as oversized rather than buffering it whole.
    /// </summary>
    public static async Task<byte[]> ReadBodyAsync(Stream body, CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        var chunk = new byte[64 * 1024];
        while (true)
        {
            var read = await body.ReadAsync(chunk, cancellationToken);
            if (read == 0)
                break;
            if (buffer.Length + read > MaxBodyBytes)
                throw new EnvelopeFramingException(oversized: true);
            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// Parses a delimited frame sequence. Throws
    /// <see cref="EnvelopeFramingException"/> on a malformed body (truncated
    /// or unparseable) or an oversized one (a frame, count, or implied body
    /// over its cap); the endpoint maps the two onto distinct HTTP statuses.
    /// </summary>
    public static List<Frame> Parse(byte[] body)
    {
        var frames = new List<Frame>();
        var position = 0;
        while (position < body.Length)
        {
            if (frames.Count >= MaxFrames)
                throw new EnvelopeFramingException(oversized: true);

            if (!TryReadVarint(body, ref position, out var length))
                throw new EnvelopeFramingException(oversized: false);
            if (length > MaxFrameBytes)
                throw new EnvelopeFramingException(oversized: true);
            if (position + length > body.Length)
                throw new EnvelopeFramingException(oversized: false);

            Frame frame;
            try
            {
                frame = Frame.Parser.ParseFrom(body, position, (int)length);
            }
            catch (InvalidProtocolBufferException)
            {
                throw new EnvelopeFramingException(oversized: false);
            }
            frames.Add(frame);
            position += (int)length;
        }
        return frames;
    }

    /// <summary>
    /// Encodes frames as one delimited sequence, the response-body mirror of
    /// <see cref="Parse"/>.
    /// </summary>
    public static byte[] Encode(IReadOnlyList<Frame> frames)
    {
        var body = new MemoryStream();
        foreach (var frame in frames)
        {
            var marshaled = frame.ToByteArray();
            WriteVarint(body, marshaled.Length);
            body.Write(marshaled);
        }
        return body.ToArray();
    }

    /// <summary>The wire size one frame occupies in an envelope body: its
    /// delimited length plus the varint delimiter itself.</summary>
    public static int WireSize(Frame frame)
    {
        var marshaled = frame.ToByteArray();
        return marshaled.Length + VarintLength(marshaled.Length);
    }

    private static bool TryReadVarint(byte[] source, ref int position, out uint value)
    {
        value = 0;
        var shift = 0;
        for (var consumed = 0; consumed < 5; consumed++)
        {
            if (position >= source.Length)
                return false;
            var b = source[position++];
            value |= (uint)(b & 0x7f) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }
        return false; // More than 5 bytes: not a uint32 varint.
    }

    private static void WriteVarint(Stream target, int value)
    {
        uint remaining = (uint)value;
        while (remaining >= 0x80)
        {
            target.WriteByte((byte)(remaining | 0x80));
            remaining >>= 7;
        }
        target.WriteByte((byte)remaining);
    }

    private static int VarintLength(int value)
    {
        var length = 1;
        uint remaining = (uint)value;
        while (remaining >= 0x80)
        {
            remaining >>= 7;
            length++;
        }
        return length;
    }
}

/// <summary>
/// A refused envelope body. <see cref="Oversized"/> distinguishes the
/// size-cap refusals (HTTP 413) from malformed framing (HTTP 400).
/// </summary>
internal sealed class EnvelopeFramingException(bool oversized) : Exception
{
    public bool Oversized { get; } = oversized;
}
