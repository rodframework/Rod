using System.Buffers.Binary;
using Rod.Transport.Listeners.Streams;

namespace Rod.Transport.Listeners.Bridge;

// The bridge wire contract (ADR-025, extending/listeners.md): the carriage
// a listener process speaks to the kernel over its per-listener local
// socket. One connection is one medium peer. The first byte the peer sends
// selects the carriage; every message after it rides the same
// self-delimited framing the raw-TCP family carries
// (StreamContactFraming): a varint byte length, then exactly that many
// bytes. Nothing here parses rod.v1 grammar -- the bytes are the medium's
// own payload units, opaque to the listener and opaque to the bridge.

/// <summary>
/// The bridge's one-byte carriage selection: the first byte each peer
/// sends after connecting. <c>C</c> is the rod.v1 contact stream (the
/// Beacon.Contact carriage: one message per contact body, sealed or
/// plaintext, enrollment riding the opening message as an EnrollRequest
/// frame); <c>R</c> is the route-forward carriage (request/response units
/// dispatched by path, the https shape).
/// </summary>
internal static class BridgeCarriage
{
    public const byte Contact = (byte)'C';
    public const byte RouteForward = (byte)'R';
}

/// <summary>
/// The route-forward carriage's message codec (the https shape,
/// ADR-025): one request unit in -- the method, the path, the observed
/// peer address and User-Agent (the facts the kernel's audit wants and
/// the medium's own face is the only place to read them from), and the
/// body -- and one answer unit out: the status, the content type, and
/// the body. The kernel routes by path onto the same cores the HTTP
// routes drive; the listener terminates the medium and carries bytes.
/// </summary>
internal static class BridgeRouteProtocol
{
    public const byte MethodGet = 0;
    public const byte MethodPost = 1;

    /// <summary>Encodes one forwarded request. The varint framing around
    /// the unit is <see cref="StreamContactFraming"/>'s own.</summary>
    public static byte[] EncodeRequest(byte method, string path, string peer, string userAgent, byte[] body)
    {
        var buffer = new MemoryStream();
        buffer.WriteByte(method);
        WriteString(buffer, path);
        WriteString(buffer, peer);
        WriteString(buffer, userAgent);
        buffer.Write(body);
        return buffer.ToArray();
    }

    /// <summary>
    /// Decodes one forwarded request. False answers a malformed unit -- the
    /// connection is dropped, the same refusal every bridge shape keeps.
    /// </summary>
    public static bool TryDecodeRequest(
        byte[] message, out byte method, out string path, out string peer, out string userAgent, out byte[] body)
    {
        method = 0;
        path = "";
        peer = "";
        userAgent = "";
        body = [];
        var offset = 0;
        if (message.Length < 1)
            return false;
        method = message[offset++];
        if (!TryReadString(message, ref offset, out path))
            return false;
        if (!TryReadString(message, ref offset, out peer))
            return false;
        if (!TryReadString(message, ref offset, out userAgent))
            return false;
        body = message[offset..];
        return true;
    }

    /// <summary>Encodes one forwarded answer: status, content type,
    /// body.</summary>
    public static byte[] EncodeResponse(int status, string contentType, byte[] body)
    {
        var buffer = new MemoryStream(2 + 5 + contentType.Length + body.Length);
        Span<byte> statusBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(statusBytes, (ushort)status);
        buffer.Write(statusBytes);
        WriteString(buffer, contentType);
        buffer.Write(body);
        return buffer.ToArray();
    }

    /// <summary>Decodes one forwarded answer (the fixture candidate's other
    /// half; the kernel side only encodes).</summary>
    public static bool TryDecodeResponse(
        byte[] message, out int status, out string contentType, out byte[] body)
    {
        status = 0;
        contentType = "";
        body = [];
        var offset = 0;
        if (message.Length < 2)
            return false;
        status = BinaryPrimitives.ReadUInt16BigEndian(message);
        offset = 2;
        if (!TryReadString(message, ref offset, out contentType))
            return false;
        body = message[offset..];
        return true;
    }

    private static void WriteString(MemoryStream buffer, string value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(value);
        WriteVarint(buffer, (ulong)bytes.Length);
        buffer.Write(bytes);
    }

    private static bool TryReadString(byte[] message, ref int offset, out string value)
    {
        value = "";
        ulong length = 0;
        var shift = 0;
        while (true)
        {
            if (offset >= message.Length || shift > 28)
                return false;
            var read = message[offset++];
            length |= (ulong)(read & 0x7f) << shift;
            if ((read & 0x80) == 0)
                break;
            shift += 7;
        }
        if (length > (ulong)(message.Length - offset))
            return false;
        value = System.Text.Encoding.UTF8.GetString(message, offset, (int)length);
        offset += (int)length;
        return true;
    }

    private static void WriteVarint(MemoryStream buffer, ulong value)
    {
        while (value >= 0x80)
        {
            buffer.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }
        buffer.WriteByte((byte)value);
    }
}
