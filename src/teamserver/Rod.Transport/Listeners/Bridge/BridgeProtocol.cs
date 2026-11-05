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
/// frame); <c>R</c> is the route-forward carriage (request/answer units
/// routed by path, the https shape). The values are frozen identifiers,
/// never renamed: a later carriage is a new value, and an unknown value
/// is the dropped connection -- the same additive discipline rod.v1's
/// FrameKind keeps.
/// </summary>
internal static class BridgeCarriage
{
    public const byte Contact = (byte)'C';
    public const byte RouteForward = (byte)'R';
}

/// <summary>
/// The route-forward carriage's unit codec (the https shape, ADR-025):
/// one request unit in, one answer unit out, and a unit is a **field
/// map** -- a counted run of length-prefixed, string-keyed fields with
/// opaque byte values. Nothing is positional, so nothing can move: the
/// request carries <c>method</c>, <c>path</c>, and <c>body</c> beside the
/// medium's observed peer facts (<c>peer</c>, <c>ua</c>, whatever the
/// medium honestly observes), and the answer carries <c>status</c>,
/// <c>content-type</c>, and <c>body</c>. An unknown key is carried and
/// ignored -- a new medium names a new fact with a new key and no format
/// ever changes. This is the HTTP-header / gRPC-metadata model, the same
/// unknown-field discipline rod.v1's own evolution rules keep. The
/// kernel routes by path onto the same cores its own routes drive; the
/// listener terminates the medium and carries bytes.
/// </summary>
internal static class BridgeRouteProtocol
{
    // The request's keys.
    public const string MethodKey = "method";
    public const string PathKey = "path";
    public const string BodyKey = "body";

    // The observed peer facts the kernel's audit facts read today. A
    // medium that observes more names more keys; the kernel ignores what
    // it does not know.
    public const string PeerKey = "peer";
    public const string UserAgentKey = "ua";

    // The header convention both directions keep: a request carries the
    // medium front's observed request headers as <c>header-<lowercase-name></c>
    // fields (the deploy token, the browser-only Origin), and an answer
    // carries the route's response headers the same way (the CORS answer,
    // cache control, a download's disposition). The HTTP-header model this
    // carriage already keeps, spelled once.
    public const string HeaderPrefix = "header-";

    // The answer's keys.
    public const string StatusKey = "status";
    public const string ContentTypeKey = "content-type";

    // The method spellings -- ASCII text, the vocabulary the kernel's
    // route table matches; a method the table does not carry answers 404.
    public const string MethodGet = "GET";
    public const string MethodPost = "POST";

    /// <summary>
    /// A unit is a handful of facts; a count beyond any honest one is a
    /// malformed unit, dropped like every other malformed shape.
    /// </summary>
    public const int MaxFields = 64;

    /// <summary>Encodes one unit from its fields, in the order given.
    /// The varint framing around the unit is
    /// <see cref="StreamContactFraming"/>'s own.</summary>
    public static byte[] EncodeUnit(IEnumerable<KeyValuePair<string, byte[]>> fields)
    {
        var ordered = fields.ToArray();
        var buffer = new MemoryStream();
        WriteVarint(buffer, (ulong)ordered.Length);
        foreach (var (key, value) in ordered)
        {
            var keyBytes = System.Text.Encoding.UTF8.GetBytes(key);
            WriteVarint(buffer, (ulong)keyBytes.Length);
            buffer.Write(keyBytes);
            WriteVarint(buffer, (ulong)value.Length);
            buffer.Write(value);
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// Decodes one unit into its field map. False answers a malformed
    /// unit -- the connection is dropped, the same refusal every bridge
    /// shape keeps. A duplicate key takes the last value; an unknown key
    /// rides through, none of the kernel's business until it is.
    /// </summary>
    public static bool TryDecodeUnit(byte[] message, out IReadOnlyDictionary<string, byte[]> fields)
    {
        fields = new Dictionary<string, byte[]>();
        var offset = 0;
        if (!TryReadVarint(message, ref offset, out var count) || count > (ulong)MaxFields)
            return false;

        var decoded = (Dictionary<string, byte[]>)fields;
        for (var i = 0; i < (int)count; i++)
        {
            if (!TryReadBytes(message, ref offset, out var keyBytes)
                || !TryReadBytes(message, ref offset, out var value))
                return false;
            decoded[System.Text.Encoding.UTF8.GetString(keyBytes)] = value;
        }
        return offset <= message.Length;
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

    private static bool TryReadVarint(byte[] message, ref int offset, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (true)
        {
            if (offset >= message.Length || shift > 28)
                return false;
            var read = message[offset++];
            value |= (ulong)(read & 0x7f) << shift;
            if ((read & 0x80) == 0)
                return true;
            shift += 7;
        }
    }

    private static bool TryReadBytes(byte[] message, ref int offset, out byte[] value)
    {
        value = [];
        if (!TryReadVarint(message, ref offset, out var length) || length > (ulong)(message.Length - offset))
            return false;
        value = message[offset..(offset + (int)length)];
        offset += (int)length;
        return true;
    }
}
