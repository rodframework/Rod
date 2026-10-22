using System.Collections.Concurrent;
using Rod.CoreState;

namespace Rod.Transport.Listeners.Dns;

// The DNS contact name grammar (architecture.md Sec 8, the DNS listener's
// contract, documented for implant authors in extending/implants.md). Every
// contact is a TXT query under the listener's zone -- the listener's public
// endpoint, a domain the teamserver answers for. The query NAME carries the
// implant's message, base32-encoded into labels (DNS labels are case-
// insensitive; the encoding is lowercase RFC 4648 without padding):
//
//   poll (presence + fetch next tasking):
//     p.<b32(implant id)>.<zone>
//
//   key-named poll (the sealed carriage, an artifact whose build baked an
//   envelope key): the poll names the key id, so the answer is sealed under
//   that key -- the raw R1 AES-GCM body, base32 like every TXT payload here:
//     k.<b32(implant id)>.<b32(key id)>.<zone>
//
//   result chunk (report a task's outcome, short outputs only):
//     r.<b32(task id)>.<outcome s|f>.<seq>.<terminal t|m>.<b32(chunk)>.<b32(implant id)>.<zone>
//
//   delivery probe (did my result or channel output for this task land?):
//     n.<b32(task id)>.<b32(sha128 of the plaintext)>.<b32(implant id)>.<zone>
//   answered TXT y/n -- the retransmission half: a lost chunk drops the
//   reassembly server-side, so the sender keeps the frame pending until
//   the probe confirms its blob landed (first-wins makes the re-send
//   idempotent).
//
//   staged demand (pull a staged task's payload from a byte offset,
//   ADR-010): the offset is decimal, the prefix proof is the b32 of the
//   held bytes' SHA-256 (the bare label 'e' on a fresh demand), and the
//   answer is "=<b32 token>" naming a chunked download:
//     s.<b32(task id)>.<offset>.<b32(sha256) | e>.<b32(implant id)>.<zone>
//
//   staged download chunk (the token-keyed answer, the a.-probe shape):
//     d.<b32(token)>.<seq>.<zone>
//   answered "<t|m>.<b32(chunk)>" -- the chunk seals as a raw R1 body under
//   the staged tag for a key-bound implant; the sequence indexes 200-byte
//   slices from the honored seam.
//
// A poll is answered with zero or one TXT record whose strings concatenate to
// the base32 of a signed rod.v1 TaskRequest; a result is answered with an
// empty NOERROR answer. The chunk sequence is 0-origin decimal; the terminal
// flag closes the reassembly. Short-argument tasking only: a TaskRequest that
// does not fit the DNS budget is not claimed over this transport.
//
// Sealing (an artifact with a baked envelope key, the same posture the web
// envelope contacts carry): the k-poll's answer and the r/c chunks wrap their
// payloads as raw R1 bodies under purpose-specific AADs, so the resolver chain
// reads no frame bytes in the clear; a p-poll from a key-bound implant is
// answered empty (the downgrade refusal -- plaintext tasking is not handed to
// an artifact known to carry a key), and a plaintext r/c reassembly from one
// is dropped the same way.

/// <summary>
/// Parses and renders the contact query names. Pure grammar, no I/O -- the
/// listener service and the tests share one definition.
/// </summary>
internal static class DnsContactNames
{
    /// <summary>A poll: the implant's presence ping and task fetch.</summary>
    internal sealed record Poll(ImplantId Implant);

    /// <summary>
    /// A key-named poll: the same presence ping and task fetch, with the
    /// artifact's envelope key id riding the name so the answer seals under
    /// that key -- the resolver chain reads no tasking bytes in the clear.
    /// </summary>
    internal sealed record SealedPoll(ImplantId Implant, Guid KeyId);

    /// <summary>One chunk of a task result the implant reports back.</summary>
    internal sealed record ResultChunk(
        ImplantId Implant,
        TaskId Task,
        Rod.CoreState.Tasks.TaskOutcome Outcome,
        int Sequence,
        bool Terminal,
        byte[] Chunk);

    /// <summary>
    /// One chunk of a live channel's output (architecture.md Sec 10.3, the
    /// store-and-forward carriage over DNS): the chunks reassemble into one
    /// marshaled ChannelOutput message.
    /// </summary>
    internal sealed record ChannelChunk(
        ImplantId Implant,
        TaskId Task,
        int Sequence,
        bool Terminal,
        byte[] Chunk);

    /// <summary>
    /// One chunk of an enrollment upload (architecture.md Sec 8, enrollment
    /// over DNS): the client-chosen stream id keys the reassembly, the
    /// terminal chunk assembles the (sealed or plaintext) enroll body.
    /// </summary>
    internal sealed record EnrollChunk(byte[] Stream, int Sequence, bool Terminal, byte[] Chunk);

    /// <summary>One probe of an enrollment answer: a token, a chunk index.</summary>
    internal sealed record EnrollAnswerProbe(byte[] Token, int Sequence);

    /// <summary>
    /// One demand for a staged task's payload (ADR-010): the byte offset the
    /// demanding implant holds, with its SHA-256 prefix proof -- null on a
    /// fresh demand.
    /// </summary>
    internal sealed record StagedDemand(ImplantId Implant, TaskId Task, long Offset, byte[]? PrefixSha);

    /// <summary>
    /// One probe of a staged download: the token the demand's answer named,
    /// and the chunk index within it.
    /// </summary>
    internal sealed record StagedDownloadProbe(byte[] Token, int Sequence);

    /// <summary>
    /// One delivery probe: the task the sender reported to, and the first 16
    /// bytes of SHA-256 over the report's plaintext -- the identity of the
    /// exact blob whose landing the sender asks about.
    /// </summary>
    internal sealed record DeliveryProbe(ImplantId Implant, TaskId Task, byte[] Sha);

    /// <summary>
    /// Parses a query name against <paramref name="zone"/>. Returns the poll
    /// or result-chunk view, or null when the name is not a contact under
    /// this zone (other names in the zone are answered NXDOMAIN by the
    /// listener, not parsed here).
    /// </summary>
    public static Poll? TryParsePoll(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 2 || labels[0] != "p")
            return null;
        if (!TryDecodeId(labels[1], out var implant))
            return null;
        return new Poll(implant);
    }

    /// <summary>
    /// Parses a key-named poll against <paramref name="zone"/>:
    /// k.&lt;b32(implant id)&gt;.&lt;b32(key id)&gt;. The key id is the raw
    /// 16-byte guid form, the same bytes the baked key packs.
    /// </summary>
    public static SealedPoll? TryParseSealedPoll(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 3 || labels[0] != "k")
            return null;
        if (!TryDecodeId(labels[1], out var implant))
            return null;
        if (!TryDecode(labels[2], out var keyBytes) || keyBytes.Length != 16)
            return null;
        return new SealedPoll(implant, new Guid(keyBytes));
    }

    public static ResultChunk? TryParseResult(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 7 || labels[0] != "r")
            return null;
        if (!TryDecodeId(labels[6], out var implant))
            return null;
        if (!TryDecode(labels[1], out var taskBytes)
            || !TaskId.TryParse(System.Text.Encoding.UTF8.GetString(taskBytes), out var task))
            return null;

        var outcome = labels[2] switch
        {
            "s" => Rod.CoreState.Tasks.TaskOutcome.Succeeded,
            "f" => Rod.CoreState.Tasks.TaskOutcome.Failed,
            _ => (Rod.CoreState.Tasks.TaskOutcome?)null,
        };
        var terminal = labels[4] switch
        {
            "t" => true,
            "m" => false,
            _ => (bool?)null,
        };
        if (outcome is null || terminal is null || !int.TryParse(labels[3], out var sequence) || sequence < 0)
            return null;

        // An empty chunk rides as the bare label "e": base32 of zero bytes
        // would render an empty label, which a DNS name cannot carry.
        var chunk = labels[5] == "e"
            ? Array.Empty<byte>()
            : TryDecode(labels[5], out var decoded) ? decoded : null;
        if (chunk is null)
            return null;

        return new ResultChunk(implant, task, outcome.Value, sequence, terminal.Value, chunk);
    }

    /// <summary>
    /// Parses a channel-output chunk against <paramref name="zone"/>:
    /// c.&lt;task&gt;.&lt;seq&gt;.&lt;t|m&gt;.&lt;chunk&gt;.&lt;implant&gt;.
    /// </summary>
    public static ChannelChunk? TryParseChannel(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 6 || labels[0] != "c")
            return null;
        if (!TryDecodeId(labels[5], out var implant))
            return null;
        if (!TryDecode(labels[1], out var taskBytes)
            || !TaskId.TryParse(System.Text.Encoding.UTF8.GetString(taskBytes), out var task))
            return null;
        var terminal = labels[3] switch
        {
            "t" => true,
            "m" => false,
            _ => (bool?)null,
        };
        if (terminal is null || !int.TryParse(labels[2], out var sequence) || sequence < 0)
            return null;
        var chunk = labels[4] == "e"
            ? Array.Empty<byte>()
            : TryDecode(labels[4], out var decoded) ? decoded : null;
        if (chunk is null)
            return null;
        return new ChannelChunk(implant, task, sequence, terminal.Value, chunk);
    }

    /// <summary>Renders a poll name (the implant-side twin of the parser).</summary>
    public static string PollName(ImplantId implant, string zone)
        => $"p.{Encode(implant.ToString())}.{zone}";

    /// <summary>
    /// Renders a key-named poll (the implant-side twin of the parser): the
    /// key id rides as its raw 16 guid bytes, base32 like every label.
    /// </summary>
    public static string SealedPollName(ImplantId implant, Guid keyId, string zone)
        => $"k.{Encode(implant.ToString())}.{Encode(keyId.ToByteArray())}.{zone}";

    /// <summary>Renders a result-chunk name under <paramref name="zone"/>.</summary>
    public static string ResultName(
        ImplantId implant, TaskId task, bool succeeded, int sequence, bool terminal, byte[] chunk, string zone)
        => "r." + Encode(task.ToString())
            + "." + (succeeded ? "s" : "f")
            + "." + sequence.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + "." + (terminal ? "t" : "m")
            + "." + (chunk.Length == 0 ? "e" : Encode(chunk))
            + "." + Encode(implant.ToString())
            + "." + zone;

    /// <summary>
    /// Parses an enrollment-upload chunk against <paramref name="zone"/>:
    /// e.&lt;stream&gt;.&lt;seq&gt;.&lt;t|m&gt;.&lt;chunk&gt;.
    /// </summary>
    public static EnrollChunk? TryParseEnroll(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 5 || labels[0] != "e")
            return null;
        if (!TryDecode(labels[1], out var stream) || stream.Length == 0)
            return null;
        var terminal = labels[3] switch
        {
            "t" => true,
            "m" => false,
            _ => (bool?)null,
        };
        if (terminal is null || !int.TryParse(labels[2], out var sequence) || sequence < 0)
            return null;
        var chunk = labels[4] == "e"
            ? Array.Empty<byte>()
            : TryDecode(labels[4], out var decoded) ? decoded : null;
        if (chunk is null)
            return null;
        return new EnrollChunk(stream, sequence, terminal.Value, chunk);
    }

    /// <summary>
    /// Parses an enrollment-answer probe against <paramref name="zone"/>:
    /// a.&lt;token&gt;.&lt;seq&gt;.
    /// </summary>
    public static EnrollAnswerProbe? TryParseEnrollAnswer(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 3 || labels[0] != "a")
            return null;
        if (!TryDecode(labels[1], out var token) || token.Length == 0)
            return null;
        if (!int.TryParse(labels[2], out var sequence) || sequence < 0)
            return null;
        return new EnrollAnswerProbe(token, sequence);
    }

    /// <summary>
    /// Parses a staged-payload demand against <paramref name="zone"/>:
    /// s.&lt;task&gt;.&lt;offset&gt;.&lt;b32(sha256) | e&gt;.&lt;implant&gt;.
    /// The offset is decimal; the proof label 'e' names a fresh demand.
    /// </summary>
    public static StagedDemand? TryParseStaged(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 5 || labels[0] != "s")
            return null;
        if (!TryDecodeId(labels[4], out var implant))
            return null;
        if (!TryDecode(labels[1], out var taskBytes)
            || !TaskId.TryParse(System.Text.Encoding.UTF8.GetString(taskBytes), out var task))
            return null;
        if (!long.TryParse(labels[2], out var offset) || offset < 0)
            return null;
        var proof = labels[3] == "e"
            ? null
            : TryDecode(labels[3], out var decoded) ? decoded : null;
        if (proof is not null && proof.Length != 32)
            return null;
        return new StagedDemand(implant, task, offset, proof);
    }

    /// <summary>
    /// Parses a staged-download probe against <paramref name="zone"/>:
    /// d.&lt;token&gt;.&lt;seq&gt;.
    /// </summary>
    public static StagedDownloadProbe? TryParseStagedDownload(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 3 || labels[0] != "d")
            return null;
        if (!TryDecode(labels[1], out var token) || token.Length == 0)
            return null;
        if (!int.TryParse(labels[2], out var sequence) || sequence < 0)
            return null;
        return new StagedDownloadProbe(token, sequence);
    }

    /// <summary>
    /// Parses a delivery probe against <paramref name="zone"/>:
    /// n.&lt;b32(task id)&gt;.&lt;b32(sha128)&gt;.&lt;b32(implant id)&gt;.
    /// </summary>
    public static DeliveryProbe? TryParseDelivery(string name, string zone)
    {
        if (!TryStripZone(name, zone, out var labels))
            return null;
        if (labels.Length != 4 || labels[0] != "n")
            return null;
        if (!TryDecodeId(labels[3], out var implant))
            return null;
        if (!TryDecode(labels[1], out var taskBytes)
            || !TaskId.TryParse(System.Text.Encoding.UTF8.GetString(taskBytes), out var task))
            return null;
        if (!TryDecode(labels[2], out var sha) || sha.Length == 0 || sha.Length > 32)
            return null;
        return new DeliveryProbe(implant, task, sha);
    }

    /// <summary>
    /// Renders a delivery probe name (the implant-side twin of the parser).
    /// </summary>
    public static string ProbeName(ImplantId implant, TaskId task, byte[] sha, string zone)
        => "n." + Encode(task.ToString())
            + "." + Encode(sha)
            + "." + Encode(implant.ToString())
            + "." + zone;

    /// <summary>
    /// The delivery probe's blob identity: the first 16 SHA-256 bytes over
    /// the report's plaintext, the value both sender and server can compute.
    /// </summary>
    public static byte[] DeliverySha(byte[] plaintext)
        => System.Security.Cryptography.SHA256.HashData(plaintext)[..16];

    /// <summary>The zone label suffix a name must end with, case-insensitive.</summary>
    private static bool TryStripZone(string name, string zone, out string[] labels)
    {
        labels = Array.Empty<string>();
        if (!name.EndsWith(zone, StringComparison.OrdinalIgnoreCase))
            return false;
        var head = name[..^zone.Length].TrimEnd('.');
        if (head.Length == 0)
            return false;
        labels = head.Split('.');
        return labels.Length > 0 && labels[0] is "p" or "k" or "r" or "c" or "e" or "a" or "n" or "s" or "d";
    }

    private static bool TryDecodeId(string label, out ImplantId implant)
    {
        implant = default;
        if (!TryDecode(label, out var raw))
            return false;
        if (!Guid.TryParse(System.Text.Encoding.UTF8.GetString(raw), out var value))
            return false;
        implant = new ImplantId(value);
        return true;
    }

    /// <summary>Lowercase RFC 4648 base32 without padding.</summary>
    public static string Encode(byte[] bytes)
        => Base32Lower(bytes);

    /// <summary>Encodes a UTF-8 string's bytes.</summary>
    public static string Encode(string text)
        => Base32Lower(System.Text.Encoding.UTF8.GetBytes(text));

    /// <summary>Decodes base32 (either case, padding tolerated).</summary>
    public static bool TryDecode(string text, out byte[] bytes)
    {
        try
        {
            bytes = System.Convert.FromHexString(ToHex(text));
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    // Base32 decode without System.Buffers.Text base32 support (the BCL has
    // none): map the RFC 4648 alphabet back to bits via a hex intermediate.
    private static string ToHex(string text)
    {
        var clean = text.TrimEnd('=').ToUpperInvariant();
        var bits = 0;
        var bitCount = 0;
        var hex = new System.Text.StringBuilder(clean.Length);
        foreach (var c in clean)
        {
            var value = c switch
            {
                >= 'A' and <= 'Z' => c - 'A',
                >= '2' and <= '7' => c - '2' + 26,
                _ => throw new FormatException("Not base32."),
            };
            bits = (bits << 5) | value;
            bitCount += 5;
            if (bitCount >= 8)
            {
                bitCount -= 8;
                hex.Append(((bits >> bitCount) & 0xFF).ToString("X2"));
            }
        }
        // Trailing partial bits are padding, not data; the encoder never emits
        // them, so a clean multiple of 40 bits decodes losslessly.
        return hex.ToString();
    }

    private static string Base32Lower(byte[] bytes)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var sb = new System.Text.StringBuilder((bytes.Length * 8 + 4) / 5);
        var bits = 0;
        var bitCount = 0;
        foreach (var b in bytes)
        {
            bits = (bits << 8) | b;
            bitCount += 8;
            while (bitCount >= 5)
            {
                bitCount -= 5;
                sb.Append(alphabet[(bits >> bitCount) & 0x1F]);
            }
        }
        if (bitCount > 0)
            sb.Append(alphabet[(bits << (5 - bitCount)) & 0x1F]);
        return sb.ToString();
    }

    /// <summary>
    /// The bounded reassembly buffer for result chunks: per-task chunk maps
    /// with a total-size cap and an entry cap so a spoofed flood cannot grow
    /// the listener without bound. Entries vanish on completion, on the idle
    /// window, or when the caps push the least recently touched entry out --
    /// never the task in hand, so spoofed debris occupying the map cannot
    /// starve a live task's chunks.
    /// </summary>
    internal sealed class ResultReassembler
    {
        // One task's state under the gate: its chunks in arrival order, the
        // running byte total, and the last-chunk stamp the idle window and
        // the entry cap evict by.
        private sealed class Entry
        {
            public required List<(int Sequence, byte[] Chunk)> Chunks { get; init; }
            public long Bytes;
            public DateTimeOffset Touched;
        }

        private readonly object _gate = new();
        private readonly TimeProvider _clock;
        private readonly Dictionary<TaskId, Entry> _byTask = new();

        // The per-task output ceiling, sealed overhead included: a keyed
        // artifact's blob is plaintext plus the R1 body's fixed 46 bytes, so
        // the cap keeps the same plaintext capacity it always had.
        public const int MaxTaskBytes = 4 * 1024 + 64;
        public const int MaxTasks = 256;

        /// <summary>
        /// A task that has not heard a chunk in this window is abandoned --
        /// dropped mid-sequence results and spoofed debris alike leave on
        /// idle, not only on completion or the caps.
        /// </summary>
        public static readonly TimeSpan IdleEviction = TimeSpan.FromMinutes(10);

        public ResultReassembler(TimeProvider? clock = null)
            => _clock = clock ?? TimeProvider.System;

        /// <summary>
        /// Adds a chunk; on the terminal chunk, returns the concatenated
        /// output when the sequence is contiguous 0..n, else null (the
        /// reassembly is dropped). Non-terminal adds return null.
        /// </summary>
        public byte[]? Add(TaskId task, int sequence, bool terminal, byte[] chunk)
        {
            lock (_gate)
            {
                var now = _clock.GetUtcNow();
                foreach (var stale in _byTask
                             .Where(kv => now - kv.Value.Touched > IdleEviction)
                             .Select(kv => kv.Key)
                             .ToArray())
                {
                    _byTask.Remove(stale);
                }

                if (!_byTask.TryGetValue(task, out var entry))
                {
                    // The caps push out the least recently touched entry so
                    // the map always admits the task in hand.
                    while (_byTask.Count >= MaxTasks)
                    {
                        var lru = _byTask.Aggregate((a, b) => a.Value.Touched <= b.Value.Touched ? a : b).Key;
                        _byTask.Remove(lru);
                    }
                    entry = new Entry { Chunks = new List<(int, byte[])>(), Bytes = 0, Touched = now };
                    _byTask[task] = entry;
                }

                entry.Touched = now;
                entry.Bytes += chunk.Length;
                if (entry.Bytes > MaxTaskBytes)
                {
                    _byTask.Remove(task);
                    return null;
                }
                entry.Chunks.Add((sequence, chunk));

                if (!terminal)
                    return null;

                _byTask.Remove(task);
                if (!TryConcatenate(entry.Chunks, out var output))
                    return null;
                return output;
            }
        }

        private static bool TryConcatenate(List<(int Sequence, byte[] Chunk)> chunks, out byte[] output)
        {
            var ordered = chunks.OrderBy(c => c.Sequence).ToArray();
            if (ordered.Length == 0 || ordered[0].Sequence != 0 || ordered[^1].Sequence != ordered.Length - 1)
            {
                output = Array.Empty<byte>();
                return false; // not contiguous from zero: a chunk went missing
            }
            var total = ordered.Sum(c => c.Chunk.Length);
            var buffer = new byte[total];
            var offset = 0;
            foreach (var (_, chunk) in ordered)
            {
                chunk.CopyTo(buffer, offset);
                offset += chunk.Length;
            }
            output = buffer;
            return true;
        }
    }
}
