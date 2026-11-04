using System.Buffers.Binary;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Text;
using System.Threading.Channels;
using Rod.Audit;
using Rod.CoreState;
using Rod.CoreState.Operators;
using Rod.CoreState.Tasks;
using Rod.Transport.Listeners.Streams;
// The domain entity shares its name with the BCL Task; this file names both,
// so alias each to itself and let the references stay explicit.
using Task = System.Threading.Tasks.Task;

namespace Rod.Transport.Channels;

// The chained-contact half of the tunnel bind (architecture.md Sec 5.2,
// Sec 8): the server side of a parent implant's tunnel.bind channel. Where
// the relay bind bridges a teamserver-side listener onto a channel, the
// chain link bridges the channel onto the contact machinery -- every
// connection the parent's listener accepted rides the channel as packets,
// and each becomes one contact served through the shared stream bridge:
// enrollment, handshake, ingest, and dispatch, the whole ordinary contact
// flow, with the parent's channel standing in for the listener socket.
//
// The grammar is the verb's own (Sec 10: a channel's byte stream is its
// verb's grammar), mirrored from the implant-side handler:
//
//     packet := kind(1) connection(4, LE) length(2, LE) payload(length)
//     bound  (1): payload := "host:port" -- the listener's actual address
//     open   (2): payload := the accepted peer's address
//     data   (3): payload := the carried bytes, at most 16384
//     close  (4): payload empty -- the connection ended, either direction
//     eof    (5): payload empty -- downstream only; the far side's write
//                 half ends and the socket's write half closes
//
// The parent allocates the connection ids (it is the side accepting); this
// side echoes them. Downstream packets ride the same LiveChannelHub enqueue
// the operator input route uses, so the chain link is a machine-shaped
// stand-in for the operator the way the relay bind is -- and every contact
// the link serves attributes its own records: the child's enrollment and
// tasking arc to the child, the carriage's records to the parent, the
// lineage between them recorded at enrollment (Sec 5.2). The link lives and
// dies with the task -- the final TaskResult, the beacon stream ending, or
// a malformed grammar all close it -- the session-scoped lifetime every
// channel verb shares.

/// <summary>
/// The registry of live chain links: one per dispatched tunnel.bind task.
/// Hands the task's channel output to its link's grammar parser, and closes
/// every link when its task or stream ends. Singleton, like the hub it
/// feeds.
/// </summary>
internal sealed class ChainHub
{
    private readonly LiveChannelHub _channels;
    private readonly DegradedChannelHub _degraded;
    private readonly Func<StreamBeaconBridge> _bridge;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;
    private readonly Microsoft.Extensions.Logging.ILogger<ChainHub> _logger;
    private readonly ConcurrentDictionary<Guid, ChainLink> _byTask = new();

    public ChainHub(
        LiveChannelHub channels,
        DegradedChannelHub degraded,
        Func<StreamBeaconBridge> bridge,
        IAuditStore audit,
        TimeProvider clock,
        Microsoft.Extensions.Logging.ILogger<ChainHub> logger)
    {
        _channels = channels;
        _degraded = degraded;
        _bridge = bridge;
        _audit = audit;
        _clock = clock;
        _logger = logger;
    }

    /// <summary>
    /// Hands one channel output chunk to the task's chain link, raw. False
    /// (a no-op, never an error) when the task is not a chain bind -- the
    /// common case on every other channel. Called from the beacon ingest
    /// before the chunk decodes for the transcript; the link re-frames the
    /// stream and routes each packet to its contact. A link is created on
    /// the task's first chunk, so a dispatched bind starts serving with the
    /// listener's bound packet and needs no bind route of its own.
    /// </summary>
    public bool TryDeliver(Rod.CoreState.Tasks.Task task, ReadOnlyMemory<byte> data)
    {
        if (!string.Equals(task.Verb, ChannelVerbs.TunnelBind, StringComparison.OrdinalIgnoreCase))
            return false;

        var link = _byTask.GetOrAdd(
            task.Id.Value, _ => new ChainLink(
                _channels, _degraded, _bridge(), _audit, _clock, task, _logger));
        return link.Deliver(data);
    }

    /// <summary>
    /// Closes the task's chain link -- the final TaskResult landed, so the
    /// channel and every contact bridged onto it are over.
    /// </summary>
    public void CloseTask(Guid taskId, string reason)
    {
        if (_byTask.TryRemove(taskId, out var link))
            link.Close(reason);
    }

    /// <summary>
    /// Closes every link riding the implant's channels -- its beacon stream
    /// ended, and a channel is session-scoped (architecture.md Sec 10.3):
    /// the link dies with the stream that carried it, and every chained
    /// contact it held ends with it.
    /// </summary>
    public void CloseImplant(ImplantId implant, string reason)
    {
        foreach (var (taskId, link) in _byTask)
        {
            if (link.Implant == implant && _byTask.TryRemove(taskId, out var removed))
                removed.Close(reason);
        }
    }

    // One live link: the grammar parser and every contact the parent's
    // listener has accepted. Deliver is serialized under the gate -- the
    // channel's output arrives in order, and the parser's remainder is not
    // concurrent state. Close is idempotent -- the task completing, the
    // stream dying, and a malformed stream can race, and whichever lands
    // first owns the contacts' closing audits.
    private sealed class ChainLink
    {
        private readonly DegradedChannelHub _degraded;
        private readonly Microsoft.Extensions.Logging.ILogger _logger;
        // The packet kinds of the bind grammar, mirrored from the
        // implant-side handler (src/channel.rs, tunnel.bind).
        private const byte KindBound = 1;
        private const byte KindOpen = 2;
        private const byte KindData = 3;
        private const byte KindClose = 4;

        // The largest packet payload the grammar carries, the chunk budget
        // the implant's own pumps use.
        private const int MaxPacketBytes = 16 * 1024;

        // The unparsed-remainder ceiling: a stream that piles up more than
        // the parser can consume is malformed or stalled, and the link ends
        // rather than buffers without bound.
        private const int MaxRemainderBytes = 1024 * 1024;

        private readonly LiveChannelHub _channels;
        private readonly StreamBeaconBridge _bridge;
        private readonly IAuditStore _audit;
        private readonly TimeProvider _clock;
        private readonly Rod.CoreState.Tasks.Task _bind;
        private readonly object _gate = new();
        private readonly Dictionary<uint, ChainContact> _contacts = new();
        private readonly List<byte> _pending = new();
        private string? _address;
        private bool _closed;

        public ChainLink(
            LiveChannelHub channels,
            DegradedChannelHub degraded,
            StreamBeaconBridge bridge,
            IAuditStore audit,
            TimeProvider clock,
            Rod.CoreState.Tasks.Task bind,
            Microsoft.Extensions.Logging.ILogger logger)
        {
            _channels = channels;
            _degraded = degraded;
            _bridge = bridge;
            _audit = audit;
            _clock = clock;
            _bind = bind;
            _logger = logger;
        }

        public ImplantId Implant => _bind.ImplantId;

        public bool Deliver(ReadOnlyMemory<byte> data)
        {
            lock (_gate)
            {
                if (_closed)
                    return false;

                _pending.AddRange(data.Span);
                if (_pending.Count > MaxRemainderBytes)
                {
                    CloseLocked("the channel stream exceeded the grammar's remainder budget");
                    return false;
                }

                while (_pending.Count >= 7)
                {
                    var span = System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_pending);
                    var kind = span[0];
                    var id = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(1, 4));
                    var length = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(5, 2));
                    if (kind is < KindBound or > KindClose || length > MaxPacketBytes)
                    {
                        CloseLocked("the channel stream is not the bind grammar");
                        return false;
                    }
                    if (_pending.Count < 7 + length)
                        break; // the packet's tail is still in flight

                    var payload = _pending.GetRange(7, length).ToArray();
                    _pending.RemoveRange(0, 7 + length);
                    if (!RouteLocked(kind, id, payload))
                        return false;
                }
                return true;
            }
        }

        // One whole packet, under the gate. False ends the link (a malformed
        // stream -- a duplicate contact id or an id this side does not
        // hold); anything else is routed or ignored, never fatal.
        private bool RouteLocked(byte kind, uint id, byte[] payload)
        {
            switch (kind)
            {
                case KindBound:
                    // The listener's actual address: recorded for the hop
                    // audits, nothing to route.
                    _address = Encoding.UTF8.GetString(payload);
                    return true;

                case KindOpen:
                    if (_contacts.ContainsKey(id))
                    {
                        CloseLocked("the channel stream named a repeated connection id");
                        return false;
                    }
                    var contact = new ChainContact(
                        _channels, _degraded, _bridge, _audit, _clock, _bind, id,
                        Encoding.UTF8.GetString(payload), _address, Remove, _logger);
                    _contacts[id] = contact;
                    contact.Start();
                    return true;

                case KindData:
                    // Data for an ended contact is nothing to do; the
                    // contact's own close already reported its end.
                    if (_contacts.TryGetValue(id, out var receiving))
                        receiving.DeliverInbound(payload);
                    return true;

                case KindClose:
                    if (_contacts.TryGetValue(id, out var ending) && _contacts.Remove(id))
                        ending.EndInbound("the chained connection closed");
                    return true;

                default:
                    return false;
            }
        }

        public void Close(string reason)
        {
            lock (_gate)
                CloseLocked(reason);
        }

        private void CloseLocked(string reason)
        {
            if (_closed)
                return;
            _closed = true;

            foreach (var contact in _contacts.Values)
                contact.EndInbound(reason);
            _contacts.Clear();
        }

        // The contact's serving task returned: forget it, and -- when the
        // contact's end is the server's own (a refused handshake, the
        // contact timeout, a malformed contact body) rather than the
        // parent's reported close -- tell the parent to drop the socket.
        private void Remove(uint id, ChainContact contact, string cause)
        {
            lock (_gate)
            {
                if (!_closed
                    && _contacts.TryGetValue(id, out var registered)
                    && registered == contact
                    && _contacts.Remove(id))
                    _channels.TryEnqueue(
                        _bind.ImplantId,
                        _bind.Id.Value,
                        EncodePacket(KindClose, id),
                        eof: false);
            }
        }

        public static byte[] EncodePacket(byte kind, uint id, ReadOnlySpan<byte> payload = default)
        {
            var packet = new byte[7 + payload.Length];
            packet[0] = kind;
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(1, 4), id);
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(5, 2), (ushort)payload.Length);
            payload.CopyTo(packet.AsSpan(7));
            return packet;
        }
    }

    // One chained contact: the duplex pipe that stands in for the listener
    // socket, with the shared stream bridge serving it. Inbound packets
    // (the parent's channel output) queue for the bridge to read; the
    // bridge's writes leave as data packets through the same enqueue the
    // operator input route uses. The contact ends when either half does --
    // the parent's close packet completes the inbound queue and the bridge
    // reads its EOF, or the bridge returns and the parent is told to drop
    // the socket.
    private sealed class ChainContact
    {
        // The inbound queue depth: a bridge that cannot keep up (a contact
        // whose client sends faster than the server serves) must not pin
        // server memory; a full queue ends the contact, the honest failure
        // the client sees as a dropped connection.
        private const int MaxQueuedChunks = 256;

        private readonly LiveChannelHub _channels;
        private readonly StreamBeaconBridge _bridge;
        private readonly IAuditStore _audit;
        private readonly TimeProvider _clock;
        private readonly Rod.CoreState.Tasks.Task _bind;
        private readonly uint _id;
        private readonly string _peer;
        private readonly string? _address;
        private readonly Action<uint, ChainContact, string> _removed;
        private readonly DegradedChannelHub _degraded;
        private readonly Microsoft.Extensions.Logging.ILogger _logger;
        private readonly Channel<byte[]> _inbound =
            Channel.CreateBounded<byte[]>(new BoundedChannelOptions(MaxQueuedChunks)
            {
                SingleReader = true,
                SingleWriter = false,
            });
        private readonly CancellationTokenSource _done = new();
        private readonly ChainContactPipe _pipe;
        private System.Threading.Tasks.Task _serving = System.Threading.Tasks.Task.CompletedTask;

        public ChainContact(
            LiveChannelHub channels,
            DegradedChannelHub degraded,
            StreamBeaconBridge bridge,
            IAuditStore audit,
            TimeProvider clock,
            Rod.CoreState.Tasks.Task bind,
            uint id,
            string peer,
            string? address,
            Action<uint, ChainContact, string> removed,
            Microsoft.Extensions.Logging.ILogger logger)
        {
            _channels = channels;
            _bridge = bridge;
            _audit = audit;
            _clock = clock;
            _bind = bind;
            _id = id;
            _peer = peer;
            _address = address;
            _removed = removed;
            _degraded = degraded;
            _logger = logger;
            _pipe = new ChainContactPipe(_inbound.Reader, EmitDownstreamAsync);
        }

        public void Start()
        {
            // The hop's audit lands ahead of the serving task so an
            // enrollment the contact carries is never the first record the
            // chain holds for it.
            _ = AppendHopAuditAsync(
                AuditEventKind.ChainHopOpened,
                $"connection={_id} peer={_peer} listener={_address ?? "unreported"}",
                $"connection {_id} from {_peer}");
            _serving = ServeAsync();
        }

        private async System.Threading.Tasks.Task ServeAsync()
        {
            try
            {
                // A chained contact arrives over no listener of its own --
                // its ingress is the parent's channel -- so the null
                // listener keeps the enrollment token-scoped, and the
                // carrying parent is the lineage the enrollment records.
                await _bridge.HandleContactAsync(
                    _pipe, listener: null, _done.Token, carrier: "chain", chainParent: _bind.ImplantId);
            }
            catch (Exception ex)
            {
                // The bridge's own catch set covers the expected ends; a
                // fault past it still ends the contact, never the link.
                _logger.LogInformation(
                    "Chained contact {Connection} on bind {Task} ended faulted: {Fault}",
                    _id, _bind.Id.Value, ex.Message);
            }
            finally
            {
                _done.Cancel();
                _inbound.Writer.TryComplete();
                await AppendHopAuditAsync(
                    AuditEventKind.ChainHopClosed,
                    $"connection={_id} cause=the contact ended",
                    $"connection {_id}: the contact ended");
                _removed(_id, this, "the contact ended");
            }
        }

        /// <summary>One inbound packet from the parent's channel.</summary>
        public void DeliverInbound(byte[] payload)
        {
            if (!_inbound.Writer.TryWrite(payload))
                EndInbound("the contact stopped reading");
        }

        /// <summary>
        /// The inbound half ends -- the parent reported the connection's
        /// close, or the link itself is closing. The bridge reads its EOF
        /// and the serving task unwinds.
        /// </summary>
        public void EndInbound(string cause)
        {
            _inbound.Writer.TryComplete();
        }

        // The bridge's writes: one data packet per unit, down the same two
        // lanes the operator input route rides -- the parent's live sink
        // when its stream holds one, the degraded parking queue when the
        // parent polls (a chained parent's own contact is often the chain
        // above it, a poll cadence). Both lanes failing (the parent is gone)
        // ends the contact; the link's own close is right behind.
        private async Task EmitDownstreamAsync(ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        {
            var packet = ChainLink.EncodePacket(3, _id, body.Span);
            if (_channels.TryEnqueue(_bind.ImplantId, _bind.Id.Value, packet, eof: false))
                return;
            if (await _degraded.TryEnqueueAsync(
                    _bind.ImplantId, _bind.Id, packet, eof: false, cancellationToken))
                return;
            _done.Cancel();
        }

        private async System.Threading.Tasks.Task AppendHopAuditAsync(
            AuditEventKind kind, string payload, string outcome)
        {
            try
            {
                await _audit.AppendAsync(
                    AuditEvent.Fact(
                        eventId: Guid.NewGuid(),
                        engagementId: _bind.EngagementId.Value,
                        operatorId: _bind.IssuedBy.Value,
                        implantId: _bind.ImplantId.Value,
                        taskId: _bind.Id.Value,
                        verb: _bind.Verb,
                        kind: kind,
                        payload: payload,
                        output: null,
                        outcome: outcome,
                        at: _clock.GetUtcNow()),
                    CancellationToken.None);
            }
            catch
            {
                // The audit store refusing must not take the contact's
                // machinery with it; the chain's integrity check names the
                // gap.
            }
        }
    }

    // The contact's stand-in for the listener socket: reads drain the
    // inbound queue (whole chunks, the boundary the framing layer wants),
    // writes accumulate until the flush the framing layer always sends
    // between messages -- so one downstream packet carries one whole contact
    // message, prefix and body together. Reads end at zero when the inbound
    // queue completes -- the framing layer turns that into the stream's EOF,
    // the same end a closed socket reads.
    private sealed class ChainContactPipe(
        ChannelReader<byte[]> inbound,
        Func<ReadOnlyMemory<byte>, CancellationToken, Task> downstream) : Stream
    {
        private byte[]? _rest;
        private int _restOffset;
        private readonly MemoryStream _outbound = new();

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken)
        {
            while (true)
            {
                if (_rest is { } chunk)
                {
                    var take = Math.Min(chunk.Length - _restOffset, buffer.Length);
                    chunk.AsMemory(_restOffset, take).CopyTo(buffer);
                    _restOffset += take;
                    if (_restOffset >= chunk.Length)
                        _rest = null;
                    return take;
                }

                if (!await inbound.WaitToReadAsync(cancellationToken))
                    return 0; // the inbound half completed: the stream's EOF

                if (!inbound.TryRead(out _rest))
                    continue;
                _restOffset = 0;
            }
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            _outbound.Write(buffer.Span);
            await Task.CompletedTask;
        }

        public override void Flush()
        {
            // The flush path the framing layer actually takes is the async
            // one below; the sync override exists for the abstract contract.
            EmitDownstreamAsync(CancellationToken.None).GetAwaiter().GetResult();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
            => EmitDownstreamAsync(cancellationToken);

        private async Task EmitDownstreamAsync(CancellationToken cancellationToken)
        {
            if (_outbound.Length == 0)
                return;
            var message = _outbound.ToArray();
            _outbound.SetLength(0);
            await downstream(message, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException("The contact pipe is asynchronous-only.");

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException("The contact pipe is asynchronous-only.");

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();
    }
}
