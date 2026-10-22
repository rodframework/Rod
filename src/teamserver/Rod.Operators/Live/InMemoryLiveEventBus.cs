using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Rod.CoreState;
using Rod.CoreState.Engagements;
using Rod.CoreState.Live;

namespace Rod.Operators.Live;

/// <summary>
/// In-memory <see cref="ILiveEventBus"/> by default.
/// -- no Postgres / no out-of-process bus yet. Each engagement owns a set of
/// subscriber channels; <see cref="PublishAsync"/> fans an event out to every
/// current subscriber on that engagement, and <see cref="SubscribeAsync"/>
/// yields a per-subscriber stream. State is process-local and lost on restart;
/// the port keeps callers agnostic to that.
///
/// Live state is best-effort: the audit trail (architecture.md Sec 11) is the
/// durable, attributed record, and this bus is the transient projection
/// operators read while connected. A slow subscriber never blocks a publisher:
/// each subscriber's channel is bounded, and a full channel drops the oldest
/// undelivered event rather than stalling the producer or the other peers. The
/// dropped subscriber still sees the latest state on its next list read.
///
/// Engagement isolation is by construction: a subscriber receives only its own
/// engagement's events, because publish and subscribe are both keyed on the
/// engagement id (architecture.md Sec 3).
/// </summary>
public sealed class InMemoryLiveEventBus : ILiveEventBus
{
    // One engagement -> its live subscribers. Each subscriber holds its own
    // bounded channel, so publishers and peers are decoupled per subscriber.
    private readonly ConcurrentDictionary<EngagementId, SubscriberSet> _engagements = new();

    // Per-subscriber capacity. Live events are small and frequent; a bounded
    // channel with drop-oldest keeps a stalled subscriber from blocking the bus
    // while still delivering a recent backlog on a brief stall.
    private const int ChannelCapacity = 256;

    public Task PublishAsync(LiveEvent @event, CancellationToken cancellationToken = default)
    {
        if (_engagements.TryGetValue(@event.EngagementId, out var set))
            set.Publish(@event);

        return Task.CompletedTask;
    }

    /// <summary>
    /// How many operator SSE streams are connected right now, across every
    /// engagement (the diagnostics face's connection count, architecture.md
    /// Sec 15.3, ADR-008). A deliberately deployment-wide total: the count is
    /// an aggregate with no per-engagement breakdown, so the diagnostics red
    /// line holds by construction. Diagnostic-grade snapshot -- a subscriber
    /// leaving mid-read is counted or missed, never double-counted.
    /// </summary>
    public int ConnectedSubscribers
    {
        get
        {
            var total = 0;
            foreach (var set in _engagements.Values)
                total += set.SubscriberCount;
            return total;
        }
    }

    public async IAsyncEnumerable<LiveEvent> SubscribeAsync(
        EngagementId engagement,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // A subscriber set is retired the moment its last subscriber leaves, so
        // an engagement with no connected operator holds no state at all. The
        // loop guards the retire race: a set marked removed returns null from
        // Add, and the subscriber retries against a fresh set instead of
        // attaching to a set no publisher can reach.
        while (true)
        {
            var set = _engagements.GetOrAdd(engagement, _ => new SubscriberSet(ChannelCapacity));
            var subscriber = set.Add();
            if (subscriber is null)
                continue;

            try
            {
                await foreach (var item in subscriber.Reader.ReadAllAsync().WithCancellation(cancellationToken))
                    yield return item;
                yield break;
            }
            finally
            {
                // Always remove on exit, including cancellation, so the engagement's
                // subscriber set does not leak a dead channel -- and retire the set
                // itself when this was its last subscriber.
                if (set.Remove(subscriber))
                    _engagements.TryRemove(KeyValuePair.Create(engagement, set));
            }
        }
    }

    // Holds one engagement's subscribers and the lock that serializes
    // add/remove/publish against that engagement. Per-engagement locks keep
    // independent engagements from contending. Once the last subscriber leaves,
    // the set is marked removed so a racing Add returns null and the caller
    // retries against a fresh set -- a removed set can never hold a live
    // channel again.
    private sealed class SubscriberSet
    {
        private readonly List<Channel<LiveEvent>> _subscribers = new();
        private readonly Lock _gate = new();
        private readonly int _capacity;
        private readonly BoundedChannelFullMode _fullMode = BoundedChannelFullMode.DropOldest;
        private bool _removed;

        public SubscriberSet(int capacity) => _capacity = capacity;

        // The set's current subscriber count, under the same lock add/remove
        // serialize on, so the diagnostics read never sees a torn value.
        public int SubscriberCount
        {
            get
            {
                lock (_gate)
                {
                    return _subscribers.Count;
                }
            }
        }

        public Channel<LiveEvent>? Add()
        {
            var channel = Channel.CreateBounded<LiveEvent>(new BoundedChannelOptions(_capacity)
            {
                FullMode = _fullMode,
                SingleReader = true,
                SingleWriter = false,
            });

            lock (_gate)
            {
                if (_removed)
                    return null;
                _subscribers.Add(channel);
                return channel;
            }
        }

        // Removes the subscriber and completes its channel. Returns true when the
        // subscriber was the last one: the set is then retired so the bus can
        // drop it from the engagement map.
        public bool Remove(Channel<LiveEvent> channel)
        {
            lock (_gate)
            {
                _subscribers.Remove(channel);
                channel.Writer.TryComplete();

                if (_subscribers.Count == 0)
                {
                    _removed = true;
                    return true;
                }
                return false;
            }
        }

        // Fan-out to every current subscriber. A snapshot is taken under the lock
        // so adds/removes racing this call stay consistent; writes themselves are
        // outside the lock (each channel is independent and non-blocking under
        // DropOldest).
        public void Publish(LiveEvent @event)
        {
            Channel<LiveEvent>[] snapshot;
            lock (_gate)
            {
                if (_removed)
                    return;
                snapshot = _subscribers.ToArray();
            }

            foreach (var channel in snapshot)
                channel.Writer.TryWrite(@event);
        }
    }
}
