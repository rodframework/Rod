using System.Collections.Concurrent;
using Rod.CoreState;
using Rod.CoreState.Live;
using Rod.Operators.Live;
using Task = System.Threading.Tasks.Task;

namespace Rod.Operators.Tests;

/// <summary>
/// The bus's connected-subscriber count (architecture.md Sec 15.3, ADR-008):
/// the diagnostics face's SSE connection number. The count is the
/// deployment-wide total across engagements -- two engagements' subscribers
/// sum into one number, and when the last subscriber of an engagement leaves,
/// its set retires and the count falls back, so a long-lived engagement never
/// leaks a phantom connection.
/// </summary>
public class LiveEventBusConnectionCountTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch;

    private static LiveEvent Event(EngagementId engagement)
        => LiveEvent.Presence(engagement, LiveEventKind.OperatorJoined, OperatorId.New(), "probe", Now);

    private static async Task SubscribeAsync(
        ILiveEventBus bus,
        EngagementId engagement,
        CancellationToken ct,
        ConcurrentQueue<string> received)
    {
        try
        {
            await foreach (var e in bus.SubscribeAsync(engagement, ct))
                received.Enqueue(e.Payload);
        }
        catch (OperationCanceledException)
        {
            // Expected teardown: the subscription ends when its token fires.
        }
    }

    // Publishes until the subscriber's queue shows one, so the subscription is
    // provably attached before the count is asserted.
    private static async Task UntilAttachedAsync(
        ILiveEventBus bus,
        EngagementId engagement,
        ConcurrentQueue<string> received)
    {
        for (var round = 0; round < 100 && received.IsEmpty; round++)
        {
            await bus.PublishAsync(Event(engagement));
            await Task.Delay(1);
        }
        Assert.False(received.IsEmpty);
    }

    [Fact]
    public async Task Count_SumsSubscribersAcrossEngagements_AndFallsWhenTheyLeave()
    {
        var bus = new InMemoryLiveEventBus();
        var left = EngagementId.New();
        var right = EngagementId.New();
        Assert.Equal(0, bus.ConnectedSubscribers);

        // One subscriber on each of two engagements: the total is the sum,
        // with no per-engagement dimension exposed anywhere.
        var leftSeen = new ConcurrentQueue<string>();
        using (var leftCts = new CancellationTokenSource())
        {
            var leftTask = SubscribeAsync(bus, left, leftCts.Token, leftSeen);
            await UntilAttachedAsync(bus, left, leftSeen);
            var rightSeen = new ConcurrentQueue<string>();
            using (var rightCts = new CancellationTokenSource())
            {
                var rightTask = SubscribeAsync(bus, right, rightCts.Token, rightSeen);
                await UntilAttachedAsync(bus, right, rightSeen);

                Assert.Equal(2, bus.ConnectedSubscribers);

                leftCts.Cancel();
                await leftTask;
                Assert.Equal(1, bus.ConnectedSubscribers);

                rightCts.Cancel();
                await rightTask;
            }
        }
        Assert.Equal(0, bus.ConnectedSubscribers);
    }
}
