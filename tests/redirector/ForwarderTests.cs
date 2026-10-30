using System.Net;
using System.Net.Sockets;
using Rod.Redirector;

namespace Rod.Redirector.Tests;

public class ForwarderTests
{
    [Fact]
    public async Task Forwards_Bytes_Both_Directions()
    {
        await using var echo = new EchoServer();
        var echoEndpoint = await echo.StartAsync();

        var forwarder = new Forwarder(
            new IPEndPoint(IPAddress.Loopback, 0),
            IPAddress.Loopback.ToString(),
            echoEndpoint.Port,
            CidrAllowList.AllowAll,
            TextWriter.Null);
        var bound = forwarder.Start();

        using var cts = new CancellationTokenSource();
        var runTask = forwarder.RunAsync(cts.Token);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(bound.Address, bound.Port);
            await using var stream = client.GetStream();

            var payload = "redirector-roundtrip"u8.ToArray();
            await stream.WriteAsync(payload);

            var received = await ReadExactAsync(stream, payload.Length);
            Assert.Equal(payload, received);

            // The other relay direction carries the echo back, proving bidirectional
            // splice rather than a one-way copy.
            Assert.Equal(payload.Length, received.Length);
        }
        finally
        {
            cts.Cancel();
            await AssertCompletesAsync(runTask);
        }
    }

    [Fact]
    public async Task Denies_Source_Outside_AllowList()
    {
        // Upstream that fails the test if reached.
        await using var echo = new EchoServer();
        var echoEndpoint = await echo.StartAsync();

        var denyLoopback = CidrAllowList.Parse(new[] { "10.0.0.0/8" }); // excludes 127.0.0.1
        var log = new StringWriter();
        var forwarder = new Forwarder(
            new IPEndPoint(IPAddress.Loopback, 0),
            IPAddress.Loopback.ToString(),
            echoEndpoint.Port,
            denyLoopback,
            log);
        var bound = forwarder.Start();

        using var cts = new CancellationTokenSource();
        var runTask = forwarder.RunAsync(cts.Token);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(bound.Address, bound.Port);
            await using var stream = client.GetStream();

            // Force the forwarder to process the accepted connection. The denied
            // connection is closed without forwarding; the read returns 0 (FIN) or
            // throws on reset -- either means nothing was relayed to the upstream.
            await stream.WriteAsync("ping"u8.ToArray());
            int read;
            try
            {
                read = await stream.ReadAsync(new byte[16]);
            }
            catch (IOException)
            {
                read = 0;
            }

            Assert.Equal(0, read);
            Assert.Contains("denied", log.ToString());
            Assert.False(echo.Accepted, "the denied connection must not reach the upstream");
        }
        finally
        {
            cts.Cancel();
            await AssertCompletesAsync(runTask);
        }
    }

    [Fact]
    public async Task RunAsync_Throws_When_Not_Started()
    {
        var forwarder = new Forwarder(
            new IPEndPoint(IPAddress.Loopback, 0),
            IPAddress.Loopback.ToString(),
            1,
            CidrAllowList.AllowAll,
            TextWriter.Null);

        await Assert.ThrowsAsync<InvalidOperationException>(() => forwarder.RunAsync(CancellationToken.None));
    }

    private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int count)
    {
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read));
            if (n == 0)
                break;
            read += n;
        }

        return read == count ? buffer : buffer[..read];
    }

    private static async Task AssertCompletesAsync(Task task)
    {
        var winner = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.True(task.IsCompleted, "the forwarder did not stop within the grace period.");
    }

    /// <summary>
    /// A minimal loopback echo upstream: accepts a single connection and copies
    /// each received byte straight back to the sender. Tracks whether a
    /// connection was ever accepted so a test can assert the redirector never
    /// forwarded a denied one.
    /// </summary>
    private sealed class EchoServer : IAsyncDisposable
    {
        private TcpListener? _listener;
        private Task? _serve;
        private CancellationTokenSource? _cts;

        public bool Accepted { get; private set; }

        public Task<IPEndPoint> StartAsync()
        {
            _cts = new CancellationTokenSource();
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            var endpoint = (IPEndPoint)_listener.LocalEndpoint;
            _serve = ServeAsync(endpoint, _cts.Token);
            return Task.FromResult(endpoint);
        }

        private async Task ServeAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
        {
            try
            {
                using var client = await _listener!.AcceptTcpClientAsync(cancellationToken);
                Accepted = true;
                await using var stream = client.GetStream();
                // Echo received bytes straight back. Reading and writing the same
                // NetworkStream works because the read and write sides of a TCP
                // socket are independent directions.
                await stream.CopyToAsync(stream, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Clean shutdown.
            }
        }

        public async ValueTask DisposeAsync()
        {
            // Capture and null the token source so a repeat dispose (the test's
            // `await using` plus any manual call) is a no-op rather than an
            // ObjectDisposedException on Cancel.
            var cts = _cts;
            _cts = null;
            try
            {
                cts?.Cancel();
            }
            catch (ObjectDisposedException)
            {
            }
            try
            {
                _listener?.Stop();
            }
            catch (SocketException)
            {
            }
            if (_serve is not null)
                await Task.WhenAny(_serve, Task.Delay(TimeSpan.FromSeconds(5)));
            cts?.Dispose();
        }
    }
}
