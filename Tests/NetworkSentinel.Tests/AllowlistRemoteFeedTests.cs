using System.Net;
using System.Text;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class AllowlistRemoteFeedTests
{
    // TEST-NET-3 (RFC 5737): never routable, and not in the bundled default list, so
    // seeing it allowlisted can only have come from the served feed.
    private const string FeedIp = "203.0.113.77";

    private const string FeedBody =
        """
        { "domains": ["allowlist-probe.invalid"], "ips": ["203.0.113.77"], "cidrs": [] }
        """;

    /// <summary>Serves the feed body once per request on a loopback port, until disposed.</summary>
    private sealed class FeedServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        public string Url { get; }
        public int Requests;

        public FeedServer()
        {
            // Bind a free high port by trial: HttpListener has no "port 0" mode.
            for (var port = 18820; port < 18870; port++)
            {
                try
                {
                    _listener.Prefixes.Clear();
                    _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
                    _listener.Start();
                    Url = $"http://127.0.0.1:{port}/allowlist.json";
                    _ = Task.Run(Serve);
                    return;
                }
                catch (HttpListenerException) { /* in use — next port */ }
            }

            throw new InvalidOperationException("No free loopback port for the feed server.");
        }

        private async Task Serve()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); }
                catch { return; }

                Interlocked.Increment(ref Requests);
                var bytes = Encoding.UTF8.GetBytes(FeedBody);
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { /* already down */ }
            try { _listener.Close(); } catch { /* already down */ }
        }
    }

    [Fact]
    public async Task RepeatedRefreshInsideTheRateLimitWindowKeepsFeedEntries()
    {
        using var server = new FeedServer();
        using var svc = new AllowlistService { UseRemoteFeed = true, RemoteFeedUrl = server.Url };

        await svc.InitializeAsync();
        Assert.True(svc.IsAllowed(FeedIp, out var reason),
            "the live fetch should have allowlisted the feed's IP");
        Assert.False(string.IsNullOrWhiteSpace(reason));

        // RefreshAsync clears every set and rebuilds from local sources first. The
        // 10-minute rate limit means these two refreshes take the no-live-fetch path,
        // which used to return without re-merging the cache — silently stripping every
        // remote-feed entry from the never-block set. Auto-block could then fire on a
        // feed-protected address.
        await svc.RefreshAsync();
        Assert.True(svc.IsAllowed(FeedIp, out _),
            "refresh inside the rate-limit window must keep the cached feed entries");

        await svc.RefreshAsync();
        Assert.True(svc.IsAllowed(FeedIp, out _),
            "a second refresh must still keep them");

        // Proves the second and third passes really were rate-limited rather than
        // quietly re-fetching, which would make the assertions above vacuous.
        Assert.Equal(1, server.Requests);
    }
}
