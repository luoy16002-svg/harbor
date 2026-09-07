using Harbor;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class SubscriptionChecks
{
    private static void Require(bool condition) { if (!condition) throw new Exception("Subscription check failed."); }
    private static void Reject(Action action) { bool rejected = false; try { action(); } catch { rejected = true; } Require(rejected); }
    private static JsonObject Profile() => new() { ["nodes"] = new JsonArray(), ["groups"] = new JsonArray(), ["rules"] = new JsonArray(), ["finalPolicy"] = "DIRECT" };
    private static SubscriptionEntry Entry(SubscriptionUsage? usage = null) => new("fixture-id", "Feed", "https://feed.invalid/fixture-token", [], DateTimeOffset.UtcNow.AddDays(-1), "\"v1\"", "", "old-digest", 0, usage);
    private static HttpResponseMessage Response(HttpStatusCode status, string? usage = null, string body = "socks5://127.0.0.1:9#local")
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };
        if (usage != null) response.Headers.TryAddWithoutValidation("Subscription-Userinfo", usage);
        return response;
    }

    internal static async Task RunAsync(Action<string, Action> check, Func<string, Func<Task>, Task> checkAsync)
    {
        check("Subscription usage handles semicolons, optional expiry and provider-only statistics", () =>
        {
            var now = DateTimeOffset.UtcNow;
            var usage = SubscriptionUsage.Parse(" upload = 1024;download=2048;total=8192;expire=0;future=ignored ", now);
            Require(usage is { Upload: 1024, Download: 2048, Total: 8192, ExpiresAt: null } && usage.RecordedAt == now);
            Require(usage!.Used == 3072 && usage.Percent == 37.5 && usage.Summary.Contains("3 KiB") && usage.Remaining.Contains("5 KiB"));
            var tomorrow = SubscriptionUsage.Parse($"upload=0; download=0; total=0; expire={now.AddDays(1).ToUnixTimeSeconds()}", now)!;
            Require(tomorrow.Expiry(now).Contains("1 天后到期") && tomorrow.Summary.Contains("额度未提供") && tomorrow.Percent == 0);
            Require(tomorrow.Expiry(now.AddDays(2)).Contains("已到期"));
        });
        check("Malformed, duplicate and oversized usage metadata cannot fabricate a quota", () =>
        {
            foreach (string? header in new[] { null, "", "upload=1;download=2", "upload=-1;download=2;total=100", "upload=1.5;download=2;total=100",
                "upload=1;download=2;total=100;UPLOAD=3", "upload=1;download=2;total=100;expire=-1", "upload=1;download=2;total=100;expire=253402300800",
                "upload=18446744073709551616;download=0;total=100", new string('x', 2049) }) Require(SubscriptionUsage.Parse(header, DateTimeOffset.UtcNow) == null);
            var maximum = SubscriptionUsage.Parse($"upload={ulong.MaxValue};download={ulong.MaxValue};total=1;expire=253402300799", DateTimeOffset.UtcNow)!;
            Require(maximum.Used == (decimal)ulong.MaxValue * 2 && maximum.Percent == 100 && maximum.Remaining.Contains("达到"));
            Require(maximum.Summary.Length < 80 && maximum.Expiry(DateTimeOffset.UtcNow).Length < 80);
        });
        check("Legacy subscription workspaces load without metadata; new quota records stay encrypted", () =>
        {
            var entry = Entry(); var entries = JsonSerializer.SerializeToNode(new[] { entry }, Storage.Json)!.AsArray(); entries[0]!.AsObject().Remove("usage");
            Storage.Write(Storage.WorkspacePath, new JsonObject { ["profile"] = Profile(), ["subscriptions"] = entries });
            Require(Subscriptions.Read().Single().Usage == null);
            var usage = new SubscriptionUsage(1234567, 2345678, 987654321, DateTimeOffset.UtcNow.AddDays(2), DateTimeOffset.UtcNow);
            Storage.SaveWorkspace(Profile(), [entry with { Usage = usage }]);
            Require(Subscriptions.Read().Single().Usage == usage);
            string disk = Encoding.UTF8.GetString(File.ReadAllBytes(Storage.WorkspacePath));
            Require(!disk.Contains("fixture-token") && !disk.Contains("987654321") && !disk.Contains("expiresAt"));
        });
        await checkAsync("Conditional subscription replies update metadata and validators without replacing content", async () =>
        {
            var oldUsage = new SubscriptionUsage(1, 2, 100, null, DateTimeOffset.UtcNow.AddDays(-2)); var previous = Entry(oldUsage);
            using var changed = new HttpFixture(request =>
            {
                Require(request.Headers.IfNoneMatch.Single().Tag == "\"v1\"" && request.Headers.UserAgent.ToString().StartsWith("Harbor/", StringComparison.Ordinal));
                var response = Response(HttpStatusCode.NotModified, "upload=10;download=20;total=100;expire=0");
                response.Headers.ETag = new EntityTagHeaderValue("\"v2\""); return response;
            });
            var download = await Subscriptions.FetchWithHandlerAsync(previous.Url, changed, previous);
            Require(download.NotModified && download.Text == "" && download.Digest == previous.Digest && download.Etag == "\"v2\"" && download.Usage!.Used == 30);
            var profile = Profile(); var update = SubscriptionUpdate.Prepare(profile, previous, download, DateTimeOffset.UtcNow);
            Require(update.ContentUnchanged && JsonNode.DeepEquals(profile, update.Profile) && update.Entry.Usage!.Used == 30 && update.Entry.Etag == "\"v2\"");
            Require(previous.Usage == oldUsage && previous.Etag == "\"v1\"");
            using var absent = new HttpFixture(_ => Response(HttpStatusCode.NotModified));
            Require((await Subscriptions.FetchWithHandlerAsync(previous.Url, absent, previous)).Usage == oldUsage);
            using var malformed = new HttpFixture(_ => Response(HttpStatusCode.NotModified, "total=not-a-number"));
            Require((await Subscriptions.FetchWithHandlerAsync(previous.Url, malformed, previous)).Usage == null);
        });
        await checkAsync("Identical subscription bodies still refresh usage and cache headers", async () =>
        {
            var previous = Entry(new SubscriptionUsage(1, 2, 100, null, DateTimeOffset.UtcNow.AddDays(-1)));
            using var firstHandler = new HttpFixture(_ => Response(HttpStatusCode.OK, "upload=1;download=9;total=100"));
            var first = await Subscriptions.FetchWithHandlerAsync(previous.Url, firstHandler);
            previous = previous with { Digest = first.Digest };
            using var secondHandler = new HttpFixture(_ => { var response = Response(HttpStatusCode.OK, "upload=2;download=18;total=100"); response.Headers.ETag = new EntityTagHeaderValue("\"new\""); return response; });
            var second = await Subscriptions.FetchWithHandlerAsync(previous.Url, secondHandler, previous);
            var update = SubscriptionUpdate.Prepare(Profile(), previous, second, DateTimeOffset.UtcNow);
            Require(update.ContentUnchanged && update.Entry.Usage!.Used == 20 && update.Entry.Etag == "\"new\"" && !second.NotModified);
            using var absent = new HttpFixture(_ => Response(HttpStatusCode.OK));
            Require((await Subscriptions.FetchWithHandlerAsync(previous.Url, absent, previous)).Usage == null);
        });
        await checkAsync("Invalid usage does not reject a valid feed and redirect metadata is ignored", async () =>
        {
            using var invalid = new HttpFixture(_ => Response(HttpStatusCode.OK, "upload=-1;download=2;total=100"));
            var validBody = await Subscriptions.FetchWithHandlerAsync(Entry().Url, invalid);
            Require(validBody.Usage == null && ProfileImport.Parse(validBody.Text).Nodes.Count == 1);
            int count = 0;
            using var redirect = new HttpFixture(request =>
            {
                if (++count == 1) { var response = Response(HttpStatusCode.Redirect, "upload=999;download=999;total=999"); response.Headers.Location = new Uri("https://final.invalid/feed"); return response; }
                Require(!request.Headers.IfNoneMatch.Any() && request.Headers.IfModifiedSince == null);
                return Response(HttpStatusCode.OK, "upload=1;download=2;total=100");
            });
            Require((await Subscriptions.FetchWithHandlerAsync(Entry().Url, redirect, Entry())).Usage!.Used == 3 && count == 2);
            using var duplicates = new HttpFixture(_ => { var response = Response(HttpStatusCode.OK, "upload=1;download=2;total=100"); response.Headers.TryAddWithoutValidation("Subscription-Userinfo", "upload=3;download=4;total=100"); return response; });
            Require((await Subscriptions.FetchWithHandlerAsync(Entry().Url, duplicates)).Usage == null);
        });
        check("A changed subscription URL cannot reuse old validators or accept an unsolicited 304", () =>
        {
            using var handler = new HttpFixture(request => { Require(!request.Headers.IfNoneMatch.Any()); return Response(HttpStatusCode.NotModified); });
            Reject(() => Subscriptions.FetchWithHandlerAsync("https://replacement.invalid/new", handler, Entry()).GetAwaiter().GetResult());
            using var unsolicited = new HttpFixture(_ => Response(HttpStatusCode.NotModified));
            Reject(() => Subscriptions.FetchWithHandlerAsync(Entry().Url, unsolicited, Entry() with { Etag = "", LastModified = "" }).GetAwaiter().GetResult());
        });
        await checkAsync("Cancelling a subscription request interrupts header wait and preserves cancellation identity", async () =>
        {
            using var cancellation = new CancellationTokenSource();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var handler = new AsyncHandler(async (_, token) => { entered.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return Response(HttpStatusCode.OK); });
            var task = Subscriptions.FetchWithHandlerAsync(Entry().Url, handler, cancellationToken: cancellation.Token);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); cancellation.Cancel();
            try { await task.WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("Cancellation was ignored."); }
            catch (OperationCanceledException error) { Require(error.CancellationToken == cancellation.Token && !error.Message.Contains("30")); }
            Require(handler.Calls == 1);
            try { await Subscriptions.FetchWithHandlerAsync(Entry().Url, handler, cancellationToken: cancellation.Token); throw new Exception("Pre-cancelled request ran."); }
            catch (OperationCanceledException) { Require(handler.Calls == 1); }
        });
        await checkAsync("Cancelling a subscription body read disposes its response stream", async () =>
        {
            using var cancellation = new CancellationTokenSource(); using var stream = new WaitingStream();
            using var handler = new HttpFixture(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) });
            var task = Subscriptions.FetchWithHandlerAsync(Entry().Url, handler, cancellationToken: cancellation.Token);
            await stream.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); cancellation.Cancel();
            try { await task.WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("Body cancellation was ignored."); }
            catch (OperationCanceledException) { Require(stream.Disposed); }
        });
        check("Subscription update previews separate changes, removals and referenced retention without mutating input", () =>
        {
            var profile = Profile();
            profile["nodes"] = ProfileImport.Parse("socks5://old-auth@127.0.0.1:9#Feed%20%C2%B7%20changed\nsocks5://127.0.0.1:10#Feed%20%C2%B7%20same\nsocks5://127.0.0.1:11#Feed%20%C2%B7%20keep\nsocks5://127.0.0.1:12#Feed%20%C2%B7%20removed\nsocks5://127.0.0.1:13#manual").Nodes;
            profile["finalPolicy"] = "Feed · keep";
            var previous = Entry() with { NodeNames = ["Feed · changed", "Feed · same", "Feed · keep", "Feed · removed"] };
            var before = profile.ToJsonString();
            var download = new DownloadedSubscription("socks5://new-auth@127.0.0.1:9#changed\nsocks5://127.0.0.1:10#same\nsocks5://127.0.0.1:14#added", "\"new\"", "", "new-digest", false);
            var update = SubscriptionUpdate.Prepare(profile, previous, download, DateTimeOffset.UtcNow);
            Require(update is { Added: 1, Changed: 1, Removed: 1, Retained: 1, Unchanged: 1 } && update.Changes.Count == 4);
            Require(profile.ToJsonString() == before && previous.Digest == "old-digest" && update.Profile["finalPolicy"]!.GetValue<string>() == "Feed · keep");
            Require(update.Profile["nodes"]!.AsArray().Any(node => node!["name"]!.GetValue<string>() == "manual") && !update.Entry.NodeNames.Contains("manual"));
            string display = JsonSerializer.Serialize(update.Changes);
            Require(!display.Contains("old-auth") && !display.Contains("new-auth") && !display.Contains("127.0.0.1") && update.Changes.Any(row => row.Detail.Contains("认证信息")));
        });
        check("Subscription updates preserve rule/group references and isolate manual name collisions", () =>
        {
            var profile = Profile();
            profile["nodes"] = new JsonArray(new[] { "Feed · group-old", "Feed · rule-old", "Feed · added" }.Select(name => (JsonNode)new JsonObject { ["name"] = name, ["kind"] = "socks5", ["server"] = "127.0.0.1", ["port"] = 9 }).ToArray());
            profile["groups"]!.AsArray().Add(new JsonObject { ["name"] = "selector", ["members"] = new JsonArray("Feed · group-old") });
            profile["rules"]!.AsArray().Add(new JsonObject { ["policy"] = "Feed · rule-old" });
            var previous = Entry() with { NodeNames = ["Feed · group-old", "Feed · rule-old"] };
            var download = new DownloadedSubscription("socks5://127.0.0.1:10#added", "", "", "new", false);
            var update = SubscriptionUpdate.Prepare(profile, previous, download, DateTimeOffset.UtcNow);
            Require(update.Retained == 2 && update.Added == 1 && update.Entry.NodeNames.Contains("Feed · added (2)") && !update.Entry.NodeNames.Contains("Feed · added"));
            Require(update.Profile["nodes"]!.AsArray().Count == 4 && JsonNode.DeepEquals(profile["rules"], update.Profile["rules"]) && JsonNode.DeepEquals(profile["groups"], update.Profile["groups"]));
        });
        check("Empty and unsupported-only subscription updates never erase existing proxies", () =>
        {
            var profile = Profile(); profile["nodes"] = ProfileImport.Parse("socks5://127.0.0.1:9#Feed%20%C2%B7%20keep").Nodes;
            var before = profile.ToJsonString(); var previous = Entry() with { NodeNames = ["Feed · keep"] };
            foreach (string text in new[] { "{\"nodes\":[]}", "hysteria2://fixture@127.0.0.1:443#unsupported", "" })
                Reject(() => SubscriptionUpdate.Prepare(profile, previous, new DownloadedSubscription(text, "", "", "new", false), DateTimeOffset.UtcNow));
            Require(profile.ToJsonString() == before && previous.NodeNames.Length == 1);
        });
    }

    private sealed class AsyncHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        internal int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) { Calls++; return respond(request, token); }
    }
    private sealed class WaitingStream : Stream
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Disposed;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) { Entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
