using Harbor;
using System.Text.Json.Nodes;

internal static class TrafficRouteChecks
{
    private static JsonObject Fixture() => new()
    {
        ["nodes"] = new JsonArray(new JsonObject { ["name"] = "owned", ["kind"] = "socks5", ["server"] = "proxy.invalid", ["port"] = 9, ["tls"] = true }),
        ["groups"] = new JsonArray(), ["rules"] = new JsonArray(), ["finalPolicy"] = "DIRECT", ["routingMode"] = "global"
    };
    private static TrafficRouteSetting Route() => new("工作", true, ["work.example"], ["Work.exe"], "owned", true);
    internal static void Run(Action<string, Action> check)
    {
        void Assert(bool value) { if (!value) throw new Exception("Traffic route check failed"); }
        void Reject(Action action) { try { action(); } catch (FormatException) { return; } throw new Exception("Invalid traffic route was accepted"); }
        check("Traffic route import preserves legacy profiles and rejects ambiguous or contradictory paths", () =>
        {
            var profile = Fixture(); Assert(TrafficRoutes.Read(profile).Count == 0);
            profile["trafficRoutes"] = TrafficRoutes.Serialize([Route()]); Assert(TrafficRoutes.Read(profile).Single().Policy == "owned");
            foreach (var route in new[] { Route() with { Policy = "missing" }, Route() with { Policy = "DIRECT" }, Route() with { Domains = [], Processes = [] }, Route() with { Domains = ["https://work.example"] } })
            { profile["trafficRoutes"] = TrafficRoutes.Serialize([route]); Reject(() => TrafficRoutes.Read(profile)); }
            profile["trafficRoutes"] = TrafficRoutes.Serialize([Route(), Route()]); Reject(() => TrafficRoutes.Read(profile));
            profile["trafficRoutes"] = TrafficRoutes.Serialize(Enumerable.Range(0, 9).Select(i => Route() with { Name = "路径" + i, Domains = Enumerable.Repeat("work.example", 256).ToArray(), Processes = [] }));
            Reject(() => TrafficRoutes.Read(profile));
        });
        check("Subscription refresh retains a removed node referenced only by a traffic path", () =>
        {
            var profile = Fixture(); profile["trafficRoutes"] = TrafficRoutes.Serialize([Route()]);
            var entry = new SubscriptionEntry("id", "feed", "https://feed.invalid", ["owned"], default, "", "", "", 0);
            var merged = Subscriptions.Merge(profile, new JsonArray(), entry, "", out _, out int retained);
            Assert(retained == 1 && merged["nodes"]!.AsArray().Count == 1 && TrafficRoutes.Read(merged).Single().Policy == "owned");
        });
        check("Path capabilities distinguish TCP TLS, plaintext SOCKS UDP, and unsupported HTTP UDP", () =>
        {
            var profile = Fixture(); var node = profile["nodes"]![0]!;
            Assert(TrafficRoutes.Encrypted(node, "tcp") && !TrafficRoutes.Encrypted(node, "udp"));
            Assert(TrafficRoutes.OutboundFacts(profile, "owned").Contains("UDP 无代理层加密"));
            node["kind"] = "https"; Assert(TrafficRoutes.OutboundFacts(profile, "owned").Contains("UDP 不支持"));
            node["kind"] = "trojan"; node["transport"] = "ws";
            Assert(TrafficRoutes.Encrypted(node, "udp") && TrafficRoutes.OutboundFacts(profile, "owned").Contains("WSS"));
            Assert(!TrafficRoutes.OutboundFacts(profile, "DIRECT").Contains("TLS"));
        });
        check("Path edits preserve explicit outbound verification fingerprints", () =>
        {
            var profile = Fixture(); string? original = VerificationHistory.Fingerprint(profile, "owned");
            profile["trafficRoutes"] = TrafficRoutes.Serialize([Route()]); Assert(original == VerificationHistory.Fingerprint(profile, "owned"));
            profile["nodes"]![0]!["tls"] = false; Assert(original != VerificationHistory.Fingerprint(profile, "owned"));
        });
        check("Automatic group capability counts include transport support and both protection levels", () =>
        {
            var profile = Fixture(); profile["nodes"]!.AsArray().Add(new JsonObject { ["name"] = "encrypted", ["kind"] = "shadowsocks" });
            profile["nodes"]!.AsArray().Add(new JsonObject { ["name"] = "web", ["kind"] = "https" });
            profile["groups"] = new JsonArray(new JsonObject { ["name"] = "pool", ["kind"] = "fallback", ["members"] = new JsonArray("DIRECT", "owned", "web", "encrypted") });
            Assert(TrafficRoutes.OutboundFacts(profile, "pool").Contains("TCP 4 / UDP 3"));
            Assert(TrafficRoutes.OutboundFacts(profile, "pool", true).Contains("TCP 3 / UDP 1"));
            profile["privacy"] = new JsonObject { ["requireEncryptedProxy"] = true, ["blockDirect"] = true };
            Assert(TrafficRoutes.OutboundFacts(profile, "pool").Contains("TCP 3 / UDP 1"));
            profile["privacy"]!["blockDirect"] = false;
            Assert(TrafficRoutes.OutboundFacts(profile, "pool").Contains("TCP 4 / UDP 2"));
            Assert(TrafficRoutes.OutboundFacts(profile, "pool").Contains("未计入实时健康"));
        });
        check("Priority advice distinguishes full coverage, partial overlap, and process/domain intersections", () =>
        {
            var first = Route() with { Name = "first", Domains = ["EXAMPLE."], Processes = ["WORK.EXE"] };
            var second = Route();
            Assert(TrafficRoutes.OverlapNotice([first, second], 1).Contains("全部条件"));
            Assert(TrafficRoutes.OverlapNotice([first with { Enabled = false }, second], 1) == "");
            Assert(TrafficRoutes.OverlapNotice([first, second with { Enabled = false }], 1) == "");
            Assert(TrafficRoutes.OverlapNotice([first, second with { Processes = ["Another.exe"] }], 1).Contains("部分条件"));
            Assert(TrafficRoutes.OverlapNotice([first with { Domains = ["sub.work.example"], Processes = [] }, second with { Processes = [] }], 1).Contains("部分条件"));
            Assert(TrafficRoutes.OverlapNotice([first with { Domains = ["notwork.example"], Processes = [] }, second with { Processes = [] }], 1) == "");
            Assert(TrafficRoutes.OverlapNotice([first with { Domains = [] }, second with { Processes = [] }], 1).Contains("可能同时命中"));
            var domainOnly = first with { Processes = [] }; var processOnly = first with { Name = "process", Domains = [] };
            Assert(TrafficRoutes.OverlapNotice([domainOnly, processOnly, second], 2).Contains("全部条件"));
            Assert(!TrafficRoutes.ExplainReason("Transport: the selected outbound does not support UDP").Contains("Transport:"));
        });
        check("Encrypted workspace history restores path order, enablement, and protection requirements", () =>
        {
            string previous = Storage.Root; Storage.Root = Path.Combine(previous, "paths-" + Guid.NewGuid().ToString("N"));
            try
            {
                var profile = Fixture(); profile["trafficRoutes"] = TrafficRoutes.Serialize([Route()]); Storage.SaveWorkspace(profile, []);
                var changed = profile.DeepClone().AsObject(); changed["trafficRoutes"] = TrafficRoutes.Serialize([Route() with { Enabled = false, RequireEncryptedProxy = false }]); Storage.SaveWorkspace(changed, []);
                var history = WorkspaceHistory.Read().Single(); Assert(TrafficRoutes.Read(history.State.Profile).Single().RequireEncryptedProxy);
                Assert(WorkspaceHistory.Compare(Storage.LoadWorkspace()!, history.State).Any(v => v.Area == "流量路径 · 工作"));
                Assert(!System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(Storage.WorkspacePath)).Contains("work.example"));
                var restored = WorkspaceHistory.PrepareRestore(history.State); Storage.SaveWorkspace(restored.Profile, restored.Subscriptions);
                Assert(TrafficRoutes.Read(Storage.LoadWorkspace()!.Profile).Single().Enabled);
            }
            finally { Storage.Root = previous; }
        });
    }
}
