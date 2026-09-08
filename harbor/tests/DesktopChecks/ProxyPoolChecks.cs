using Harbor;
using System.Text.Json.Nodes;

internal static class ProxyPoolChecks
{
    internal static void Run(Action<string, Action> check)
    {
        void Assert(bool value) { if (!value) throw new Exception("Pool assertion failed"); }
        void Reject(Action action) { try { action(); } catch (FormatException) { return; } throw new Exception("Expected invalid pool to be rejected"); }
        JsonObject Profile(int members = 2) => new()
        {
            ["nodes"] = new JsonArray(Enumerable.Range(0, members).Select(i => (JsonNode?)new JsonObject { ["name"] = "n" + i }).ToArray()),
            ["groups"] = new JsonArray(new JsonObject { ["name"] = "pool", ["kind"] = "fallback", ["members"] = new JsonArray(Enumerable.Range(0, members).Select(i => (JsonNode?)JsonValue.Create("n" + i)).ToArray()), ["pool"] = new PoolOptions().ToJson() })
        };
        check("Automatic pool defaults are opt-in and options survive serialization", () =>
        {
            var legacy = new JsonObject { ["groups"] = new JsonArray(new JsonObject { ["name"] = "old", ["kind"] = "select", ["members"] = new JsonArray("DIRECT") }) };
            string before = legacy.ToJsonString(); ProxyPools.Validate(legacy); Assert(before == legacy.ToJsonString());
            var options = new PoolOptions(false, "https://localhost:9443/ready?q=fixture", 60, 4000, 2, 1500);
            Assert(PoolOptions.Read(options.ToJson()) == options); Assert(PoolOptions.Read(new JsonObject()) == new PoolOptions());
        });
        check("Pool health settings enforce HTTPS, typed fields and bounded work", () =>
        {
            foreach (string url in new[] { "http://example.test/", "https://u:p@example.test/", "https://example.test/#secret", "https://example.test:0/", " https://example.test/", "https://example.test/\r\n" }) Reject(() => new PoolOptions(CheckUrl: url).Validate());
            Reject(() => new PoolOptions(ConnectAttempts: 4).Validate()); Reject(() => new PoolOptions(CheckIntervalSecs: 2).Validate());
            Reject(() => new PoolOptions(AttemptTimeoutMs: 499).Validate()); Reject(() => new PoolOptions(CheckTimeoutMs: 20000).Validate());
            Reject(() => new PoolOptions(CaPem: "invalid certificate").Validate());
            Reject(() => PoolOptions.Read(new JsonObject { ["monitor"] = "true" })); Reject(() => PoolOptions.Read(new JsonObject { ["futureSetting"] = true }));
        });
        check("Pool members cannot add direct egress, missing names, duplicates or manual selection", () =>
        {
            var profile = Profile(); ProxyPools.Validate(profile);
            foreach (string name in new[] { "DIRECT", "REJECT", "missing", "n0" })
            {
                var candidate = profile.DeepClone().AsObject(); candidate["groups"]![0]!["members"]!.AsArray().Add(name); Reject(() => ProxyPools.Validate(candidate));
            }
            profile["groups"]![0]!["kind"] = "select"; Reject(() => ProxyPools.Validate(profile));
            Reject(() => ProxyPools.ValidateName(Profile(), "n0", null)); Reject(() => ProxyPools.ValidateName(Profile(), "DIRECT", null));
            ProxyPools.ValidateName(Profile(), "pool", "pool");
        });
        check("Pool and member budgets cap persisted monitor work", () =>
        {
            Reject(() => ProxyPools.Validate(Profile(129)));
            var profile = Profile(128); var group = profile["groups"]![0]!.DeepClone(); profile["groups"]!.AsArray().Add(group); ProxyPools.Validate(profile);
            profile["groups"]!.AsArray().Add(new JsonObject { ["name"] = "extra", ["kind"] = "fallback", ["members"] = new JsonArray("n0"), ["pool"] = new PoolOptions().ToJson() }); Reject(() => ProxyPools.Validate(profile));
            profile = Profile(1); for (int i = 1; i < 9; i++) profile["groups"]!.AsArray().Add(profile["groups"]![0]!.DeepClone()); Reject(() => ProxyPools.Validate(profile));
        });
    }
}
