using Harbor;
using System.Text.Json.Nodes;

internal static class DirectExceptionChecks
{
    internal static void Run(Action<string, Action> check)
    {
        void Assert(bool value) { if (!value) throw new Exception("Direct exception check failed"); }
        void Reject(Action action) { try { action(); } catch (FormatException) { return; } throw new Exception("Accepted invalid direct exception"); }
        check("Direct exceptions preserve legacy defaults and normalize explicit names", () =>
        {
            Assert(!DirectExceptions.Read(new JsonObject()).Enabled);
            var parsed = DirectExceptions.Parse(true, " Video.Example.\r\nvideo.example\ncdn.example", "Game.exe\ngame.EXE");
            Assert(parsed.Domains.SequenceEqual(new[] { "video.example", "cdn.example" }) && parsed.Processes.Length == 1);
            var clone = DirectExceptions.Read(new JsonObject { ["directExceptions"] = parsed.ToJson() });
            Assert(clone.Enabled && clone.Domains.SequenceEqual(parsed.Domains) && clone.Processes.SequenceEqual(parsed.Processes));
        });
        check("Direct exception presets merge without broad bypasses or duplicate processes", () =>
        {
            string domains = DirectExceptions.Merge("personal.example", DirectExceptions.GameDomains);
            domains = DirectExceptions.Merge(domains, DirectExceptions.VideoDomains);
            string again = DirectExceptions.Merge(domains, DirectExceptions.GameDomains);
            var parsed = DirectExceptions.Parse(true, again, string.Join("\n", DirectExceptions.GameProcesses));
            Assert(domains == again && parsed.Domains.Contains("personal.example") && parsed.Domains.Contains("bilibili.com"));
            Assert(parsed.Processes.Contains("YuanShen.exe") && !parsed.Processes.Contains("launcher.exe"));
            Assert(!parsed.Domains.Any(v => v is "cn" or "com" || v.Contains('*')));
        });
        check("Direct exception editor rejects URLs, addresses, paths, wildcards and oversized lists", () =>
        {
            foreach (string bad in new[] { "https://bilibili.com", "*.example.com", "127.0.0.1", "::1", "bad..example", "例子.cn" }) Reject(() => DirectExceptions.Parse(true, bad, ""));
            foreach (string bad in new[] { "C:\\Game.exe", "../Game.exe", "*.exe", "Game", ".exe" }) Reject(() => DirectExceptions.Parse(true, "", bad));
            Reject(() => DirectExceptions.Parse(true, string.Join("\n", Enumerable.Range(0, 257).Select(i => "h" + i + ".example")), ""));
            Reject(() => DirectExceptions.Read(new JsonObject { ["directExceptions"] = new JsonObject { ["unknown"] = true } }));
        });
        check("Encrypted workspace history retains and restores direct exception settings", () =>
        {
            string previous = Storage.Root; Storage.Root = Path.Combine(previous, "exceptions-" + Guid.NewGuid().ToString("N"));
            try
            {
                var profile = new JsonObject { ["routingMode"] = "global", ["nodes"] = new JsonArray(), ["groups"] = new JsonArray(), ["rules"] = new JsonArray() };
                Storage.SaveWorkspace(profile, []);
                profile["directExceptions"] = DirectExceptions.Parse(true, "private.fixture.example", "Game.exe").ToJson();
                Storage.SaveWorkspace(profile, []);
                var saved = Storage.LoadWorkspace()!; Assert(DirectExceptions.Read(saved.Profile).Enabled);
                Assert(!System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(Storage.WorkspacePath)).Contains("private.fixture"));
                var old = WorkspaceHistory.Read().Single(); Assert(!DirectExceptions.Read(old.State.Profile).Enabled);
                Assert(WorkspaceHistory.Compare(saved, old.State).Any(v => v.Area == "直连例外"));
                Storage.SaveWorkspace(old.State.Profile, old.State.Subscriptions);
                Assert(!DirectExceptions.Read(Storage.LoadWorkspace()!.Profile).Enabled && DirectExceptions.Read(WorkspaceHistory.Read()[0].State.Profile).Enabled);
            }
            finally { Storage.Root = previous; }
        });
    }
}
