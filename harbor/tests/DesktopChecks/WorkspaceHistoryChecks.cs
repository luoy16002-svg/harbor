using Harbor;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class WorkspaceHistoryChecks
{
    private static void Assert(bool value) { if (!value) throw new Exception("Workspace history assertion failed."); }
    private static void Reject(Action action) { try { action(); } catch { return; } throw new Exception("Invalid history operation was accepted."); }
    private static WorkspaceState Fixture(int version = 1) => new(new JsonObject
    {
        ["version"] = version, ["routingMode"] = "rules", ["finalPolicy"] = "fixture", ["groups"] = new JsonArray(), ["rules"] = new JsonArray(),
        ["nodes"] = new JsonArray(new JsonObject { ["name"] = "fixture", ["kind"] = "socks5", ["server"] = "127.0.0.1", ["port"] = 9, ["password"] = "history-private-fixture-password" })
    }, [new("feed", "Fixture feed", "https://feed.fixture.invalid/history-private-fixture-token", ["fixture"], DateTimeOffset.UtcNow,
        "\"fixture-v1\"", "Mon, 07 Sep 2026 00:00:00 GMT", "fixture-digest", 1, new(1, 2, 10, null, DateTimeOffset.UtcNow))]);
    private static void Save(WorkspaceState state) => Storage.SaveWorkspace(state.Profile, state.Subscriptions);

    internal static void Run(Action<string, Action> check)
    {
        void Isolated(string name, Action action) => check(name, () =>
        {
            string previousRoot = Storage.Root;
            Storage.Root = Path.Combine(previousRoot, "workspace-history-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Storage.Root);
            try { action(); }
            finally { Storage.Root = previousRoot; }
        });
        Isolated("Configuration changes automatically retain encrypted predecessor snapshots", () =>
        {
            var first = Fixture(); Save(first); Assert(WorkspaceHistory.Read().Count == 0);
            Save(Fixture(2)); var items = WorkspaceHistory.Read(); Assert(items.Count == 1 && WorkspaceHistory.SameConfiguration(first, items[0].State));
            string disk = Encoding.UTF8.GetString(File.ReadAllBytes(WorkspaceHistory.FilePath));
            Assert(!disk.Contains("history-private-fixture-password") && !disk.Contains("history-private-fixture-token"));
            first.Profile["version"] = 99; Assert(items[0].State.Profile["version"]!.GetValue<int>() == 1);
        });
        Isolated("Subscription usage and fetch validators refresh without consuming history", () =>
        {
            var first = Fixture(); Save(first); Save(Fixture(2));
            byte[] history = File.ReadAllBytes(WorkspaceHistory.FilePath); var current = Storage.LoadWorkspace()!;
            current.Subscriptions[0] = current.Subscriptions[0] with { Usage = new(4, 5, 20, DateTimeOffset.UtcNow.AddDays(2), DateTimeOffset.UtcNow),
                Etag = "\"fixture-v2\"", LastModified = "new", UpdatedAt = DateTimeOffset.UtcNow.AddHours(1), Digest = "new", UnsupportedCount = 8 };
            Save(current); Assert(File.ReadAllBytes(WorkspaceHistory.FilePath).SequenceEqual(history));
            Assert(Storage.LoadWorkspace()!.Subscriptions[0].Usage!.Download == 5);
        });
        Isolated("History retention keeps the ten most recent independent configurations", () =>
        {
            for (int index = 0; index < 14; index++) Save(Fixture(index));
            var items = WorkspaceHistory.Read(); Assert(items.Count == 10 && items[0].State.Profile["version"]!.GetValue<int>() == 12 && items[^1].State.Profile["version"]!.GetValue<int>() == 3);
            Assert(items.Select(item => item.Id).Distinct().Count() == 10);
        });
        Isolated("History write failure leaves current workspace bytes untouched", () =>
        {
            Save(Fixture()); Save(Fixture(2)); byte[] workspace = File.ReadAllBytes(Storage.WorkspacePath);
            File.SetAttributes(WorkspaceHistory.FilePath, FileAttributes.ReadOnly);
            try { Reject(() => Save(Fixture(3))); Assert(File.ReadAllBytes(Storage.WorkspacePath).SequenceEqual(workspace)); }
            finally { File.SetAttributes(WorkspaceHistory.FilePath, FileAttributes.Normal); }
        });
        Isolated("Failed workspace replacement retains a predecessor once and retries cleanly", () =>
        {
            Save(Fixture()); File.SetAttributes(Storage.WorkspacePath, FileAttributes.ReadOnly);
            try { Reject(() => Save(Fixture(2))); Reject(() => Save(Fixture(2))); Assert(WorkspaceHistory.Read().Count == 1); }
            finally { File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal); }
            Save(Fixture(2)); Assert(WorkspaceHistory.Read().Count == 1 && Storage.LoadWorkspace()!.Profile["version"]!.GetValue<int>() == 2);
        });
        Isolated("Restoration resets HTTP validators and quota without modifying the snapshot", () =>
        {
            var old = Fixture(); var candidate = WorkspaceHistory.PrepareRestore(old); var feed = candidate.Subscriptions[0];
            Assert(feed.Etag == "" && feed.LastModified == "" && feed.Digest == "" && feed.Usage == null && feed.UpdatedAt == old.Subscriptions[0].UpdatedAt);
            Assert(old.Subscriptions[0].Etag.Length > 0 && old.Subscriptions[0].Usage != null);
            Save(Fixture(2)); Save(candidate); var backup = WorkspaceHistory.Read()[0];
            Assert(backup.State.Profile["version"]!.GetValue<int>() == 2);
            Save(WorkspaceHistory.PrepareRestore(backup.State)); Assert(Storage.LoadWorkspace()!.Profile["version"]!.GetValue<int>() == 2);
        });
        Isolated("Restoration rejects unsafe subscription addresses, duplicates and orphan ownership", () =>
        {
            var value = Fixture(); var feed = value.Subscriptions[0];
            foreach (var invalid in new[] { feed with { Url = "http://feed.fixture.invalid/" }, feed with { Url = "https://user:pass@feed.fixture.invalid/" }, feed with { NodeNames = ["missing"] } })
                Reject(() => WorkspaceHistory.PrepareRestore(value with { Subscriptions = [invalid] }));
            Reject(() => WorkspaceHistory.PrepareRestore(value with { Subscriptions = [feed, feed] }));
        });
        Isolated("Corrupt, oversized and structurally invalid histories cannot replace current data", () =>
        {
            Save(Fixture()); byte[] before = File.ReadAllBytes(Storage.WorkspacePath);
            var item = new WorkspaceRevision(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, Fixture());
            foreach (object invalid in new object[] { new WorkspaceHistoryFile(2, [item]), new WorkspaceHistoryFile(1, [item, item]),
                new WorkspaceHistoryFile(1, [item with { State = null! }]), new WorkspaceHistoryFile(1, Enumerable.Repeat(item, 11).ToList()),
                new WorkspaceHistoryFile(1, [item with { Id = "invalid" }]), new JsonObject { ["version"] = 1 } })
            {
                Storage.Write(WorkspaceHistory.FilePath, invalid); Reject(() => WorkspaceHistory.Read()); Reject(() => Save(Fixture(2)));
            }
            File.WriteAllText(WorkspaceHistory.FilePath, "corrupt fixture"); Reject(() => WorkspaceHistory.Read());
            using (var file = new FileStream(WorkspaceHistory.FilePath, FileMode.Create)) file.SetLength(WorkspaceHistory.MaximumBytes + 1L);
            Reject(() => WorkspaceHistory.Read()); Assert(File.ReadAllBytes(Storage.WorkspacePath).SequenceEqual(before));
        });
        Isolated("History comparison names changed fields without exposing credentials or feed tokens", () =>
        {
            var old = Fixture(); var current = WorkspaceHistory.Clone(old);
            current.Profile["nodes"]![0]!["password"] = "another-private-password"; current.Profile["nodes"]![0]!["server"] = "private-server.fixture.invalid";
            current.Profile["routingMode"] = "global"; current.Subscriptions[0] = current.Subscriptions[0] with { Url = "https://feed.fixture.invalid/another-private-token" };
            var changes = WorkspaceHistory.Compare(current, old); string text = JsonSerializer.Serialize(changes, new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            Assert(changes.Count == 3 && text.Contains("认证信息") && text.Contains("订阅地址") && text.Contains("统一出口"));
            foreach (string secret in new[] { "another-private", "history-private", "private-server", "https://" }) Assert(!text.Contains(secret));
            Assert(!WorkspaceHistory.SameConfiguration(current, old) && WorkspaceHistory.Compare(old, old).Count == 0);
        });
        Isolated("Legacy workspaces gain history on their first actual configuration edit", () =>
        {
            var legacy = Fixture(); Storage.Write(Storage.ProfilePath, legacy.Profile); Storage.Write(Subscriptions.PathName, legacy.Subscriptions);
            Save(Fixture(2)); Assert(WorkspaceHistory.SameConfiguration(WorkspaceHistory.Read().Single().State, legacy));
        });
        Isolated("Clearing history preserves workspace, preferences and network recovery journal", () =>
        {
            Save(Fixture()); Save(Fixture(2)); Storage.Write(Storage.PreferencesPath, new DesktopPreferences(false, true)); Storage.Write(Storage.JournalPath, "fixture-journal");
            string[] files = [Storage.WorkspacePath, Storage.PreferencesPath, Storage.JournalPath]; var original = files.Select(File.ReadAllBytes).ToArray();
            WorkspaceHistory.Clear(); Assert(WorkspaceHistory.Read().Count == 0);
            for (int index = 0; index < files.Length; index++) Assert(File.ReadAllBytes(files[index]).SequenceEqual(original[index]));
            Save(Fixture(3)); Assert(WorkspaceHistory.Read().Count == 1);
        });
        Isolated("Bounded atomic encryption refuses an oversized replacement before changing disk", () =>
        {
            string file = Path.Combine(Storage.Root, "bounded.dat"); Storage.Write(file, "original"); byte[] before = File.ReadAllBytes(file);
            Reject(() => Storage.Write(file, new string('x', 1024), 100)); Assert(File.ReadAllBytes(file).SequenceEqual(before));
            Reject(() => Storage.Write(file, "short", 10)); Assert(File.ReadAllBytes(file).SequenceEqual(before));
        });
    }
}
