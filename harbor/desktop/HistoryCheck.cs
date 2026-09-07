using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckHistoryWorkflowAsync(Func<Window, string, Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("History checks require isolation.");
        var previous = new WorkspaceState(profile.DeepClone().AsObject(), Subscriptions.Read());
        byte[]? previousHistory = File.Exists(WorkspaceHistory.FilePath) ? File.ReadAllBytes(WorkspaceHistory.FilePath) : null;
        bool timerWasEnabled = timer.IsEnabled; timer.Stop();
        var checks = new List<string>();
        void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException("History workflow: " + message); }
        byte[] Saved() => File.ReadAllBytes(Storage.WorkspacePath);
        WorkspaceState Current() => WorkspaceHistory.Clone(new(profile, Subscriptions.Read()));
        async Task Reject(Func<Task> action)
        {
            try { await action(); } catch (Exception) { return; }
            throw new InvalidOperationException("History workflow accepted an invalid restore.");
        }
        WorkspaceHistoryDialog Review(bool allow, Func<WorkspaceHistoryDialog, Task> action, Func<bool>? clear = null)
        {
            var dialog = new WorkspaceHistoryDialog(this, Current(), allow, clear); Exception? failure = null;
            dialog.Loaded += async (_, _) =>
            {
                try { await action(dialog); }
                catch (Exception error) { failure = error; dialog.DialogResult = false; }
            };
            dialog.ShowDialog();
            if (failure != null) throw new InvalidOperationException("History dialog check failed.", failure);
            return dialog;
        }
        void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        try
        {
            WorkspaceHistory.Clear();
            Review(true, dialog =>
            {
                Require(dialog.Versions.Items.Count == 0 && !dialog.RestoreButton.IsEnabled && !dialog.ClearButton.IsEnabled, "empty history offered a restore");
                Click(dialog.CancelButton); return Task.CompletedTask;
            });
            checks.Add("an existing workspace without history displays an empty state and cannot restore");

            var initial = (await client.CallAsync("default_config")).AsObject();
            initial["listen"] = "127.0.0.1:" + FreePort(); initial["dnsListen"] = "127.0.0.1:" + FreePort();
            initial["dnsTls"] = new JsonArray(); initial["dnsServers"] = new JsonArray("127.0.0.1:9"); initial["privacy"]!["blockDirect"] = true;
            initial["nodes"] = ProfileImport.Parse("socks5://fixture:history-secret-before@127.0.0.1:9#日常线路\nsocks5://fixture:history-secret-spare@127.0.0.1:10#备用线路").Nodes;
            initial["groups"] = new JsonArray(new JsonObject { ["name"] = "常用策略", ["kind"] = "select", ["members"] = new JsonArray("日常线路", "备用线路"), ["selected"] = "日常线路" });
            initial["finalPolicy"] = "日常线路";
            var feed = new SubscriptionEntry("history-feed", "本机历史测试订阅", "https://feed.fixture.invalid/history-secret-token", ["日常线路", "备用线路"],
                DateTimeOffset.UtcNow.AddDays(-1), "\"old-feed\"", "Mon, 07 Sep 2026 00:00:00 GMT", "old-digest", 0, new(0, 1, 10, null, DateTimeOffset.UtcNow));
            await SaveAsync(initial, [feed]); WorkspaceHistory.Clear();
            var old = Current(); var changed = initial.DeepClone().AsObject();
            changed["nodes"]![0]!["password"] = "history-secret-after";
            changed["nodes"]!.AsArray().Add(new JsonObject { ["name"] = "临时线路", ["kind"] = "socks5", ["server"] = "127.0.0.1", ["port"] = 11 });
            changed["routingMode"] = "global"; changed["finalPolicy"] = "常用策略"; changed["groups"]![0]!["selected"] = "备用线路";
            changed["privacy"]!["hideMetadata"] = true;
            changed["rules"]!.AsArray().Add(new JsonObject { ["kind"] = "domain_suffix", ["value"] = "history.fixture.invalid", ["policy"] = "备用线路" });
            await SaveAsync(changed, [feed with { Url = "https://feed.fixture.invalid/history-secret-replacement" }]);
            var original = WorkspaceHistory.Read().Single(); var before = Current(); byte[] disk = Saved(); byte[] historyBytes = File.ReadAllBytes(WorkspaceHistory.FilePath);
            Require(WorkspaceHistory.SameConfiguration(original.State, old), "automatic snapshot did not preserve the actual predecessor");
            checks.Add("normal configuration save records the original proxies, subscriptions, groups, rules and privacy settings");

            Review(true, async dialog =>
            {
                Require(dialog.RestoreButton.IsEnabled && dialog.Differences.Items.Count >= 7, "restore preview omitted changed sections");
                var details = string.Join(" ", dialog.Differences.Items.OfType<WorkspaceChange>().Select(row => row.Area + row.Detail));
                Require(!details.Contains("history-secret") && !details.Contains("https://"), "preview exposed a credential or URL token");
                await capture(dialog, "workspace-history-preview"); dialog.Width = 660; await capture(dialog, "workspace-history-preview-660");
                Click(dialog.CancelButton);
            });
            Require(Saved().SequenceEqual(disk) && File.ReadAllBytes(WorkspaceHistory.FilePath).SequenceEqual(historyBytes), "preview cancellation changed encrypted data");
            checks.Add("the real preview shows configuration differences at two widths and cancellation preserves both encrypted files");

            var request = new WorkspaceRestoreRequest(original.Id, before, WorkspaceHistory.Clone(original.State));
            await StartAsync();
            Review(false, dialog => { Require(!dialog.RestoreButton.IsEnabled && dialog.Status.Text.Contains("断开"), "running preview allowed restore"); Click(dialog.CancelButton); return Task.CompletedTask; });
            await Reject(() => RestoreWorkspaceAsync(request)); Require(running && Saved().SequenceEqual(disk), "running restore changed the session");
            checks.Add("history remains viewable during a session and both UI and application guards reject restoration while connected");

            File.SetAttributes(WorkspaceHistory.FilePath, FileAttributes.ReadOnly);
            try
            {
                HomeRoutingMode.SelectedItem = "全部直连";
                for (int index = 0; busy && index < 200; index++) await Task.Delay(10);
                Require(!busy && Saved().SequenceEqual(disk) && JsonNode.DeepEquals(profile, before.Profile) && (string?)HomeRoutingMode.SelectedItem == "统一出口" &&
                    S(await client.CallAsync("snapshot"), "routingMode") == "global", "failed history write did not roll back disk, desktop and running mode");
            }
            finally { File.SetAttributes(WorkspaceHistory.FilePath, FileAttributes.Normal); }
            checks.Add("a read-only history file blocks a live edit and restores the original disk, desktop selections and runtime routing");
            await StopAsync();

            var invalidState = WorkspaceHistory.Clone(original.State); invalidState.Profile["finalPolicy"] = "missing-history-policy";
            Storage.Write(WorkspaceHistory.FilePath, new WorkspaceHistoryFile(1, [original with { State = invalidState }]));
            await Reject(() => RestoreWorkspaceAsync(new(original.Id, before, invalidState)));
            Require(Saved().SequenceEqual(disk) && JsonNode.DeepEquals(profile, before.Profile), "engine validation failure replaced the workspace");
            File.WriteAllBytes(WorkspaceHistory.FilePath, historyBytes);
            checks.Add("the engine rejects an invalid historical policy reference before any workspace replacement");

            var latest = profile.DeepClone().AsObject(); latest["privacy"]!["historySecs"] = 120;
            await SaveAsync(latest); var currentAfterEdit = Current(); byte[] afterEdit = Saved();
            await Reject(() => RestoreWorkspaceAsync(request)); Require(Saved().SequenceEqual(afterEdit), "an outdated review overwrote a newer edit");
            var revisions = WorkspaceHistory.Read(); var altered = WorkspaceHistory.Clone(original.State); altered.Profile["routingMode"] = "direct";
            Storage.Write(WorkspaceHistory.FilePath, new WorkspaceHistoryFile(1, revisions.Select(item => item.Id == original.Id ? item with { State = altered } : item).ToList()));
            await Reject(() => RestoreWorkspaceAsync(new(original.Id, currentAfterEdit, original.State)));
            Storage.Write(WorkspaceHistory.FilePath, new WorkspaceHistoryFile(1, revisions));
            Require(Saved().SequenceEqual(afterEdit), "a historical version changed after preview was accepted");
            checks.Add("changed current settings or a changed selected revision invalidate an earlier review");

            byte[]? preferences = File.Exists(Storage.PreferencesPath) ? File.ReadAllBytes(Storage.PreferencesPath) : null;
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); bool downloadCancelled = false;
            var pending = BeginSubscriptionRefreshAsync(feed.Id, async (_, token) =>
            {
                entered.TrySetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, token); return new DownloadedSubscription("", "", "", "", false); }
                finally { downloadCancelled = token.IsCancellationRequested; }
            });
            await entered.Task;
            var accepted = Review(true, dialog =>
            {
                dialog.Versions.SelectedItem = dialog.Versions.Items.OfType<WorkspaceRevision>().Single(item => item.Id == original.Id);
                Require(dialog.RestoreButton.IsEnabled && !downloadCancelled, "viewing history cancelled a pending download");
                Click(dialog.RestoreButton); return Task.CompletedTask;
            });
            Require(accepted.Request != null, "restore button did not return the reviewed selection");
            await Safe(() => RestoreWorkspaceAsync(accepted.Request!)); await pending;
            var restored = Current(); var restoredFeed = restored.Subscriptions.Single();
            Require(!running && downloadCancelled && WorkspaceHistory.SameConfiguration(restored, old) && restoredFeed.Etag == "" && restoredFeed.LastModified == "" && restoredFeed.Digest == "" && restoredFeed.Usage == null,
                "accepted restore did not cancel the download and restore profile/ownership without stale metadata");
            Require((string?)HomeRoutingMode.SelectedItem == "按规则" && NodeGrid.Items.Count == 2 && SubscriptionUsageText.Text.Contains("未提供"), "restored profile was not reflected in the UI");
            Require(preferences == null ? !File.Exists(Storage.PreferencesPath) : File.ReadAllBytes(Storage.PreferencesPath).SequenceEqual(preferences), "restore changed desktop network preferences");
            checks.Add("the real restore button cancels a pending download, synchronizes all workspace views, resets feed validators and remains disconnected");

            var undo = WorkspaceHistory.Read()[0]; Require(WorkspaceHistory.SameConfiguration(undo.State, currentAfterEdit), "restore did not retain its predecessor");
            var undoDialog = Review(true, dialog => { Click(dialog.RestoreButton); return Task.CompletedTask; });
            await Safe(() => RestoreWorkspaceAsync(undoDialog.Request!));
            Require(WorkspaceHistory.SameConfiguration(Current(), currentAfterEdit) && !running, "a second reviewed restore could not undo the first");
            checks.Add("restoration automatically retains its predecessor so a second reviewed restore can undo it");

            byte[] beforeClear = Saved(); bool confirm = false;
            Review(true, dialog =>
            {
                Click(dialog.ClearButton); Require(dialog.Versions.Items.Count > 0, "declining clear deleted history");
                confirm = true; Click(dialog.ClearButton);
                Require(dialog.Versions.Items.Count == 0 && !dialog.RestoreButton.IsEnabled && Saved().SequenceEqual(beforeClear), "clearing history changed the workspace or left a stale selection active");
                Click(dialog.CancelButton); return Task.CompletedTask;
            }, () => confirm);
            checks.Add("clear confirmation can be declined and accepted clearing removes only history and disables the selected restore");

            File.WriteAllText(WorkspaceHistory.FilePath, "corrupt isolated fixture");
            Review(true, async dialog =>
            {
                Require(!dialog.RestoreButton.IsEnabled && dialog.ClearButton.IsEnabled && dialog.Status.Text.Contains("无法读取"), "corrupt history did not show a recoverable error");
                await capture(dialog, "workspace-history-unavailable"); Click(dialog.ClearButton); Click(dialog.CancelButton);
            }, () => true);
            Require(Saved().SequenceEqual(beforeClear) && WorkspaceHistory.Read().Count == 0, "corrupt history recovery touched current data");
            checks.Add("unreadable history disables restore and can be cleared without decrypting or modifying the current workspace");

            var final = profile.DeepClone().AsObject(); final["routingMode"] = "rules"; await SaveAsync(final);
            Navigate(NavSettings, new RoutedEventArgs()); SettingsPage.ScrollToTop(); Notice.Visibility = Visibility.Collapsed;
            Width = 1280; Height = 840; await capture(this, "settings-history-1280"); Width = 980; Height = 700; await capture(this, "settings-history-980");
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0,
                ["fixture"] = "Isolated encrypted workspace, local-only engine, real WPF history dialogs and buttons, held subscription task, and forced persistence failures",
                ["checks"] = new JsonArray(checks.Select(item => (JsonNode?)JsonValue.Create(item)).ToArray()) };
        }
        finally
        {
            if (File.Exists(WorkspaceHistory.FilePath)) File.SetAttributes(WorkspaceHistory.FilePath, FileAttributes.Normal);
            if (running) await StopAsync();
            WorkspaceHistory.Clear(); await SaveAsync(previous.Profile, previous.Subscriptions);
            if (previousHistory == null) WorkspaceHistory.Clear(); else File.WriteAllBytes(WorkspaceHistory.FilePath, previousHistory);
            Width = 1280; Height = 840; Notice.Visibility = Visibility.Collapsed; Navigate(NavOverview, new RoutedEventArgs());
            if (timerWasEnabled) timer.Start();
        }
    }
}
