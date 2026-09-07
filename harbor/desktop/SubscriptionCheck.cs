using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckSubscriptionWorkflowAsync(Func<Window, string, Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Subscription checks require isolation.");
        var previousProfile = profile.DeepClone().AsObject(); var previousEntries = Subscriptions.Read();
        var checks = new List<string>();
        void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException("Subscription workflow: " + message); }
        string Link(string name, int port, string password = "fixture") => $"socks5://fixture:{password}@127.0.0.1:{port}#{Uri.EscapeDataString(name)}";
        byte[] Saved() => File.ReadAllBytes(Storage.WorkspacePath);
        async Task Settled()
        {
            for (int index = 0; (busy || subscriptionCancellation != null) && index < 200; index++) await Task.Delay(10);
            Require(!busy && subscriptionCancellation == null, "operation did not settle");
        }
        try
        {
            const string feedName = "本机测试订阅";
            string Prefix(string name) => feedName + " · " + name;
            var candidate = (await client.CallAsync("default_config")).AsObject();
            candidate["listen"] = "127.0.0.1:" + FreePort(); candidate["dnsListen"] = "127.0.0.1:" + FreePort();
            candidate["nodes"] = ProfileImport.Parse(string.Join("\n", Link(Prefix("变更线路"), 9), Link(Prefix("不变线路"), 10), Link(Prefix("引用保留"), 11), Link(Prefix("移除线路"), 12), Link("手动线路", 13))).Nodes;
            candidate["finalPolicy"] = Prefix("变更线路");
            candidate["rules"] = new JsonArray(new JsonObject { ["kind"] = "domain_suffix", ["value"] = "keep.fixture.invalid", ["policy"] = Prefix("引用保留") });
            var usage = new SubscriptionUsage(1024 * 1024, 5UL * 1024 * 1024 * 1024 - 1024 * 1024, 20UL * 1024 * 1024 * 1024, DateTimeOffset.UtcNow.AddDays(3), DateTimeOffset.UtcNow);
            var entry = new SubscriptionEntry("feed-fixture", feedName, "https://feed.fixture.invalid/private-fixture-token", candidate["nodes"]!.AsArray().Select(node => S(node!, "name")).Where(name => name != "手动线路").ToArray(), DateTimeOffset.UtcNow, "\"v1\"", "", "before", 0, usage);
            var noMetadata = new SubscriptionEntry("no-metadata-fixture", "未提供统计的订阅", "https://no-metadata.fixture.invalid/feed", [], DateTimeOffset.UtcNow, "", "", "", 0);
            await SaveAsync(candidate, [entry, noMetadata]); Navigate(NavSubscriptions, new RoutedEventArgs());
            Require(SubscriptionUsageText.Text.Contains("5 GiB / 20 GiB", StringComparison.Ordinal) && SubscriptionUsageProgress.Value == 25 && SubscriptionUsageExpiry.Text.Contains("到期", StringComparison.Ordinal), "provider metadata was not displayed");
            SubscriptionGrid.SelectedItem = SubscriptionGrid.Items.OfType<SubscriptionRow>().Single(row => row.Id == noMetadata.Id); RefreshSubscriptionGrid();
            Require((SubscriptionGrid.SelectedItem as SubscriptionRow)?.Id == noMetadata.Id && SubscriptionUsageProgress.Visibility == Visibility.Collapsed && SubscriptionUsageText.Text.Contains("未提供", StringComparison.Ordinal), "missing metadata was shown as zero/unlimited or selection was reset");
            SubscriptionGrid.SelectedItem = SubscriptionGrid.Items.OfType<SubscriptionRow>().Single(row => row.Id == entry.Id);
            checks.Add("provider usage/expiry and absent metadata remain distinct; selection survives refresh");
            await StartAsync();
            byte[] originalDisk = Saved(); var originalProfile = profile.DeepClone().AsObject();

            async Task HeldDownload(bool disconnect)
            {
                var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var handler = new SubscriptionFixtureHandler(async (_, token) => { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return new HttpResponseMessage(HttpStatusCode.OK); });
                var operation = BeginSubscriptionRefreshAsync(entry.Id, (source, token) => Subscriptions.FetchWithHandlerAsync(source.Url, handler, source, token));
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
                Require(!busy && ConnectButton.IsEnabled && CancelSubscriptionButton.IsEnabled && !RefreshSubscriptionButton.IsEnabled && !RemoveSubscriptionButton.IsEnabled, "download blocked connection controls or allowed duplicate updates");
                if (!disconnect)
                {
                    Notice.Visibility = Visibility.Collapsed; await capture(this, "subscriptions-downloading-1280");
                    CancelSubscriptionButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                }
                else ToggleEngine(this, new RoutedEventArgs());
                await operation.WaitAsync(TimeSpan.FromSeconds(3)); await Settled();
                Require(Saved().SequenceEqual(originalDisk) && JsonNode.DeepEquals(profile, originalProfile) && running == !disconnect, "cancel or disconnect changed subscription data");
                bool engineRunning = (await client.CallAsync("snapshot"))["running"]!.GetValue<bool>();
                Require(engineRunning == !disconnect, $"engine state did not match the UI after download cancellation: disconnect={disconnect}, desktop={running}, engine={engineRunning}");
            }
            await HeldDownload(false); checks.Add("cancel interrupts a subscription download while preserving data and active listeners");
            await HeldDownload(true); checks.Add("disconnect cancels its pending subscription download before stopping listeners");
            await StartAsync();

            string updatedText = string.Join("\n", Link("变更线路", 9, "replacement-fixture"), Link("不变线路", 10), Link("新增线路", 14), "hysteria2://fixture@127.0.0.1:15#unsupported-fixture");
            var downloaded = new DownloadedSubscription(updatedText, "\"v2\"", "", "after", false, usage);
            bool Review(SubscriptionUpdate update, bool apply, bool render)
            {
                Require(update is { Added: 1, Changed: 1, Removed: 1, Retained: 1, Unchanged: 1 } && update.Issues.Count == 1, "preview did not describe the actual update");
                Require(Saved().SequenceEqual(originalDisk) && JsonNode.DeepEquals(profile, originalProfile), "preview changed data before approval");
                var dialog = new SubscriptionUpdatePreview(this, update); Exception? renderError = null;
                dialog.Loaded += async (_, _) =>
                {
                    try
                    {
                        if (render)
                        {
                            await capture(dialog, "subscription-update-preview");
                            dialog.Width = 640; await capture(dialog, "subscription-update-preview-640");
                        }
                        (apply ? dialog.ApplyButton : dialog.CancelButton).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    }
                    catch (Exception error) { renderError = error; dialog.DialogResult = false; }
                };
                bool accepted = dialog.ShowDialog() == true;
                if (renderError != null) throw new InvalidOperationException("Preview render failed.", renderError);
                return accepted;
            }
            await BeginSubscriptionRefreshAsync(entry.Id, (_, _) => Task.FromResult(downloaded), update => Review(update, false, false));
            Require(Saved().SequenceEqual(originalDisk) && JsonNode.DeepEquals(profile, originalProfile), "declining the real preview changed data");
            checks.Add("cancelling the real preview leaves profile and subscription bytes untouched");
            await BeginSubscriptionRefreshAsync(entry.Id, (_, _) => Task.FromResult(downloaded), update => Review(update, true, true));
            var updatedEntry = Subscriptions.Read().Single(item => item.Id == entry.Id);
            Require(updatedEntry.Digest == "after" && updatedEntry.NodeNames.Contains(Prefix("新增线路")) && updatedEntry.NodeNames.Contains(Prefix("引用保留")) && !updatedEntry.NodeNames.Contains(Prefix("移除线路")), "accepted preview did not apply ownership/retention atomically");
            Require(profile["nodes"]!.AsArray().Single(node => S(node!, "name") == Prefix("变更线路"))!["password"]!.GetValue<string>() == "replacement-fixture" && running, "changed credentials were not saved or engine was stopped");
            checks.Add("accepting the real preview applies changes and retains referenced proxies without stopping listeners");

            ulong generation = N(await client.CallAsync("snapshot"), "generation");
            var metadata = new DownloadedSubscription("", "\"v3\"", "", updatedEntry.Digest, true, usage with { Download = usage.Download + 1024, RecordedAt = DateTimeOffset.UtcNow });
            bool metadataReview = false;
            await BeginSubscriptionRefreshAsync(entry.Id, (_, _) => Task.FromResult(metadata), _ => { metadataReview = true; return false; });
            Require(!metadataReview && N(await client.CallAsync("snapshot"), "generation") == generation && Subscriptions.Read().Single(item => item.Id == entry.Id).Usage == metadata.Usage, "metadata-only update reconfigured the engine or lost statistics");
            checks.Add("unchanged content refreshes metadata without a preview or a runtime configuration generation");

            var beforeFailure = profile.DeepClone().AsObject(); byte[] failureDisk = Saved();
            var failing = new DownloadedSubscription(Link("另一个新线路", 16), "", "", "failed-save", false, null);
            File.SetAttributes(Storage.WorkspacePath, FileAttributes.ReadOnly);
            try { await BeginSubscriptionRefreshAsync(entry.Id, (_, _) => Task.FromResult(failing), _ => true); }
            finally { File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal); }
            var runtimeNames = (await client.CallAsync("snapshot"))["nodes"]!.AsArray().Select(node => S(node!, "name")).ToHashSet();
            Require(Saved().SequenceEqual(failureDisk) && JsonNode.DeepEquals(profile, beforeFailure) && runtimeNames.SetEquals(beforeFailure["nodes"]!.AsArray().Select(node => S(node!, "name"))), "save failure did not restore disk, UI and runtime ownership");
            checks.Add("failed persistence rolls runtime proxies back and preserves original encrypted workspace bytes");

            var enteredStale = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseStale = new TaskCompletionSource<DownloadedSubscription>(TaskCreationOptions.RunContinuationsAsynchronously);
            bool staleReview = false;
            var stale = BeginSubscriptionRefreshAsync(entry.Id, (_, token) => { enteredStale.SetResult(); return releaseStale.Task.WaitAsync(token); }, _ => { staleReview = true; return true; });
            await enteredStale.Task;
            var newerEntries = Subscriptions.Read(); int changedIndex = newerEntries.FindIndex(item => item.Id == entry.Id);
            newerEntries[changedIndex] = newerEntries[changedIndex] with { Url = "https://replacement.fixture.invalid/new-source" }; Subscriptions.Save(newerEntries); byte[] replacementDisk = Saved();
            releaseStale.SetResult(failing); await stale;
            Require(!staleReview && Saved().SequenceEqual(replacementDisk), "late response overwrote a replaced subscription source");
            checks.Add("a late response from a replaced subscription is discarded before review or writes");
            var noNodes = new DownloadedSubscription("{\"nodes\":[]}", "", "", "empty-response", false);
            await BeginSubscriptionRefreshAsync(entry.Id, (_, _) => Task.FromResult(noNodes), _ => true);
            Require(Saved().SequenceEqual(replacementDisk), "empty feed erased existing nodes");
            checks.Add("empty downloaded feed is rejected without changing current proxies");

            subscriptionStatus = "本机订阅流程验证 · 统计为示例数据";
            RefreshSubscriptionGrid(); Navigate(NavSubscriptions, new RoutedEventArgs()); Notice.Visibility = Visibility.Collapsed;
            await capture(this, "subscriptions-configured-1280");
            Width = 980; Height = 700; await capture(this, "subscriptions-configured-980"); Width = 1280; Height = 840;
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0, ["fixture"] = "Synthetic provider response headers and in-memory downloads; isolated running engine; real WPF review buttons", ["checks"] = new JsonArray(checks.Select(item => (JsonNode?)JsonValue.Create(item)).ToArray()) };
        }
        finally
        {
            if (File.Exists(Storage.WorkspacePath)) File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal);
            await CancelSubscriptionRefreshAsync(); if (running) await StopAsync(); Width = 1280; Height = 840;
            await SaveAsync(previousProfile, previousEntries); subscriptionStatus = "更新前可检查线路变化；下载过程中可以取消。";
            SyncSubscriptionControls(); Notice.Visibility = Visibility.Collapsed; Navigate(NavOverview, new RoutedEventArgs());
        }
    }

    private sealed class SubscriptionFixtureHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond(request, cancellationToken);
    }
}
