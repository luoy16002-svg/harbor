using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckRoutingWorkflowAsync(Func<Window, string, Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Routing checks require isolation.");
        var previous = profile.DeepClone().AsObject(); var entries = Subscriptions.Read();
        bool timerInitiallyEnabled = timer.IsEnabled;
        string? oldPreviewMode = RehearsalRoutingMode.SelectedItem as string;
        var checks = new List<string>();
        void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException("Routing workflow: " + message); }
        async Task Settled()
        {
            for (int i = 0; busy && i < 150; i++) await Task.Delay(20);
            Require(!busy, "UI action did not settle");
        }
        async Task<JsonObject> Explain(string host) => (await client.CallAsync("explain", new JsonObject { ["host"] = host, ["port"] = 443 })).AsObject();
        try
        {
            var legacy = (await client.CallAsync("default_config")).AsObject(); legacy.Remove("routingMode");
            legacy["listen"] = "127.0.0.1:" + FreePort(); legacy["dnsListen"] = "127.0.0.1:" + FreePort();
            legacy["dnsTls"] = new JsonArray(); legacy["dnsServers"] = new JsonArray("127.0.0.1:9");
            legacy["privacy"]!["blockDirect"] = true;
            legacy["privacy"]!["blockedDomains"] = new JsonArray("unused.fixture.invalid", "blocked.fixture.invalid");
            await SaveAsync(legacy, []);
            Require((string?)HomeRoutingMode.SelectedItem == "按规则" && (string?)RoutingModeInput.SelectedItem == "按规则" && profile["routingMode"] == null, "old profile did not keep its rule routing");
            checks.Add("old profiles keep rule routing without requiring a migration write");

            HomeRoutingMode.SelectedItem = "全部直连"; await Settled();
            Require((string?)ConnectButton.Content == "连接" && !HomePolicy.IsEnabled && !HomeVerify.IsEnabled, "direct mode still demanded an imported proxy");
            ToggleEngine(this, new RoutedEventArgs()); await Settled();
            Require(running && S(await client.CallAsync("snapshot"), "routingMode") == "direct", "direct mode with no proxies did not start through the connection button");
            Require(Storage.LoadWorkspace()?.Profile["routingMode"]?.GetValue<string>() == "direct" && trayRoute?.Text?.Contains("DIRECT") == true, "saved or tray route does not match direct mode");
            checks.Add("home direct selection persists, updates the tray, and connects without any proxies");
            await StopAsync();

            var fixture = profile.DeepClone().AsObject();
            fixture["nodes"] = new JsonArray(new JsonObject { ["name"] = "本机分流测试线路", ["kind"] = "socks5", ["server"] = "unused.fixture.invalid", ["port"] = 9 });
            fixture["groups"] = new JsonArray(new JsonObject { ["name"] = "测试策略组", ["kind"] = "select", ["members"] = new JsonArray("本机分流测试线路", "DIRECT"), ["selected"] = "本机分流测试线路" });
            fixture["finalPolicy"] = "测试策略组";
            await SaveAsync(fixture, []); await StartAsync();
            Require(running, "direct preflight tried to resolve an unused proxy");
            checks.Add("direct startup ignores the unused proxy server blocked by local DNS privacy rules");

            bool timerWasEnabled = timer.IsEnabled; timer.Stop();
            var delayed = new TaskCompletionSource<JsonNode>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task? oldPoll = null;
            try
            {
                for (int i = 0; refreshing && i < 100; i++) await Task.Delay(10);
                Require(!refreshing, "previous status poll did not finish");
                oldPoll = RefreshAsync(() => delayed.Task);
                Require(refreshing, "delayed status poll did not start");
                await StopAsync(); await StartAsync();
                delayed.SetResult(new JsonObject { ["running"] = false }); await oldPoll;
                Require(running && snapshot?["running"]?.GetValue<bool>() == true && (await client.CallAsync("snapshot"))["running"]?.GetValue<bool>() == true, "a stale stopped reply shut down or repainted the new session");
                checks.Add("a delayed status reply from before disconnect cannot stop or repaint a reconnected engine");
            }
            finally
            {
                delayed.TrySetResult(new JsonObject { ["running"] = false });
                if (oldPoll != null) await oldPoll;
                if (timerWasEnabled) timer.Start();
            }

            ulong directGeneration = N(await client.CallAsync("snapshot"), "generation");
            RoutingModeInput.SelectedItem = "全局出口"; await Settled();
            var global = await Explain("localhost");
            Require(S(global, "outbound") == "本机分流测试线路" && global["ruleIndex"] == null && N(global, "generation") > directGeneration, "global mode did not override the localhost rule with the selected group");
            Require((string?)HomeRoutingMode.SelectedItem == "全局出口" && RuleGrid.Items.Cast<RuleRow>().All(row => row.State == "待用"), "home or rule status was not synchronized");
            Require(Storage.LoadWorkspace()?.Profile["routingMode"]?.GetValue<string>() == "global", "live mode was not persisted");
            HomeRoutingMode.SelectedItem = "按规则"; await Settled();
            Require(S(await Explain("localhost"), "outbound") == "DIRECT" && RuleGrid.Items.Cast<RuleRow>().All(row => row.State == "生效"), "switching back did not restore rule matching");
            checks.Add("both real mode selectors apply live, preserve groups and rules, and keep their displayed states synchronized");

            byte[] beforePreview = File.ReadAllBytes(Storage.WorkspacePath);
            ulong beforeGeneration = N(await client.CallAsync("snapshot"), "generation");
            RehearsalRoutingMode.SelectedItem = "全局出口"; RehearsalPolicy.SelectedItem = "测试策略组";
            RehearsalTargets.Text = "localhost:443 tcp\nblocked.fixture.invalid:443 udp";
            CompareExit(this, new RoutedEventArgs()); await Settled();
            var row = JsonSerializer.SerializeToNode(RehearsalGrid.Items[0])!;
            Require(RehearsalGrid.Items.Count == 2 && row["Before"]?.GetValue<string>() == "DIRECT" && row["After"]?.GetValue<string>() == "本机分流测试线路", "candidate mode was not included in route comparison");
            Require(File.ReadAllBytes(Storage.WorkspacePath).SequenceEqual(beforePreview) && N(await client.CallAsync("snapshot"), "generation") == beforeGeneration, "preview changed active or saved settings");
            checks.Add("offline preview compares candidate modes and groups without changing disk bytes or runtime generation");

            File.SetAttributes(Storage.WorkspacePath, FileAttributes.ReadOnly);
            try { HomeRoutingMode.SelectedItem = "全部直连"; await Settled(); }
            finally { File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal); }
            Require(File.ReadAllBytes(Storage.WorkspacePath).SequenceEqual(beforePreview) && ProfileWorkflow.RoutingMode(profile) == "rules", "failed persistence replaced the saved profile");
            Require((string?)HomeRoutingMode.SelectedItem == "按规则" && (string?)RoutingModeInput.SelectedItem == "按规则" && S(await client.CallAsync("snapshot"), "routingMode") == "rules", "failed save did not roll back UI and runtime routing");
            checks.Add("a failed atomic save restores the original desktop selections, disk bytes, and runtime mode");

            var releaseBusy = new TaskCompletionSource(); var pending = Safe(() => releaseBusy.Task);
            HomeRoutingMode.SelectedItem = "全部直连";
            Require((string?)HomeRoutingMode.SelectedItem == "按规则" && ProfileWorkflow.RoutingMode(profile) == "rules", "an overlapping action left an unsaved mode displayed");
            releaseBusy.SetResult(); await pending;
            checks.Add("an overlapping UI action cannot leave an unsaved routing mode selected");

            foreach (string label in new[] { "全局出口", "全部直连", "按规则" })
            {
                HomeRoutingMode.SelectedItem = label; await Settled();
                Require(S(await Explain("blocked.fixture.invalid"), "outbound") == "REJECT", "mode selection disabled the domain block list");
            }
            Require(RehearsalGrid.Items.Count == 0, "active configuration change retained an outdated route comparison");
            CompareExit(this, new RoutedEventArgs()); await Settled(); Require(RehearsalGrid.Items.Count == 2, "preview did not repopulate");
            RehearsalRoutingMode.SelectedItem = "全部直连"; Require(RehearsalGrid.Items.Count == 0, "candidate mode change kept stale results");
            CompareExit(this, new RoutedEventArgs()); await Settled();
            RehearsalTargets.Text = "localhost:80 tcp"; Require(RehearsalGrid.Items.Count == 0, "target edits kept stale results");
            CompareExit(this, new RoutedEventArgs()); await Settled();
            RehearsalPolicy.SelectedItem = "DIRECT"; Require(RehearsalGrid.Items.Count == 0, "candidate outbound change kept stale results");
            checks.Add("changes to active routing or candidate mode, outbound, and targets clear stale comparison results");
            HomeRoutingMode.SelectedItem = "全部直连"; await Settled();
            Require(S(await Explain("198.51.100.10"), "outbound") == "REJECT" && RoutingModeDescription.Text.Contains("会被拦截") && HomeRoutingDescription.Text.Contains("禁止"), "direct restriction or its explanation disappeared");
            checks.Add("privacy blocks remain effective in every mode and the direct-mode conflict is explained");
            timer.Stop();
            Navigate(NavRouting, new RoutedEventArgs()); RoutingPage.ScrollToTop(); Notice.Visibility = Visibility.Collapsed;
            Width = 980; Height = 700; await capture(this, "routing-direct-980");
            Width = 1280; Height = 840;
            HomeRoutingMode.SelectedItem = "全局出口"; await Settled(); Notice.Visibility = Visibility.Collapsed;
            RehearsalRoutingMode.SelectedItem = "按规则"; RehearsalPolicy.SelectedItem = "测试策略组";
            RehearsalTargets.Text = "localhost:443 tcp\nblocked.fixture.invalid:443 udp";
            CompareExit(this, new RoutedEventArgs()); await Settled();
            await capture(this, "routing-modes-1280"); Width = 980; Height = 700; await capture(this, "routing-modes-980");
            Navigate(NavOverview, new RoutedEventArgs()); OverviewSubtitle.Text = "本机分流流程验证 · 未发送外网请求";
            await capture(this, "overview-routing-980"); Width = 1280; Height = 840; await capture(this, "overview-routing-1280");
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0,
                ["fixture"] = "Isolated engine with local-only listeners, blocked unused proxy, real WPF mode selectors, and a forced save failure",
                ["checks"] = new JsonArray(checks.Select(item => (JsonNode?)JsonValue.Create(item)).ToArray()) };
        }
        finally
        {
            if (File.Exists(Storage.WorkspacePath)) File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal);
            if (running) await StopAsync(); Width = 1280; Height = 840;
            await SaveAsync(previous, entries); RehearsalRoutingMode.SelectedItem = oldPreviewMode;
            Notice.Visibility = Visibility.Collapsed; Navigate(NavOverview, new RoutedEventArgs());
            if (timerInitiallyEnabled) timer.Start();
        }
    }
}
