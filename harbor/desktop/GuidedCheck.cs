using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;

namespace Harbor;
public partial class MainWindow
{
    // Exercises production UI handlers against an isolated workspace. No external requests.
    internal async Task<JsonObject> CheckGuidedWorkflowAsync(Func<Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Guided checks require isolation.");
        var previous = profile.DeepClone().AsObject(); var subscriptions = Subscriptions.Read();
        void Require(bool value, string message) { if (!value) throw new InvalidOperationException("Guided workflow: " + message); }
        async Task Settled()
        {
            for (int i = 0; busy && i < 100; i++) await Task.Delay(20);
            Require(!busy, "UI action did not settle");
        }
        try
        {
            profile = (await client.CallAsync("default_config")).AsObject(); SyncProfile();
            await ImportTextAsync("socks5://fixture:password@127.0.0.1:9#本机测试线路甲\nsocks5://fixture:password@127.0.0.1:9#本机测试线路乙", false);
            Require(S(profile, "finalPolicy") == "本机测试线路甲" && (string?)HomePolicy.SelectedItem == "本机测试线路甲", "first import did not choose a node");
            Require(Storage.LoadWorkspace()?.Profile["finalPolicy"]?.GetValue<string>() == "本机测试线路甲", "selected route was not persisted");
            Require(NodeGrid.IsEnabled && NodeGrid.Items.Count == 2, "node list must be selectable");
            NodeSearch.Text = "线路乙"; Require(NodeGrid.Items.Count == 1 && ((NodeRow)NodeGrid.Items[0]).Name == "本机测试线路乙", "search did not filter by node name");
            NodeSearch.Text = "missing.fixture"; Require(NodeGrid.Items.Count == 0 && NodeEmptyTitle.Text == "没有匹配的线路", "filtered empty state is misleading");
            ResetNodeFilter(this, new RoutedEventArgs()); Require(NodeGrid.Items.Count == 2, "reset did not restore lines");
            HomePolicy.SelectedItem = "本机测试线路乙"; await Settled();
            Require(S(profile, "finalPolicy") == "本机测试线路乙", "home selection was not saved");
            RehearsalPolicy.SelectedItem = "DIRECT"; RehearsalTargets.Text = "example.com:443 tcp\nlocalhost:443 tcp";
            CompareExit(this, new RoutedEventArgs()); await Settled();
            Require(RehearsalGrid.Items.Count == 2 && S(profile, "finalPolicy") == "本机测试线路乙" && (string?)RehearsalPolicy.SelectedItem == "DIRECT", "comparison modified the active policy or reset the preview selection");
            RuleGrid.SelectedIndex = 0; ToggleRule(this, new RoutedEventArgs()); await Settled();
            Require(profile["rules"]![0]!["enabled"]?.GetValue<bool>() == false, "rule disable was not saved");
            ToggleRule(this, new RoutedEventArgs()); await Settled();
            Require(profile["rules"]![0]!["enabled"]?.GetValue<bool>() == true, "rule enable was not saved");
            DnsProvider.SelectedItem = "AdGuard · 广告与追踪过滤"; ApplyDnsProvider(this, new RoutedEventArgs()); await Settled();
            Require(ProfileWorkflow.DnsPreset(profile) == "AdGuard · 广告与追踪过滤", "DNS preset was not saved");
            EgressModeInput.SelectedIndex = 1; SaveSettings(this, new RoutedEventArgs()); await Settled();
            Require(S(profile, "egressMode") == "system" && Storage.LoadWorkspace()?.Profile["egressMode"]?.GetValue<string>() == "system", "upstream network choice was not persisted");
            EgressModeInput.SelectedIndex = 0; SaveSettings(this, new RoutedEventArgs()); await Settled();
            Require(S(profile, "egressMode") == "physical", "physical upstream mode was not restored");
            var beforeBlocked = profile.DeepClone().AsObject(); var blocked = profile.DeepClone().AsObject();
            blocked["nodes"]![1]!["server"] = "blocked.fixture.invalid";
            blocked["privacy"]!["blockedDomains"] = new JsonArray("blocked.fixture.invalid");
            await SaveAsync(blocked); ToggleEngine(this, new RoutedEventArgs()); await Settled();
            Require(!running && (await client.CallAsync("snapshot"))["running"]?.GetValue<bool>() == false && NoticeText.Text.Contains("DNS lookup blocked", StringComparison.Ordinal), "DNS failure did not stop connection before listener startup");
            VerifySelected(HomeVerify, new RoutedEventArgs());
            for (int i = 0; verifying && i < 150; i++) await Task.Delay(20);
            Require(!verifying && VerificationHistory.Load().Get(profile, "本机测试线路乙") is { Success: false }, "actual blocked verification did not persist a failure");
            NodeFilter.SelectedIndex = 3; Require(NodeGrid.Items.Count == 1 && ((NodeRow)NodeGrid.Items[0]).Name == "本机测试线路乙", "failed verification filter did not match");
            NodeFilter.SelectedIndex = 1; Require(NodeGrid.Items.Count == 0, "failed verification was presented as successful");
            ResetNodeFilter(this, new RoutedEventArgs());
            ClearLineChecks(this, new RoutedEventArgs()); Require(VerificationHistory.Load().Get(profile, "本机测试线路乙") == null, "clear left saved verification behind");
            await SaveAsync(beforeBlocked);
            var trayProfile = profile.DeepClone().AsObject(); trayProfile["listen"] = "127.0.0.1:" + FreePort(); trayProfile["dnsListen"] = "127.0.0.1:" + FreePort(); await SaveAsync(trayProfile);
            Require(Icon != null && tray?.Icon != null && trayToggle != null && trayStoppedIcon != null && trayConnectedIcon != null, "application or tray icon missing");
            using (var embedded = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!)) Require(embedded != null, "EXE icon missing");
            var toggle = trayToggle ?? throw new InvalidOperationException("Tray action missing");
            toggle.PerformClick(); await Settled();
            Require(running && ReferenceEquals(tray!.Icon, trayConnectedIcon) && toggle.Text?.Contains("断开", StringComparison.Ordinal) == true, "tray did not start the isolated listener or update its state");
            toggle.PerformClick(); await Settled();
            Require(!running && ReferenceEquals(tray!.Icon, trayStoppedIcon), "tray did not stop the listener or update its icon");
            try { busy = true; SyncTray(); Require(!toggle.Enabled && trayExit?.Enabled == false, "busy tray allowed concurrent start or exit"); } finally { busy = false; SyncTray(); }
            Hide(); ShowMainWindow(); Require(IsVisible && WindowState != WindowState.Minimized, "tray restore did not reveal the window");
            Require(!running && !SystemProxy.IsEnabled && !HomeMode.IsEnabled && !ClearDnsButton.IsEnabled, "isolated controls allowed system capture");
            Require((await client.CallAsync("snapshot"))["running"]?.GetValue<bool>() == false, "offline actions started listeners");
            Notice.Visibility = Visibility.Collapsed; OverviewSubtitle.Text = "隔离流程验证 · 示例线路未连接 · 未发送外部请求";
            await capture();
            return new JsonObject { ["passed"] = true, ["checks"] = new JsonArray("first import selects and persists node", "node table stays selectable", "node search and empty state", "home route switch persists", "route preview preserves configuration", "rule disable/enable persists", "DNS preset persists", "upstream network choice persists", "DNS preflight failure prevents listener startup", "actual blocked verification persists", "verification filters distinguish failure", "clear verification removes saved record", "application and tray icons load", "tray starts and stops isolated listeners", "busy tray prevents concurrent actions", "tray restores hidden window", "isolation locks system controls", "offline UI actions do not start listeners"), ["externalRequests"] = 0 };
        }
        finally { await SaveAsync(previous, subscriptions); Notice.Visibility = Visibility.Collapsed; }
    }
}
