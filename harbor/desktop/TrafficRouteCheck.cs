using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckTrafficRoutesAsync(Func<Window, string, Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Path checks require isolation.");
        var previous = profile.DeepClone().AsObject(); var subscriptions = Subscriptions.Read();
        bool timerWasEnabled = timer.IsEnabled; timer.Stop(); var checks = new List<string>();
        void Require(bool value, string message) { if (!value) throw new InvalidOperationException("Traffic paths: " + message); }
        void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        async Task Settled() { for (int i = 0; busy && i < 150; i++) await Task.Delay(20); Require(!busy, "action did not settle"); UpdateLayout(); }
        IEnumerable<Button> Buttons(DependencyObject root)
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            {
                var child = VisualTreeHelper.GetChild(root, i); if (child is Button button) yield return button;
                foreach (var descendant in Buttons(child)) yield return descendant;
            }
        }
        Button CardButton(string label, int index) => Buttons(TrafficRouteCards).Single(button => button.Content as string == label && button.Tag is int tag && tag == index);
        bool HasText(DependencyObject root, string text)
        {
            if (root is TextBlock block && block.Text.Contains(text)) return true;
            return Enumerable.Range(0, VisualTreeHelper.GetChildrenCount(root)).Any(i => HasText(VisualTreeHelper.GetChild(root, i), text));
        }
        TrafficRouteDialog Dialog(TrafficRouteSetting initial, Func<TrafficRouteDialog, Task> action)
        {
            var dialog = new TrafficRouteDialog(this, profile, initial); Exception? failure = null;
            dialog.Loaded += async (_, _) => { try { await action(dialog); } catch (Exception error) { failure = error; dialog.DialogResult = false; } };
            dialog.ShowDialog(); if (failure != null) throw new InvalidOperationException("Path editor failed", failure); return dialog;
        }
        async Task<JsonNode> Explain(string protocol = "tcp") => await client.CallAsync("explain", new JsonObject { ["host"] = "work.example", ["port"] = 443, ["protocol"] = protocol });
        try
        {
            var fixture = (await client.CallAsync("default_config")).AsObject(); fixture.Remove("trafficRoutes");
            fixture["listen"] = "127.0.0.1:" + FreePort(); fixture["dnsListen"] = "127.0.0.1:" + FreePort();
            fixture["dnsTls"] = new JsonArray(); fixture["dnsServers"] = new JsonArray("127.0.0.1:9"); fixture["probeIntervalSecs"] = 3600;
            fixture["nodes"] = new JsonArray(
                new JsonObject { ["name"] = "本机普通线路", ["kind"] = "socks5", ["server"] = "127.0.0.1", ["port"] = 9 },
                new JsonObject { ["name"] = "本机 TLS 线路", ["kind"] = "https", ["server"] = "127.0.0.1", ["port"] = 9 },
                new JsonObject { ["name"] = "本机加密线路", ["kind"] = "shadowsocks", ["server"] = "127.0.0.1", ["port"] = 9, ["password"] = "public-fixture" });
            fixture["groups"] = new JsonArray(new JsonObject { ["name"] = "加密备用组", ["kind"] = "fallback", ["members"] = new JsonArray("本机普通线路", "本机 TLS 线路", "本机加密线路") });
            fixture["directExceptions"] = DirectExceptions.Parse(true, "work.example", "").ToJson();
            fixture["finalPolicy"] = "本机普通线路"; fixture["routingMode"] = "direct";
            await SaveAsync(fixture, []); await StartAsync(); fixture = profile.DeepClone().AsObject(); fixture["routingMode"] = "global"; await SaveAsync(fixture);
            Require(TrafficRouteCards.Items.Count == 0 && TrafficRouteEmpty.Visibility == Visibility.Visible, "legacy workspace did not keep an empty path list");
            var work = new TrafficRouteSetting("工作网站 · 加密保护", true, ["work.example"], ["Work.exe"], "本机 TLS 线路", true);
            byte[] disk = File.ReadAllBytes(Storage.WorkspacePath);
            Dialog(work, dialog => { dialog.NameInput.Text = "取消的路径"; dialog.DialogResult = false; return Task.CompletedTask; });
            Require(disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)), "cancel changed the workspace");
            checks.Add("legacy workspace and editor cancellation preserve disk and active routing");
            Dialog(work, dialog =>
            {
                dialog.DomainsInput.Text = "https://work.example"; Click(dialog.SaveButton);
                Require(dialog.Result == null && dialog.IsVisible && dialog.ErrorText.Text.Length > 0, "invalid path escaped the editor");
                dialog.DialogResult = false; return Task.CompletedTask;
            });
            checks.Add("invalid domain input keeps the path editor open with an error");
            var accepted = Dialog(work, async dialog =>
            {
                await capture(dialog, "traffic-path-editor"); dialog.Width = 620; dialog.Height = 600; await capture(dialog, "traffic-path-editor-620");
                Require(HasText(dialog.PolicyInput, "线路 · 本机 TLS 线路"), "selected outbound did not render its readable label");
                var fixedChoice = dialog.PolicyInput.SelectedItem;
                dialog.PolicyInput.SelectedItem = dialog.PolicyInput.Items.Cast<object>().Single(item => item.ToString() == "策略组 · 加密备用组"); dialog.UpdateLayout();
                Require(HasText(dialog.PolicyInput, "策略组 · 加密备用组") && HasText(dialog, "TCP 2 / UDP 1"), "group selection did not update its label and transport counts");
                ((DockPanel)dialog.Content).Children.OfType<ScrollViewer>().Single().ScrollToEnd();
                await capture(dialog, "traffic-path-editor-bottom-620");
                dialog.PolicyInput.SelectedItem = fixedChoice; Click(dialog.SaveButton);
                checks.Add("outbound picker renders readable labels and updates configured TCP/UDP counts when selecting a group");
            });
            Require(accepted.Result != null, "save did not produce a path");
            await SaveTrafficRoutesAsync([accepted.Result!]);
            Require(TrafficRoutes.Read(Storage.LoadWorkspace()!.Profile).Single().RequireEncryptedProxy && S(await Explain(), "outbound") == "本机 TLS 线路" && S(await Explain("udp"), "outbound") == "REJECT", "persisted path did not override legacy direct routing or enforce UDP protection");
            checks.Add("saved path overrides legacy exceptions, uses TLS for TCP, and rejects unsupported protected UDP");
            Navigate(NavRouting, new RoutedEventArgs()); RoutingPage.ScrollToTop(); UpdateLayout();
            ExplainInput.Text = "203.0.113.1:443"; ExplainProcess.Text = "Work.exe"; ExplainProtocol.SelectedItem = "udp";
            disk = File.ReadAllBytes(Storage.WorkspacePath); ulong generation = N(await client.CallAsync("snapshot"), "generation");
            await ExplainOfflineAsync();
            Require(ExplainPath.Visibility == Visibility.Visible && ExplainPathText.Text.Contains("拦截") && ExplainPathFacts.Text.Contains("手动输入") && ExplainPathFacts.Text.Contains("保护要求") && ExplainPathFacts.Text.Contains("UDP 不支持"), "process preview did not show the protected UDP path and its cause");
            Require(disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)) && N(await client.CallAsync("snapshot"), "generation") == generation, "offline path check changed active or saved configuration");
            ExplainProtocol.SelectedItem = "tcp"; Require(ExplainPath.Visibility == Visibility.Collapsed, "input change left a stale visual path");
            checks.Add("process and transport preview is offline and clears stale results when inputs change");
            var shadow = new TrafficRouteSetting("直连优先级测试", true, ["work.example"], [], "DIRECT", false);
            await SaveTrafficRoutesAsync([work, shadow]); UpdateLayout();
            Require(((TrafficRouteRow)TrafficRouteCards.Items[1]).Advice.Contains("全部条件"), "fully shadowed card did not explain its priority");
            Dialog(shadow with { Name = "重叠预览" }, dialog =>
            {
                Require(dialog.OverlapText.Text.Contains("全部条件"), "editor omitted live priority advice");
                dialog.DomainsInput.Text = "unrelated.example";
                Require(!dialog.OverlapText.Text.Contains("全部条件") && dialog.OverlapText.Text.Contains("可能同时命中"), "editor retained stale full-coverage advice");
                dialog.DialogResult = false; return Task.CompletedTask;
            });
            var cardSource = TrafficRouteCards.ItemsSource; var editButton = CardButton("编辑", 0);
            System.Windows.Input.FocusManager.SetFocusedElement(this, editButton);
            double scrollOffset = RoutingPage.VerticalOffset;
            for (int i = 0; i < 3; i++) SyncHome(); UpdateLayout();
            Require(ReferenceEquals(cardSource, TrafficRouteCards.ItemsSource) && ReferenceEquals(editButton, CardButton("编辑", 0)) &&
                ReferenceEquals(System.Windows.Input.FocusManager.GetFocusedElement(this), editButton) && RoutingPage.VerticalOffset == scrollOffset,
                "unchanged status refresh recreated cards or lost focus/scroll position");
            checks.Add("overlap advice updates in cards and editor while unchanged refresh preserves card focus and scroll");
            Notice.Visibility = Visibility.Collapsed; Width = 980; Height = 700; UpdateLayout(); RoutingPage.ScrollToVerticalOffset(280);
            await capture(this, "traffic-path-overlap-980");
            Click(CardButton("↓", 0)); await Settled(); Require(S(await Explain(), "outbound") == "DIRECT", "move-down did not change first-match priority");
            Click(CardButton("↑", 1)); await Settled(); Require(S(await Explain(), "outbound") == "本机 TLS 线路", "move-up did not restore priority");
            Click(CardButton("停用", 0)); await Settled(); Require(S(await Explain(), "outbound") == "DIRECT", "disable did not restore the next path");
            Click(CardButton("启用", 0)); await Settled(); Require(S(await Explain(), "outbound") == "本机 TLS 线路", "enable did not restore the protected path");
            Click(CardButton("移除", 1)); await Settled(); Require(TrafficRoutes.Read(profile).Count == 1, "remove did not save the card list");
            checks.Add("real card buttons change priority, disable, enable, and remove paths in the running engine");
            disk = File.ReadAllBytes(Storage.WorkspacePath); File.SetAttributes(Storage.WorkspacePath, FileAttributes.ReadOnly); bool rejected = false;
            try { await SaveTrafficRoutesAsync([work with { Enabled = false }]); }
            catch (IOException) { rejected = true; } catch (UnauthorizedAccessException) { rejected = true; }
            finally { File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal); }
            Require(rejected && disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)) && TrafficRoutes.Read(profile).Single().Enabled && S(await Explain(), "outbound") == "本机 TLS 线路", "failed save did not roll back disk, cards and live routing");
            checks.Add("failed atomic persistence rolls back the saved profile, displayed path, and running engine");
            var renamed = profile.DeepClone().AsObject(); renamed["nodes"]![1]!["name"] = "改名后的 TLS 线路"; RenameReferences(renamed, "本机 TLS 线路", "改名后的 TLS 线路");
            await client.CallAsync("validate", new JsonObject { ["config"] = renamed });
            Require(TrafficRoutes.Read(renamed).Single().Policy == "改名后的 TLS 线路", "node rename did not update its path reference");
            Require(WorkspaceHistory.Read().Any(revision => TrafficRoutes.Read(revision.State.Profile).Count > 0), "history omitted path settings");
            checks.Add("node renaming updates route references and encrypted history retains previous paths");
            await SaveTrafficRoutesAsync([
                new("原神 / 米哈游直连", true, DirectExceptions.GameDomains.ToArray(), DirectExceptions.GameProcesses.ToArray(), "DIRECT", false),
                work,
                new("媒体网站 · 自动备用", true, ["media.example"], [], "加密备用组", true)
            ]);
            Require(TrafficRouteCards.Items.Count == 3 && TrafficDefault.Text.Contains("本机普通线路"), "visual route list or default summary missing");
            Notice.Visibility = Visibility.Collapsed; RoutingPage.ScrollToTop(); Width = 1280; Height = 840; await capture(this, "traffic-paths-1280");
            Width = 980; Height = 700; await capture(this, "traffic-paths-980");
            ExplainInput.Text = "work.example:443"; ExplainProcess.Text = ""; ExplainProtocol.SelectedItem = "udp"; await ExplainOfflineAsync();
            ExplainPath.BringIntoView(); await capture(this, "traffic-path-preview-980");
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0, ["checks"] = new JsonArray(checks.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()) };
        }
        finally
        {
            if (File.Exists(Storage.WorkspacePath)) File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal);
            if (running) await StopAsync(); Width = 1280; Height = 840; ExplainProcess.Text = ""; ExplainProtocol.SelectedItem = "tcp";
            await SaveAsync(previous, subscriptions); Navigate(NavOverview, new RoutedEventArgs()); Notice.Visibility = Visibility.Collapsed;
            if (timerWasEnabled) timer.Start();
        }
    }
}
