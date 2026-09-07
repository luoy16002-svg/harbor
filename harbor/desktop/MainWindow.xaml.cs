using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace Harbor;
public partial class MainWindow : Window
{
    internal readonly TaskCompletionSource Ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal bool InitializationCompleted { get; private set; }
    private EngineClient? client; private Process? guardian; private JsonObject profile = new(); private JsonNode? snapshot;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private Forms.NotifyIcon? tray; private bool running, busy, refreshing, syncing, quitting;
    private ulong lastUp, lastDown; private DateTime lastSample = DateTime.UtcNow;
    private List<FlowRow> flows = [];
    public MainWindow() { InitializeComponent(); Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/Assets/harbor.ico")); timer.Tick += async (_, _) => await RefreshAsync(); }
    private async void WindowLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var preferences = Storage.Read<DesktopPreferences>(Storage.PreferencesPath) ?? new(); SystemProxy.IsChecked = !App.Isolated && preferences.SystemProxy; MinimizeToTray.IsChecked = preferences.MinimizeToTray; ProtectExistingProxy.IsChecked = App.Isolated || preferences.ProtectExistingProxy; SystemProxy.IsEnabled = !App.Isolated; TunEnabled.IsEnabled = !App.Isolated; ProtectExistingProxy.IsEnabled = !App.Isolated;
            var recovered = Recovery.Restore(Storage.JournalPath, true); RecoveryText.Text = recovered.Message;
            string path = Path.Combine(AppContext.BaseDirectory, "harbor-engine.exe"); if (!File.Exists(path)) path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../target/debug/harbor-engine.exe"));
            client = new EngineClient(path); client.Exited += message => Dispatcher.InvokeAsync(() => { verificationCancellation?.Cancel(); if (!applyingSubscription) subscriptionCancellation?.Cancel(); if (!quitting) { running = false; SetRunning(); ShowNotice(message); try { RecoveryText.Text = Recovery.Restore(Storage.JournalPath, true).Message; } catch (Exception error) { ShowNotice(error.Message); } } });
            profile = Storage.LoadWorkspace()?.Profile ?? (await client.CallAsync("default_config")).AsObject(); if (App.Isolated) profile["tun"] = false; bool dnsUpgraded = ProfileWorkflow.UpgradeDefaultDns(profile); bool egressUpgraded = ProfileWorkflow.UpgradeEgress(profile);
            await client.CallAsync("validate", new JsonObject { { "config", profile.DeepClone() } });
            if (dnsUpgraded || egressUpgraded) { string backupSource = File.Exists(Storage.WorkspacePath) ? Storage.WorkspacePath : Storage.ProfilePath; if (File.Exists(backupSource) && !File.Exists(backupSource + ".pre-0.3.1")) File.Copy(backupSource, backupSource + ".pre-0.3.1"); Storage.SaveWorkspace(profile, Subscriptions.Read()); }
            SyncProfile(); RefreshNetworkState(); if (dnsUpgraded || egressUpgraded) ShowNotice((dnsUpgraded ? "默认 DNS 已更新为 HTTPS 加密解析：阿里 DNS 优先，Cloudflare 备用。" : "") + (egressUpgraded ? "Harbor 的连接现在自动选择物理网络，可在设置中改为跟随系统。" : "") + "原加密配置已备份。");
            try { lineChecks = VerificationHistory.Load(); RefreshNodes(); SyncHome(); } catch (Exception error) { ShowNotice("线路验证记录无法读取，可重新验证：" + error.Message); }
            InitializeTray();
            timer.Start();
            InitializationCompleted = true;
        }
        catch (Exception error) { ShowNotice(error.Message); ConnectButton.IsEnabled = false; }
        finally { Ready.TrySetResult(); }
    }
    private async Task Safe(Func<Task> action)
    {
        if (busy) return; busy = true; ConnectButton.IsEnabled = false; SyncTray(); SyncSubscriptionControls();
        try { await action(); } catch (Exception error) { ShowNotice(error.Message); } finally { busy = false; ConnectButton.IsEnabled = client != null; SyncHome(); }
    }
    private void ShowNotice(string text) { NoticeText.Text = text; Notice.Visibility = Visibility.Visible; if (!IsVisible && tray != null && !quitting) tray.ShowBalloonTip(4000, "Harbor", text.Length > 220 ? text[..217] + "…" : text, Forms.ToolTipIcon.Info); }
    private void DismissNotice(object sender, RoutedEventArgs e) => Notice.Visibility = Visibility.Collapsed;
    private void Navigate(object sender, RoutedEventArgs e)
    {
        string name = (sender as Button)?.Tag?.ToString() ?? "Overview";
        foreach (string key in new[] { "Overview", "Connections", "Nodes", "Subscriptions", "Routing", "Dns", "Diagnostics", "Privacy", "Network", "Settings" })
        {
            ((UIElement)FindName(key + "Page")).Visibility = key == name ? Visibility.Visible : Visibility.Collapsed;
            ((Button)FindName("Nav" + key)).Background = key == name ? new SolidColorBrush(Color.FromRgb(223, 233, 228)) : Brushes.Transparent;
        }
        if (name is "Subscriptions" or "Dns" or "Diagnostics") ((Button)FindName("Nav" + (name == "Subscriptions" ? "Nodes" : name == "Dns" ? "Privacy" : "Network"))).Background = new SolidColorBrush(Color.FromRgb(223, 233, 228));
        string label = name switch { "Overview" => "总览", "Connections" => "连接", "Nodes" => "线路", "Subscriptions" => "订阅", "Routing" => "分流", "Dns" => "DNS", "Diagnostics" => "诊断", "Privacy" => "隐私保护", "Network" => "网络管理", _ => "设置" }; Breadcrumb.Text = label; if (name == "Network") { try { RefreshNetworkState(); } catch (Exception error) { ShowNotice(error.Message); } }
        if (name == "Subscriptions") RefreshSubscriptionGrid();
    }
    private async void ToggleEngine(object sender, RoutedEventArgs e)
    {
        if (!running && profile["nodes"]!.AsArray().Count == 0) { AddLines(sender, e); return; }
        await Safe(async () => { if (running) await StopAsync(); else await StartAsync(); });
    }
    private async Task StartAsync()
    {
        await CancelSubscriptionRefreshAsync();
        await CancelVerificationAsync();
        if (client == null) return;
        RunState.Text = "正在启动…";
        try
        {
            await client.CallAsync("preflight", new JsonObject { ["config"] = profile.DeepClone() }, 20);
            var environment = NetworkEnvironment.Read();
            bool tun = profile["tun"]?.GetValue<bool>() == true;
            bool followSystem = S(profile, "egressMode") == "system";
            if (!App.Isolated && ProtectExistingProxy.IsChecked == true && SystemProxy.IsChecked == true && !tun && environment.ProxyConfigured)
            {
                if (!IsVisible) ShowMainWindow();
                if (MessageBox.Show(this, "当前已有系统代理。继续后，遵循系统代理的应用将切换到 Harbor；断开时恢复原设置。\n\n" + (environment.VirtualAdapterActive && followSystem ? "还检测到虚拟网络：当前上游跟随系统，线路可能继续经过该网络。\n\n" : "") + "切换到 Harbor？", "切换系统代理", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) { SetRunning(); return; }
            }
            else if (!App.Isolated && ProtectExistingProxy.IsChecked == true && SystemProxy.IsChecked == true && !tun && environment.VirtualAdapterActive && followSystem)
            {
                if (!IsVisible) ShowMainWindow();
                if (MessageBox.Show(this, "检测到活动虚拟网络。Harbor 只设置系统代理，线路仍可能经过现有虚拟网络。继续连接？", "现有虚拟网络", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) { SetRunning(); return; }
            }
            NetworkEnvironment.EnsureCanCapture(App.Isolated, ProtectExistingProxy.IsChecked == true && tun, SystemProxy.IsChecked == true, tun, environment);
            snapshot = await client.CallAsync("start", new JsonObject { { "config", profile.DeepClone() } }, 60);
            if (SystemProxy.IsChecked == true) guardian = await Recovery.ApplyAsync(S(profile, "listen"), client.Process);
            running = true; lastUp = lastDown = 0; lastSample = DateTime.UtcNow; Chart.Clear();
            RecoveryText.Text = SystemProxy.IsChecked == true ? "原始设置已加密保存。停止连接时自动恢复。" : "本次会话未修改系统代理。";
            GuardianText.Text = guardian != null ? $"独立恢复进程运行中 · PID {guardian.Id}" : ProtectExistingProxy.IsChecked == true ? "共存保护已开启。" : "共存保护已关闭。";
            RecoveryBadge.Text = guardian != null ? "守护中" : "无需恢复";
            SetRunning(); await RefreshAsync();
        }
        catch
        {
            try { Recovery.Restore(Storage.JournalPath); } finally { await client.CallAsync("stop"); running = false; SetRunning(); }
            throw;
        }
    }
    private async Task StopAsync()
    {
        await CancelSubscriptionRefreshAsync();
        await CancelVerificationAsync();
        RunState.Text = guardian == null ? "正在停止…" : "正在恢复网络…";
        var result = Recovery.Restore(Storage.JournalPath); RecoveryText.Text = result.Message;
        // Do not stop the listener if restoration failed: a live proxy is better than a stale dead proxy.
        if (client != null) await client.CallAsync("stop");
        running = false; RecoveryBadge.Text = result.State == "conflict" ? "外部变更" : result.State is "clean" or "isolated" ? "无需恢复" : "已恢复"; GuardianText.Text = result.State is "clean" or "isolated" ? "系统代理保持原状。" : result.State == "conflict" ? "保留其他程序设置的代理。" : "系统代理恢复已完成。";
        if (guardian != null) { if (!guardian.HasExited) guardian.Kill(); guardian.Dispose(); guardian = null; }
        SetRunning();
    }
    private void SetRunning()
    {
        ConnectButton.Content = running ? "停止连接" : SystemProxy.IsChecked == true || profile["tun"]?.GetValue<bool>() == true ? "启动连接" : "启动本地代理"; RunState.Text = running ? "运行中" : "已停止"; SidebarStatus.Text = running ? "引擎运行中" : "引擎未启动";
        StatusDot.Fill = new SolidColorBrush(running ? Color.FromRgb(44, 133, 99) : Color.FromRgb(148, 162, 154)); SystemProxy.IsEnabled = !running && !App.Isolated; TunEnabled.IsEnabled = !running && !App.Isolated;
        SyncHome();
        SyncTray(); if (!running) { DownloadRate.Text = UploadRate.Text = "0 B/s"; ActiveCount.Text = "0"; FooterTraffic.Text = "无网络接管"; }
    }
    private async Task RefreshAsync()
    {
        if (refreshing || client == null || !running || quitting) return; refreshing = true;
        try
        {
            snapshot = await client.CallAsync("snapshot");
            if (snapshot["running"]?.GetValue<bool>() != true) { await StopAsync(); ShowNotice("引擎已停止，系统代理已恢复。"); return; }
            ulong up = N(snapshot, "uploaded"), down = N(snapshot, "downloaded"); double elapsed = Math.Max(0.1, (DateTime.UtcNow - lastSample).TotalSeconds);
            double upload = (up >= lastUp ? up - lastUp : 0) / elapsed, download = (down >= lastDown ? down - lastDown : 0) / elapsed; lastUp = up; lastDown = down; lastSample = DateTime.UtcNow;
            DownloadRate.Text = Format.Bytes(download) + "/s"; UploadRate.Text = Format.Bytes(upload) + "/s"; Chart.Push(download, upload);
            ActiveCount.Text = N(snapshot, "activeConnections").ToString(); TotalCount.Text = $"/ 共 {N(snapshot, "accepted")} 条";
            OverviewSubtitle.Text = $"已运行 {TimeSpan.FromSeconds(N(snapshot, "uptimeSecs")):hh\\:mm\\:ss} · 配置版本 {N(snapshot, "generation")}";
            FooterState.Text = $"引擎 {S(snapshot, "version")} · PID {client.Process.Id}"; FooterTraffic.Text = $"↓ {Format.Bytes(down)}    ↑ {Format.Bytes(up)}";
            var selected = (FlowGrid.SelectedItem as FlowRow)?.Id;
            flows = (snapshot["flows"]?.AsArray() ?? []).Select(f => new FlowRow(N(f!, "id"), S(f!, "destination"), S(f!, "protocol"), S(f!, "outbound"), Format.Bytes(N(f!, "uploaded") + N(f!, "downloaded")), State(S(f!, "state")), S(f!, "reason"), S(f!, "policy"), N(f!, "generation"), S(f!, "error"))).ToList();
            RecentGrid.ItemsSource = flows.Take(5).ToList(); ApplyFlowFilter(); if (selected != null) FlowGrid.SelectedItem = flows.FirstOrDefault(f => f.Id == selected);
            RefreshNodes(); var dns = snapshot["dns"]!; DnsStats.Text = $"缓存 {N(dns, "entries")} 条 · 命中 {N(dns, "hits")} 次 · 上游查询 {N(dns, "misses")} 次 · 拦截 {N(dns, "blocked")} 次 · 错误 {N(dns, "errors")} 次";
            EventGrid.ItemsSource = (snapshot["events"]?.AsArray() ?? []).Select(v => new { Time = DateTimeOffset.FromUnixTimeMilliseconds((long)N(v!, "time")).ToLocalTime().ToString("HH:mm:ss"), Level = S(v!, "level"), Message = S(v!, "message") }).ToList();
            DiagnosticSummary.Text = $"已处理 {N(snapshot, "accepted")} 条连接 · 失败 {N(snapshot, "failed")} 条";
        }
        catch (Exception error) { if (!quitting) ShowNotice(error.Message); }
        finally { refreshing = false; }
    }
    private static string S(JsonNode node, string key) => node[key]?.GetValue<string>() ?? "";
    private static ulong N(JsonNode node, string key)
    {
        if (node[key] is not JsonValue value) return 0;
        return value.TryGetValue<ulong>(out ulong number) ? number : ulong.Parse(value.ToJsonString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture);
    }
    private static string State(string state) => state switch { "active" => "活跃", "connecting" => "连接中", "closed" => "已结束", "failed" => "失败", "healthy" => "正常", "degraded" => "待观察", "unavailable" => "不可用", _ => "未测试" };
    private void SyncProfile()
    {
        syncing = true;
        try
        {
            ProxyAddress.Text = ListenInput.Text = S(profile, "listen"); DnsListenInput.Text = S(profile, "dnsListen"); DnsAddress.Text = "本地解析器：" + S(profile, "dnsListen");
            DnsEncrypted.IsChecked = (profile["dnsTls"] as JsonArray)?.Count > 0;
            DnsTlsServers.Text = profile["dnsTls"] is JsonArray tls && tls.Count > 0 ? string.Join("\n", tls.Select(v => ProfileWorkflow.DnsEndpointText(v!))) : "223.5.5.5:443 dns.alidns.com /dns-query\n1.1.1.1:443 cloudflare-dns.com /dns-query";
            DnsServers.Text = string.Join(", ", profile["dnsServers"]!.AsArray().Select(v => v!.GetValue<string>())); TunEnabled.IsChecked = profile["tun"]?.GetValue<bool>() == true;
            EgressModeInput.SelectedIndex = S(profile, "egressMode") == "system" ? 1 : 0;
            PolicySummary.Text = S(profile, "finalPolicy"); PolicyDetail.Text = PolicySummary.Text == "DIRECT" ? "未命中规则的连接使用直连。" : "未命中规则的连接使用此策略。";
            FinalPolicy.ItemsSource = Policies(); FinalPolicy.SelectedItem = S(profile, "finalPolicy");
            GroupGrid.ItemsSource = profile["groups"]!.AsArray().Select(v => new GroupRow(S(v!, "name"), S(v!, "kind") switch { "select" => "手动选择", "fallback" => "故障切换", _ => "优选低延迟" }, v!["members"]!.AsArray().Count + " 个成员")).ToList();
            RuleGrid.ItemsSource = profile["rules"]!.AsArray().Select((v, i) => new RuleRow(i, ProfileWorkflow.RuleLabel(S(v!, "kind")), S(v!, "value"), S(v!, "policy"), v!["enabled"]?.GetValue<bool>() == false ? "已停用" : "生效")).ToList(); RefreshNodes();
        }
        finally { syncing = false; }
        RefreshSubscriptionGrid(); SyncPrivacy(); SyncHome();
    }
    private string[] Policies() => new[] { "DIRECT", "REJECT" }.Concat(profile["nodes"]!.AsArray().Select(v => S(v!, "name"))).Concat(profile["groups"]!.AsArray().Select(v => S(v!, "name"))).ToArray();
    private void RefreshNodes()
    {
        string? selected = (NodeGrid.SelectedItem as NodeRow)?.Name;
        var nodes = profile["nodes"]?.AsArray() ?? [];
        var history = lineChecks.ForProfile(profile);
        var now = DateTimeOffset.UtcNow;
        var rows = nodes.Select(v =>
        {
            string name = S(v!, "name"); var health = snapshot?["nodes"]?.AsArray().FirstOrDefault(h => S(h!, "name") == name);
            double? latency = health?["latencyMs"]?.GetValue<double>(); string kind = S(v!, "kind");
            string security = kind is "shadowsocks" or "vmess" ? "AEAD" : kind is "https" or "trojan" or "vless" || v!["tls"]?.GetValue<bool>() == true ? kind == "socks5" ? "TLS · 仅 TCP" : "TLS" : "无额外加密";
            var check = history.GetValueOrDefault(name);
            int verificationState = check == null || !check.Fresh(now) ? 2 : check.Success ? 1 : 3;
            return new NodeRow(name, kind == "shadowsocks" ? "SS" : kind.ToUpperInvariant(), security,
                S(v!, "server") + ":" + N(v!, "port"), latency.HasValue ? $"{latency:0} ms" : "—",
                health == null ? "未测试" : State(S(health, "state")), check?.Summary(now) ?? "尚未验证",
                check?.Detail ?? "选择这条线路后，点击验证选中线路。", verificationState, verificationState == 1 ? check!.ElapsedMs : null, name == S(profile, "finalPolicy"));
        });
        string search = NodeSearch?.Text.Trim() ?? ""; int filter = Math.Max(0, NodeFilter?.SelectedIndex ?? 0);
        var visible = rows.Where(row => (search.Length == 0 || $"{row.Name} {row.Kind} {row.Server}".Contains(search, StringComparison.OrdinalIgnoreCase)) && (filter == 0 || row.VerificationState == filter)).ToList();
        if (NodeSort?.SelectedIndex == 1) visible = visible.OrderBy(row => row.VerificationMs ?? ulong.MaxValue).ToList();
        NodeGrid.ItemsSource = visible;
        if (selected != null) NodeGrid.SelectedItem = visible.FirstOrDefault(row => row.Name == selected);
        NodeCount.Text = visible.Count == nodes.Count ? $"{nodes.Count} 条线路 · 验证结果加密保存在本机" : $"显示 {visible.Count} / {nodes.Count} 条线路";
        NodeEmptyTitle.Text = nodes.Count == 0 ? "还没有线路" : "没有匹配的线路";
        NodeEmptyHint.Text = nodes.Count == 0 ? "从订阅或文件导入，也可以手动添加。" : "试试其他关键词，或点击重置筛选。";
        SyncVerificationControls();
    }
    private async Task SaveAsync(JsonObject candidate, List<SubscriptionEntry>? subscriptions = null)
    {
        if (client == null) return; await client.CallAsync("validate", new JsonObject { { "config", candidate.DeepClone() } });
        if (running) await client.CallAsync("configure", new JsonObject { { "config", candidate.DeepClone() } });
        try { Storage.SaveWorkspace(candidate, subscriptions ?? Subscriptions.Read()); } catch { if (running) await client.CallAsync("configure", new JsonObject { { "config", profile.DeepClone() } }); throw; }
        profile = candidate; SyncProfile();
    }
    private void FilterFlows(object sender, TextChangedEventArgs e) { if (FlowGrid != null) ApplyFlowFilter(); }
    private void ApplyFlowFilter() { string text = FlowSearch.Text; FlowGrid.ItemsSource = flows.Where(f => string.IsNullOrWhiteSpace(text) || $"{f.Destination} {f.Outbound} {f.Policy}".Contains(text, StringComparison.OrdinalIgnoreCase)).ToList(); }
    private void FlowSelected(object sender, SelectionChangedEventArgs e) { if (FlowGrid.SelectedItem is FlowRow f) FlowDetail.Text = $"{f.Reason} → {f.Policy} → {f.Outbound}  ·  配置版本 {f.Generation}" + (string.IsNullOrEmpty(f.Error) ? "" : "\n" + f.Error); }
    private async void CloseSelectedFlow(object sender, RoutedEventArgs e) => await Safe(async () => { if (FlowGrid.SelectedItem is FlowRow f && client != null) await client.CallAsync("close_flow", new JsonObject { { "flowId", f.Id } }); });
    private async void AddNode(object sender, RoutedEventArgs e) => await EditNodeAsync(null);
    private async void EditNode(object sender, RoutedEventArgs e) { if (NodeGrid.SelectedItem is NodeRow row) await EditNodeAsync(row.Name); }
    private async Task EditNodeAsync(string? name)
    {
        var node = profile["nodes"]!.AsArray().FirstOrDefault(v => S(v!, "name") == name);
        var form = CreateNodeForm(node);
        if (form.ShowDialog() != true) return;
        await Safe(async () => { var candidate = profile.DeepClone().AsObject(); var nodes = candidate["nodes"]!.AsArray(); int index = name == null ? -1 : nodes.ToList().FindIndex(v => S(v!, "name") == name); var value = node?.DeepClone().AsObject() ?? new JsonObject(); foreach (string field in new[] { "name", "kind", "server", "username", "password", "uuid", "transport", "wsPath", "wsHost", "security", "tlsServerName", "cipher" }) value[field] = form.Get(field); value["port"] = int.Parse(form.Get("port")); value["tls"] = form.Get("tls") == "启用" || form.Get("kind") is "vless" or "trojan" or "https"; if (form.Get("kind") is not ("trojan" or "vless" or "vmess")) value["transport"] = "tcp"; if (index < 0) { nodes.Add(value); ProfileWorkflow.SelectFirstImport(profile, candidate); } else { nodes[index] = value; RenameReferences(candidate, name!, S(value, "name")); } var subscriptions = Subscriptions.Read(); if (name != null && name != S(value, "name")) { for (int i = 0; i < subscriptions.Count; i++) subscriptions[i] = subscriptions[i] with { NodeNames = subscriptions[i].NodeNames.Select(n => n == name ? S(value, "name") : n).ToArray() }; } await SaveAsync(candidate, subscriptions); });
    }
    internal FormDialog CreateNodeForm(JsonNode? node)
    {
        var form = new FormDialog(this, node == null ? "添加节点" : "编辑节点").Field("name", "名称", node == null ? "" : S(node, "name")).Field("kind", "协议", node == null ? "socks5" : S(node, "kind"), ["socks5", "http", "https", "trojan", "shadowsocks", "vless", "vmess"]).Field("server", "服务器", node == null ? "" : S(node, "server")).Field("port", "端口", node == null ? "443" : N(node, "port").ToString()).Field("username", "用户名（HTTP / SOCKS5）", node == null ? "" : S(node, "username")).Field("password", "密码", node == null ? "" : S(node, "password"), secret: true).Field("uuid", "UUID（VLESS / VMess）", node == null ? "" : S(node, "uuid")).Field("tls", "TLS", node != null && node["tls"]?.GetValue<bool>() == true ? "启用" : "关闭", ["启用", "关闭"]).Field("transport", "传输", node == null ? "tcp" : S(node, "transport"), ["tcp", "ws"]).Field("wsPath", "WebSocket 路径", node == null ? "/" : S(node, "wsPath")).Field("wsHost", "WebSocket Host", node == null ? "" : S(node, "wsHost")).Field("security", "VMess 加密", node == null ? "auto" : S(node, "security"), ["auto", "aes-128-gcm", "chacha20-poly1305"]).Field("tlsServerName", "TLS 服务器名（可留空）", node == null ? "" : S(node, "tlsServerName")).Field("cipher", "Shadowsocks 加密", node == null ? "chacha20-ietf-poly1305" : S(node, "cipher"), ["chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"]);
        void RelevantFields() { string kind = form.Get("kind"); bool framed = kind is "vless" or "vmess" or "trojan"; form.Visible("username", kind is "http" or "https" or "socks5"); form.Visible("password", kind is not ("vless" or "vmess")); form.Visible("uuid", kind is "vless" or "vmess"); form.Visible("security", kind == "vmess"); form.Visible("cipher", kind == "shadowsocks"); form.Visible("tls", kind is not ("trojan" or "https" or "vless")); form.Visible("transport", framed); form.Visible("wsPath", framed && form.Get("transport") == "ws"); form.Visible("wsHost", framed && form.Get("transport") == "ws"); form.Visible("tlsServerName", kind is "trojan" or "https" or "vless" || form.Get("tls") == "启用"); }
        form.Changed("kind", RelevantFields); form.Changed("transport", RelevantFields); form.Changed("tls", RelevantFields); RelevantFields();
        return form;
    }
    private async void RemoveNode(object sender, RoutedEventArgs e) { if (NodeGrid.SelectedItem is NodeRow row) await RemoveOutboundAsync(row.Name, false); }
    private async void ImportNodes(object sender, RoutedEventArgs e)
    {
        var dialog = new TextDialog(this, "导入节点", "粘贴分享链接（每行一个）、Clash YAML、SIP008 或 Harbor JSON。订阅地址请从「订阅」页面添加。", "", true).AllowFileImport(); if (dialog.ShowDialog() != true) return;
        await Safe(async () => { var result = ProfileImport.Parse(dialog.Text); if (new ImportPreview(this, result).ShowDialog() != true) return; var candidate = Subscriptions.Merge(profile, result.Nodes, null, "", out _, out _); ProfileWorkflow.SelectFirstImport(profile, candidate); await SaveAsync(candidate); ShowNotice($"已导入 {result.Nodes.Count} 个节点。"); });
    }
    private async void ProbeNodes(object sender, RoutedEventArgs e)
    {
        var button = (Button)sender; button.IsEnabled = false;
        try { if (client == null || !running) throw new InvalidOperationException("请先启动引擎，再测试节点。"); await client.CallAsync("probe", timeoutSeconds: 90); await RefreshAsync(); }
        catch (Exception error) { ShowNotice(error.Message); }
        finally { button.IsEnabled = true; }
    }

    private async void AddGroup(object sender, RoutedEventArgs e) => await EditGroupAsync(null);
    private async void EditGroup(object sender, RoutedEventArgs e) { if (GroupGrid.SelectedItem is GroupRow row) await EditGroupAsync(row.Name); }
    private async Task EditGroupAsync(string? name)
    {
        var existing = profile["groups"]!.AsArray().FirstOrDefault(v => S(v!, "name") == name); var dialog = new GroupDialog(this, profile["nodes"]!.AsArray().Select(v => S(v!, "name")).Concat(new[] { "DIRECT", "REJECT" }), existing); if (dialog.ShowDialog() != true || dialog.Value == null) return;
        await Safe(async () => { var candidate = profile.DeepClone().AsObject(); var groups = candidate["groups"]!.AsArray(); int index = groups.ToList().FindIndex(v => S(v!, "name") == name); if (index < 0) groups.Add(dialog.Value.DeepClone()); else { groups[index] = dialog.Value.DeepClone(); RenameReferences(candidate, name!, S(dialog.Value, "name")); } await SaveAsync(candidate); });
    }
    private async void RemoveGroup(object sender, RoutedEventArgs e) { if (GroupGrid.SelectedItem is GroupRow row) await RemoveOutboundAsync(row.Name, true); }
    private static void RenameReferences(JsonObject candidate, string oldName, string newName)
    {
        if (oldName == newName) return; if (S(candidate, "finalPolicy") == oldName) candidate["finalPolicy"] = newName;
        foreach (var rule in candidate["rules"]!.AsArray()) if (S(rule!, "policy") == oldName) rule!["policy"] = newName;
        foreach (var group in candidate["groups"]!.AsArray()) { var members = group!["members"]!.AsArray(); for (int i = 0; i < members.Count; i++) if (members[i]!.GetValue<string>() == oldName) members[i] = newName; if (S(group, "selected") == oldName) group["selected"] = newName; }
    }
    private async void AddRule(object sender, RoutedEventArgs e) => await EditRuleAsync(null);
    private async void RemoveRule(object sender, RoutedEventArgs e) => await Safe(async () => { if (RuleGrid.SelectedItem is RuleRow row) { var candidate = profile.DeepClone().AsObject(); candidate["rules"]!.AsArray().RemoveAt(row.Index); await SaveAsync(candidate); } });
    private async void MoveRuleUp(object sender, RoutedEventArgs e) => await MoveRule(-1);
    private async void MoveRuleDown(object sender, RoutedEventArgs e) => await MoveRule(1);
    private async Task MoveRule(int delta) => await Safe(async () => { if (RuleGrid.SelectedItem is not RuleRow row) return; var candidate = profile.DeepClone().AsObject(); var rules = candidate["rules"]!.AsArray(); int next = row.Index + delta; if (next < 0 || next >= rules.Count) return; var item = rules[row.Index]!.DeepClone(); rules.RemoveAt(row.Index); rules.Insert(next, item); await SaveAsync(candidate); RuleGrid.SelectedIndex = next; });
    private async void FinalPolicyChanged(object sender, SelectionChangedEventArgs e) { if (syncing || FinalPolicy.SelectedItem is not string value) return; await Safe(async () => { var candidate = profile.DeepClone().AsObject(); candidate["finalPolicy"] = value; await SaveAsync(candidate); }); }
    private async void ExplainRoute(object sender, RoutedEventArgs e) => await Safe(ExplainOfflineAsync);
    private async void SaveDns(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        var candidate = profile.DeepClone().AsObject();
        candidate["dnsServers"] = new JsonArray(DnsServers.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
        candidate["dnsTls"] = DnsEncrypted.IsChecked == true ? ProfileWorkflow.ParseDnsEndpoints(DnsTlsServers.Text, profile["dnsTls"] as JsonArray) : new JsonArray();
        await SaveAsync(candidate); ShowNotice("DNS 配置已保存。");
    });
    private async void ClearDns(object sender, RoutedEventArgs e) => await Safe(async () => { if (client != null) await client.CallAsync("clear_dns"); await RefreshAsync(); });
    private void SavePreferences(object sender, RoutedEventArgs e)
    {
        try { Storage.Write(Storage.PreferencesPath, new DesktopPreferences(!App.Isolated && SystemProxy.IsChecked == true, MinimizeToTray.IsChecked == true, App.Isolated || ProtectExistingProxy.IsChecked == true)); RefreshNetworkState(); SetRunning(); }
        catch (Exception error) { ShowNotice("偏好设置未保存：" + error.Message); }
    }
    private async void SaveSettings(object sender, RoutedEventArgs e) => await Safe(async () => { if (running) throw new InvalidOperationException("修改监听地址、上游网络或 TUN 模式前，请先停止连接。"); var candidate = profile.DeepClone().AsObject(); candidate["listen"] = ListenInput.Text.Trim(); candidate["dnsListen"] = DnsListenInput.Text.Trim(); candidate["tun"] = TunEnabled.IsChecked == true; candidate["egressMode"] = EgressModeInput.SelectedIndex == 1 ? "system" : "physical"; await SaveAsync(candidate); });
    private async void EditProfile(object sender, RoutedEventArgs e)
    {
        var dialog = new TextDialog(this, "完整配置", "保存前会验证所有节点、规则和策略引用。现有连接保留原出口。", profile.ToJsonString(Storage.Json)); if (dialog.ShowDialog() != true) return; await Safe(async () => await SaveAsync(JsonNode.Parse(dialog.Text)?.AsObject() ?? throw new FormatException("无效的 JSON。")));
    }
    private void ExportProfile(object sender, RoutedEventArgs e) { var dialog = new SaveFileDialog { Title = "导出配置 · 文件将包含线路密码，请妥善保存", Filter = "Harbor profile|*.json", FileName = "harbor-profile.json" }; if (dialog.ShowDialog(this) == true) { File.WriteAllText(dialog.FileName, profile.ToJsonString(Storage.Json)); ShowNotice("配置已导出，文件包含节点密码。"); } }
    private void ExportDiagnostics(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter = "JSON diagnostics|*.json", FileName = "harbor-diagnostics-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".json" }; if (dialog.ShowDialog(this) != true) return;
        var report = new JsonObject { { "capturedAt", DateTimeOffset.UtcNow.ToString("O") }, { "application", "Harbor" }, { "version", typeof(MainWindow).Assembly.GetName().Version?.ToString() ?? "unknown" } };
        foreach (var key in new[] { "running", "generation", "uptimeSecs", "activeConnections", "accepted", "failed", "uploaded", "downloaded" }) report[key] = snapshot?[key]?.DeepClone();
        var dns = new JsonObject(); foreach (var key in new[] { "hits", "misses", "errors", "entries", "blocked" }) dns[key] = snapshot?["dns"]?[key]?.DeepClone(); report["dns"] = dns;
        report["configuredNodes"] = profile["nodes"]!.AsArray().Count; report["configuredRules"] = profile["rules"]!.AsArray().Count;
        File.WriteAllText(dialog.FileName, report.ToJsonString(Storage.Json)); ShowNotice("已导出汇总诊断，不包含地址、连接目标、日志正文或凭据。");
    }
    private void CheckRecovery(object sender, RoutedEventArgs e) { try { var lease = Storage.Read<Lease>(Storage.JournalPath); RecoveryText.Text = lease == null ? "没有待恢复的系统代理设置。" : new WindowsProxyStore().Read() == lease.Applied ? "系统代理由当前 Harbor 会话持有，恢复记录完整。" : "系统代理发生外部变更，停止时不会覆盖它。"; } catch (Exception error) { ShowNotice(error.Message); } }
    private async void RecoverNetwork(object sender, RoutedEventArgs e) => await Safe(async () => { if (running) await StopAsync(); else ShowNotice(Recovery.Restore(Storage.JournalPath, true).Message); });
    private async void RestartElevated(object sender, RoutedEventArgs e)
    {
        if (App.Isolated) { ShowNotice("隔离模式不能申请网络接管权限。"); return; }
        bool launched = false; await Safe(async () => { if (running) await StopAsync(); using var current = Process.GetCurrentProcess(); var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" }; start.ArgumentList.Add("--after-exit"); start.ArgumentList.Add(current.Id.ToString()); start.ArgumentList.Add(current.StartTime.ToUniversalTime().Ticks.ToString()); start.ArgumentList.Add(Storage.Root); Process.Start(start); launched = true; });
        if (launched) { quitting = true; Close(); }
    }
    private async void WindowClosing(object? sender, CancelEventArgs e)
    {
        if (client == null) { DisposeTray(); Application.Current.Shutdown(); return; }
        if (!quitting && MinimizeToTray.IsChecked == true) { e.Cancel = true; Hide(); return; }
        e.Cancel = true; if (busy) return; busy = true; quitting = true; timer.Stop();
        try { await CancelSubscriptionRefreshAsync(); await CancelVerificationAsync(); if (running) await StopAsync(); await client.DisposeAsync(); client = null; DisposeTray(); Application.Current.Shutdown(); }
        catch (Exception error) { quitting = false; busy = false; timer.Start(); ShowNotice("退出已暂停：" + error.Message); Show(); }
    }
    private sealed record FlowRow(ulong Id, string Destination, string Protocol, string Outbound, string Traffic, string State, string Reason, string Policy, ulong Generation, string Error)
    {
        public string Failure => State == "失败" ? ConnectionFailure.Describe(Error) : "—";
    }
    private sealed record NodeRow(string Name, string Kind, string Security, string Server, string Latency, string State, string Verification, string VerificationDetail, int VerificationState, ulong? VerificationMs, bool IsDefault);
    private sealed record GroupRow(string Name, string Kind, string Members);
    private sealed record RuleRow(int Index, string Kind, string Value, string Policy, string State);
}
