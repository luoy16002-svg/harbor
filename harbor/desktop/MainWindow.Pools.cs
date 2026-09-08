using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    private sealed record PoolMemberRow(string Name, string Protocol, string State, string Tint, string Latency, string Checked, string Detail, double?[] Samples);
    private bool syncingPools;
    private string? poolRowsSignature;
    private JsonNode? SelectedPool => (profile["groups"] as JsonArray ?? []).FirstOrDefault(g => g?["pool"] != null && S(g, "name") == (PoolChoice.SelectedItem as string));
    private void SyncPools()
    {
        if (PoolChoice == null || syncingPools) return;
        syncingPools = true;
        try
        {
            var names = (profile["groups"] as JsonArray ?? []).Where(g => g?["pool"] != null).Select(g => S(g!, "name")).ToArray();
            string? previous = PoolChoice.SelectedItem as string;
            if (PoolChoice.ItemsSource is not string[] before || !before.SequenceEqual(names)) PoolChoice.ItemsSource = names;
            PoolChoice.SelectedItem = names.Contains(previous) ? previous : names.FirstOrDefault();
            PoolEmpty.Visibility = names.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            PoolWorkspace.Visibility = names.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
            PoolCount.Text = $"{names.Length} / 8 个线路池 · 可用作默认出口，也可分配给应用或网站";
        }
        finally { syncingPools = false; }
        RefreshPoolState();
    }
    private void PoolSelectionChanged(object sender, SelectionChangedEventArgs e) { if (!syncingPools) RefreshPoolState(); }
    private void RefreshPoolState()
    {
        if (PoolChoice == null || SelectedPool is not { } group) return;
        string name = S(group, "name"); var options = PoolOptions.Read(group["pool"]);
        var live = running ? (snapshot?["pools"] as JsonArray ?? []).FirstOrDefault(p => S(p!, "name") == name) : null;
        var health = live?["members"] as JsonArray ?? [];
        var previous = (PoolMemberGrid.SelectedItem as PoolMemberRow)?.Name;
        var rows = group["members"]!.AsArray().Select(member =>
        {
            string nodeName = member!.GetValue<string>(); var h = health.FirstOrDefault(v => S(v!, "name") == nodeName);
            var node = (profile["nodes"] as JsonArray ?? []).FirstOrDefault(v => S(v!, "name") == nodeName);
            string state = !running ? "启动后检查" : !options.Monitor ? "监测已暂停" : h?["checking"]?.GetValue<bool>() == true ? "检查中" :
                h?["coolingDown"]?.GetValue<bool>() == true ? "建连冷却" : h?["checkedAt"] == null ? "等待检查" : h["fresh"]?.GetValue<bool>() != true ? "结果已过期" :
                S(h, "state") switch { "healthy" => "HTTPS 可用", "degraded" => "失败待复核", "unavailable" => "HTTPS 不可用", "blocked" => "检查被保护规则拦截", _ => "等待检查" };
            string tint = state == "HTTPS 可用" ? "#2F8060" : state is "HTTPS 不可用" or "建连冷却" ? "#A35441" : "#65776D";
            double? latency = h?["latencyMs"]?.GetValue<double>();
            string checkedAt = h?["checkedAt"] != null ? DateTimeOffset.FromUnixTimeMilliseconds((long)N(h, "checkedAt")).ToLocalTime().ToString("HH:mm:ss") : "—";
            string category = h?["errorCategory"]?.GetValue<string>() ?? "";
            string detail = category switch { "policy" => "检查地址被本地保护规则拦截；不能据此判定线路故障。", "proxy" => "代理连接、认证或 DNS 未通过。", "tls" => "目标 TLS 或证书验证未通过。", "http" => "未收到有效的 HTTP 200–399 响应。", "timeout" => "HTTPS 检查超时。", _ => "绿色柱为成功请求耗时，红点为失败；保留最近 20 次检查。" };
            if (h != null) detail += $" 检查 {N(h, "checks")} 次，连续失败 {N(h, "consecutiveFailures")} 次。";
            return new PoolMemberRow(nodeName, node == null ? "—" : S(node, "kind").ToUpperInvariant(), state, tint,
                latency.HasValue ? $"{latency:0} ms" : "—", checkedAt, detail, (h?["samples"] as JsonArray ?? []).Select(v => v?.GetValue<double>()).ToArray());
        }).ToList();
        string signature = JsonSerializer.Serialize(rows);
        if (signature != poolRowsSignature) { poolRowsSignature = signature; PoolMemberGrid.ItemsSource = rows; if (previous != null) PoolMemberGrid.SelectedItem = rows.FirstOrDefault(r => r.Name == previous); }
        int healthy = health.Count(h => h?["fresh"]?.GetValue<bool>() == true && S(h, "state") == "healthy");
        PoolHealthCount.Text = running && options.Monitor ? $"{healthy} / {rows.Count}" : $"— / {rows.Count}";
        PoolMonitorState.Text = !running ? "引擎停止 · 监测未运行" : !options.Monitor ? "自动检查已暂停" : $"HTTPS 可用 · 每 {options.CheckIntervalSecs} 秒检查";
        var stats = live?["stats"];
        PoolRecovered.Text = stats == null ? "0" : N(stats, "recovered").ToString();
        PoolRecoveryDetail.Text = stats == null ? "本次运行，建连失败后接通的连接" : $"{N(stats, "connections")} 条连接 · {N(stats, "attempts")} 次尝试 · {N(stats, "failed")} 条未接通";
        bool hidden = profile["privacy"]?["hideMetadata"]?.GetValue<bool>() == true;
        PoolLastOutbound.Text = hidden ? "已隐藏" : stats?["lastOutbound"]?.GetValue<string>() ?? (profile["privacy"]?["historySecs"]?.GetValue<int>() == 0 ? "不保留记录" : "尚无近期记录");
        PoolLastRecovery.Text = !hidden && stats?["lastRecoveryAt"] != null ? "上次恢复 " + DateTimeOffset.FromUnixTimeMilliseconds((long)N(stats, "lastRecoveryAt")).ToLocalTime().ToString("HH:mm:ss") : "最近接通的实际出口";
        PoolToggle.Content = options.Monitor ? "暂停监测" : "恢复监测"; PoolCheck.IsEnabled = running && options.Monitor && !busy;
        PoolUseDefault.IsEnabled = S(profile, "finalPolicy") != name;
        PoolUseDefault.Content = S(profile, "finalPolicy") == name ? "已为默认出口" : "设为默认出口";
        PoolFacts.Text = (S(group, "kind") == "latency" ? "低延迟优先" : "稳定优先") + $" · 建连最多 {options.ConnectAttempts} 次 · 总超时 {N(profile, "connectTimeoutMs")} ms\n" +
            "HTTPS 结果仅用于判断 TCP 路径；每次选线仍检查传输支持和保护要求。已有连接保持原出口。";
    }
    private async void AddPool(object sender, RoutedEventArgs e) => await EditPoolAsync(null);
    private async void EditPool(object sender, RoutedEventArgs e) { if (SelectedPool is { } group) await EditPoolAsync(S(group, "name")); }
    private async Task EditPoolAsync(string? name)
    {
        if ((profile["nodes"] as JsonArray)?.Count is not > 0) { Navigate(new Button { Tag = "Nodes" }, new RoutedEventArgs()); ShowNotice("先导入或添加线路，再选择主线和备线。"); return; }
        var existing = (profile["groups"] as JsonArray ?? []).FirstOrDefault(g => S(g!, "name") == name);
        var dialog = new PoolDialog(this, profile, existing, lineChecks.ForProfile(profile));
        if (dialog.ShowDialog() != true || dialog.Result == null) return;
        await Safe(async () => { await SavePoolAsync(name, dialog.Result); ShowNotice("线路池已保存。" + (running ? "新连接使用更新后的成员；后台监测已按设置调整。" : "启动后按设置自动监测。")); });
    }
    private async Task SavePoolAsync(string? previous, JsonObject value)
    {
        var candidate = profile.DeepClone().AsObject(); var groups = candidate["groups"]!.AsArray(); int index = groups.ToList().FindIndex(g => S(g!, "name") == previous);
        if (index < 0) groups.Add(value.DeepClone()); else { groups[index] = value.DeepClone(); RenameReferences(candidate, previous!, S(value, "name")); }
        ProxyPools.Validate(candidate); await SaveAsync(candidate); PoolChoice.SelectedItem = S(value, "name");
    }
    private async void TogglePoolMonitor(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (SelectedPool is not { } group) return; var value = group.DeepClone().AsObject(); var options = PoolOptions.Read(value["pool"]); value["pool"] = (options with { Monitor = !options.Monitor }).ToJson(); await SavePoolAsync(S(group, "name"), value);
    });
    private async void CheckPoolNow(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (!running || client == null || SelectedPool is not { } group) return;
        await client.CallAsync("pool_check", new JsonObject { ["name"] = S(group, "name") }); await RefreshAsync(); ShowNotice("已安排 HTTPS 检查，同时检查最多两条线路；正在检查或刚完成的请求会合并。");
    });
    private async void UsePoolDefault(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (SelectedPool is not { } group) return; var candidate = profile.DeepClone().AsObject(); candidate["finalPolicy"] = S(group, "name"); await SaveAsync(candidate);
        ShowNotice(ProfileWorkflow.RoutingMode(profile) == "direct" ? "已保存默认线路池。当前为直连模式，切换到规则或全局模式后使用。" : "默认出口已设为线路池；已有连接保持原出口。");
    });
    private async void RemovePool(object sender, RoutedEventArgs e) { if (SelectedPool is { } group) await RemoveOutboundAsync(S(group, "name"), true); }
    private void PoolMemberSelected(object sender, SelectionChangedEventArgs e) { PoolMemberDetail.Text = PoolMemberGrid.SelectedItem is PoolMemberRow row ? row.Name + " · " + row.Detail : "选择成员查看最近一次检查结果。"; }
    private string AttemptDetails(ulong id)
    {
        var flow = (snapshot?["flows"] as JsonArray ?? []).FirstOrDefault(f => N(f!, "id") == id);
        var attempts = flow?["attempts"] as JsonArray ?? [];
        return attempts.Count == 0 ? "" : "\n建连记录：" + string.Join(" → ", attempts.Select(a => S(a!, "outbound") + "（" + (S(a!, "state") switch { "connected" => "已接通", "failed" => "未接通", _ => "连接中" }) + $"，{N(a!, "elapsedMs")} ms）"));
    }
}
