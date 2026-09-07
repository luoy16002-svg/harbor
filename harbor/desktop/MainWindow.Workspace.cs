using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;
public partial class MainWindow
{
    private void MinimizeWindow(object sender, RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);
    private void MaximizeWindow(object sender, RoutedEventArgs e) { if (WindowState == WindowState.Maximized) SystemCommands.RestoreWindow(this); else SystemCommands.MaximizeWindow(this); }
    private void CloseWindow(object sender, RoutedEventArgs e) => Close();
    private void WindowSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (OverviewRail == null) return; bool compact = ActualWidth < 1120;
        OverviewRail.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        OverviewRailWidth.Width = new GridLength(compact ? 0 : 248); OverviewGap.Width = new GridLength(compact ? 0 : 18);
        if (Content is FrameworkElement frame) frame.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
    }
    private void RefreshNetwork(object sender, RoutedEventArgs e) { try { RefreshNetworkState(); } catch (Exception error) { ShowNotice(error.Message); } }
    private void RefreshNetworkState()
    {
        var state = NetworkEnvironment.Read(); AdapterGrid.ItemsSource = state.Adapters;
        NetworkSummary.Text = state.ProxyMode + (state.VirtualAdapterActive ? " · 检测到活动虚拟网络" : "");
        NetworkProtection.Text = App.Isolated ? "隔离模式已锁定：Harbor 无法接管系统代理或 TUN。" : ProtectExistingProxy.IsChecked == true ? "切换已有系统代理前询问；TUN 与现有虚拟网络冲突时阻止启动。" : "共存保护已关闭。网络接管取决于你在设置中的选择。";
        SyncHome();
    }
    private static JsonObject PrivacyDefaults(JsonObject value) => value["privacy"]?.DeepClone().AsObject() ?? new JsonObject { ["blockDirect"] = false, ["requireEncryptedProxy"] = false, ["hideMetadata"] = false, ["historySecs"] = 300, ["blockedDomains"] = new JsonArray(), ["allowedDomains"] = new JsonArray() };
    private void SyncPrivacy()
    {
        var settings = PrivacyDefaults(profile);
        BlockDirect.IsChecked = settings["blockDirect"]?.GetValue<bool>() == true;
        RequireEncryption.IsChecked = settings["requireEncryptedProxy"]?.GetValue<bool>() == true;
        HideMetadata.IsChecked = settings["hideMetadata"]?.GetValue<bool>() == true;
        HistorySeconds.Text = (settings["historySecs"]?.GetValue<int>() ?? 300).ToString();
        BlockedDomains.Text = string.Join("\n", (settings["blockedDomains"] as JsonArray ?? []).Select(v => v!.GetValue<string>()));
        AllowedDomains.Text = string.Join("\n", (settings["allowedDomains"] as JsonArray ?? []).Select(v => v!.GetValue<string>()));
        int blocked = (settings["blockedDomains"] as JsonArray)?.Count ?? 0, allowed = (settings["allowedDomains"] as JsonArray)?.Count ?? 0;
        BlockRuleCount.Text = $"{blocked:N0} 个拦截域名 · {allowed:N0} 个例外";
        PrivacyOverview.LineHeight = 22;
        PrivacyOverview.Text = ((profile["dnsTls"] as JsonArray)?.Count > 0 ? ((profile["dnsTls"] as JsonArray)?.Any(v => v?["httpsPath"] != null) == true ? "DNS over HTTPS 已配置" : "DNS over TLS 已配置") : "DNS 使用明文上游") + $"\n本地拦截域名：{blocked:N0}\n" + (HideMetadata.IsChecked == true ? "连接明细已隐藏" : $"已结束记录保留 {HistorySeconds.Text} 秒") + (BlockDirect.IsChecked == true ? "\n非回环直连已禁止" : "");
    }
    private async void SavePrivacy(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        var blocked = BlockRules.Parse(BlockedDomains.Text); var allowed = BlockRules.Parse(AllowedDomains.Text);
        if (blocked.Unsupported + allowed.Unsupported > 0) throw new FormatException("文本中有无法识别的规则，请使用纯域名或从规则导入入口查看支持情况。");
        if (!int.TryParse(HistorySeconds.Text, out int history) || history is < 0 or > 86400) throw new FormatException("保留时间应为 0–86400 秒。");
        var candidate = profile.DeepClone().AsObject(); var settings = PrivacyDefaults(candidate);
        settings["blockDirect"] = BlockDirect.IsChecked == true; settings["requireEncryptedProxy"] = RequireEncryption.IsChecked == true;
        settings["hideMetadata"] = HideMetadata.IsChecked == true; settings["historySecs"] = history;
        JsonArray Strings(System.Collections.Generic.IEnumerable<string> values) => new(values.Distinct(StringComparer.OrdinalIgnoreCase).Order().Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
        settings["blockedDomains"] = Strings(blocked.Blocked); settings["allowedDomains"] = Strings(allowed.Blocked.Concat(allowed.Allowed).Concat(blocked.Allowed));
        var previous = PrivacyDefaults(profile);
        if (running && new[] { "blockDirect", "requireEncryptedProxy", "blockedDomains", "allowedDomains" }.Any(key => !JsonNode.DeepEquals(previous[key], settings[key]))) throw new InvalidOperationException("请先停止 Harbor，再修改拦截域名或传输限制，以免已有连接保留旧规则。");
        candidate["privacy"] = settings; await SaveAsync(candidate);
        if (HideMetadata.IsChecked == true) { flows.Clear(); RecentGrid.ItemsSource = null; FlowGrid.ItemsSource = null; EventGrid.ItemsSource = null; FlowDetail.Text = ""; }
        await RefreshAsync(); ShowNotice("隐私设置已保存。");
    });
    private void ImportBlockRules(object sender, RoutedEventArgs e)
    {
        var dialog = new TextDialog(this, "导入本地反追踪规则", "支持域名列表、hosts、||域名^ 与 @@||域名^。页面元素、URL 路径和脚本规则不适用于网络层。", "", true).AllowFileImport();
        if (dialog.ShowDialog() != true) return;
        try
        {
            var result = BlockRules.Parse(dialog.Text); var oldBlocked = BlockRules.Parse(BlockedDomains.Text); var oldAllowed = BlockRules.Parse(AllowedDomains.Text);
            BlockedDomains.Text = string.Join("\n", oldBlocked.Blocked.Concat(result.Blocked).Distinct().Order());
            AllowedDomains.Text = string.Join("\n", oldAllowed.Blocked.Concat(oldAllowed.Allowed).Concat(result.Allowed).Distinct().Order());
            ShowNotice($"已载入 {result.Blocked.Length} 个拦截域名、{result.Allowed.Length} 个例外；{result.Unsupported} 行不支持。点击保存后生效。");
        }
        catch (Exception error) { ShowNotice(error.Message); }
    }
    private async void ClearHistory(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (running && client != null) { await client.CallAsync("clear_history"); await RefreshAsync(); }
        else { flows.Clear(); RecentGrid.ItemsSource = null; FlowGrid.ItemsSource = null; EventGrid.ItemsSource = null; }
        FlowDetail.Text = ""; ShowNotice("已清空结束的连接记录与事件明细。");
    });
    private static JsonArray RouteTargets(string text)
    {
        var targets = new JsonArray();
        foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries); string protocol = parts.Length == 2 ? parts[1].ToLowerInvariant() : "tcp";
            if (parts.Length > 2 || protocol is not ("tcp" or "udp") || !Uri.TryCreate("https://" + parts[0], UriKind.Absolute, out var uri) || uri.UserInfo.Length > 0 || uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0) throw new FormatException("每行填写：域名或 IP:端口 tcp/udp。IPv6 地址请加方括号。");
            targets.Add(new JsonObject { ["host"] = uri.IdnHost.Trim('[', ']'), ["port"] = uri.Port, ["protocol"] = protocol });
        }
        if (targets.Count is < 1 or > 256) throw new FormatException("每次支持 1–256 个预演目标。"); return targets;
    }
    private async void RehearseRoutes(object sender, RoutedEventArgs e)
    {
        string[] keys = ["finalPolicy", "rules", "groups", "privacy"];
        var draft = new JsonObject(); foreach (string key in keys) draft[key] = key == "privacy" ? PrivacyDefaults(profile) : profile[key]?.DeepClone();
        var editor = new TextDialog(this, "候选分流 · 仅用于预演", "编辑最终策略、规则、策略组或隐私限制，再比较出口变化。预演不保存配置、不发送网络请求。", draft.ToJsonString(Storage.Json));
        if (editor.ShowDialog() != true) return;
        await Safe(async () =>
        {
            if (client == null) return;
            var changes = JsonNode.Parse(editor.Text)?.AsObject() ?? throw new FormatException("候选配置不是 JSON 对象。");
            if (changes.Any(change => !keys.Contains(change.Key))) throw new FormatException("预演编辑器只接受 finalPolicy、rules、groups 和 privacy。");
            var candidate = profile.DeepClone().AsObject(); foreach (var change in changes) candidate[change.Key] = change.Value?.DeepClone();
            var result = await client.CallAsync("rehearse", new JsonObject { ["before"] = profile.DeepClone(), ["after"] = candidate, ["targets"] = RouteTargets(RehearsalTargets.Text) });
            var rows = result["rows"]!.AsArray().Select(row => new { Target = S(row!["target"]!, "host") + ":" + N(row["target"]!, "port") + " · " + S(row["target"]!, "protocol"), Before = S(row["before"]!, "outbound"), After = S(row["after"]!, "outbound"), Status = row["changed"]!.GetValue<bool>() ? "路径有变化" : "不变", Reason = S(row["after"]!, "reason") }).ToList();
            RehearsalGrid.ItemsSource = rows; RehearsalSummary.Text = $"已离线比较 {rows.Count} 个目标，{rows.Count(row => row.Status != "不变")} 项变化。网络请求 0 次，候选配置未应用。";
        });
    }
    private async Task ExplainOfflineAsync()
    {
        if (client == null) return;
        var result = await client.CallAsync("rehearse", new JsonObject { ["before"] = profile.DeepClone(), ["after"] = profile.DeepClone(), ["targets"] = RouteTargets(ExplainInput.Text) });
        var decision = result["rows"]![0]!["after"]!; ExplainResult.Text = $"{S(decision, "reason")} → {S(decision, "policy")} → {S(decision, "outbound")} · 离线预演，未测量节点健康";
    }
}
