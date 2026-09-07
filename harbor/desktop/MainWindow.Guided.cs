using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    private void SyncHome()
    {
        if (HomePolicy == null) return;
        bool previous = syncing; syncing = true;
        try
        {
            int count = (profile["nodes"] as JsonArray)?.Count ?? 0;
            HomePolicy.ItemsSource = Policies(); HomePolicy.SelectedItem = S(profile, "finalPolicy");
            HomePolicy.IsEnabled = count > 0;
            string? previewPolicy = RehearsalPolicy.SelectedItem as string;
            var choices = Policies(); RehearsalPolicy.ItemsSource = choices;
            RehearsalPolicy.SelectedItem = choices.Contains(previewPolicy) ? previewPolicy : S(profile, "finalPolicy");
            HomeMode.SelectedIndex = App.Isolated ? 1 : profile["tun"]?.GetValue<bool>() == true ? 2 : SystemProxy.IsChecked == true ? 0 : 1;
            HomeMode.IsEnabled = !running && !App.Isolated;
            ModeLabel.Text = App.Isolated ? "隔离测试" : HomeMode.SelectedIndex switch { 0 => "系统代理", 2 => "增强模式 · TUN", _ => "应用代理" };
            HomeTitle.Text = running ? "连接已开启" : count == 0 ? "从第一条线路开始" : "准备就绪";
            HomeDescription.Text = count == 0 ? "粘贴订阅地址或分享链接，Harbor 会自动选中首条线路。" : running ? "切换线路只影响新连接，已建立的连接保留原出口。" : $"已添加 {count} 条线路。选择出口后，点击右上角连接。";
            HomeDescription.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
            HeroStatusRow.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
            ModeDescription.Text = HomeMode.SelectedIndex switch
            {
                0 => "浏览器等遵循 Windows 系统代理的应用将使用 Harbor；断开后还原原设置。",
                2 => "通过虚拟网卡接入 TCP / UDP，需要管理员权限。实验功能，当前版本尚未完成真实网络稳定性验证。",
                _ => App.Isolated ? "测试工作区只允许回环监听，系统代理、DNS 和路由写入已锁定。" : "仅指定代理地址的应用使用 Harbor，适合手动分应用配置。"
            };
            OnboardingSteps.Text = count == 0 ? "① 添加线路     →     ② 选择出口     →     ③ 连接" : $"✓ {count} 条线路     →     {S(profile, "finalPolicy")}     →     {(running ? "已连接" : "待连接")}";
            HomeAdd.Content = count == 0 ? "添加线路" : "添加更多";
            ConnectButton.Content = running ? "断开" : count == 0 ? "添加线路" : "连接";
            HomeVerify.IsEnabled = !busy && !verifying && profile["nodes"]!.AsArray().Any(v => S(v!, "name") == S(profile, "finalPolicy"));
            var lastCheck = lineChecks.Get(profile, S(profile, "finalPolicy"));
            HomeCheckResult.Text = lastCheck?.Summary(DateTimeOffset.UtcNow) ?? "尚未验证";
            HomeCheckResult.ToolTip = lastCheck?.Detail;
            if (verifying) HomeCheckResult.Text = "线路验证进行中 · 可在线路页查看进度";
            SyncVerificationControls();
            SyncSubscriptionControls();
            DnsProvider.SelectedItem = ProfileWorkflow.DnsPreset(profile);
            ClearDnsButton.IsEnabled = running;
            SyncTray();
            if (!running) OverviewSubtitle.Text = "选择线路、查看流量，以及管理应用的网络路径。";
        }
        finally { syncing = previous; }
    }

    private async void HomePolicyChanged(object sender, SelectionChangedEventArgs e)
    {
        if (syncing || HomePolicy.SelectedItem is not string value) return;
        await Safe(async () => { var candidate = profile.DeepClone().AsObject(); candidate["finalPolicy"] = value; await SaveAsync(candidate); });
        SyncHome();
    }

    private async void HomeModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (syncing || HomeMode == null || client == null) return;
        int index = HomeMode.SelectedIndex;
        await Safe(async () =>
        {
            if (running || App.Isolated) throw new InvalidOperationException("请断开连接后切换模式。");
            if (index == 2)
            {
                Navigate(NavSettings, new RoutedEventArgs());
                ShowNotice("增强模式需要管理员权限。请在高级网络设置中启用 TUN，保存后再连接。");
                return;
            }
            var candidate = profile.DeepClone().AsObject(); candidate["tun"] = false; await SaveAsync(candidate);
            SystemProxy.IsChecked = index == 0; SavePreferences(this, new RoutedEventArgs());
        });
        SyncHome();
    }

    private async void AddLines(object sender, RoutedEventArgs e)
    {
        var dialog = new TextDialog(this, "添加线路", "粘贴 HTTPS 订阅地址，或一个 / 多个分享链接。也可以读取本地订阅文件。", "", true).AllowFileImport();
        if (dialog.ShowDialog() != true) return;
        await Safe(async () => await ImportTextAsync(dialog.Text));
    }

    internal async Task ImportTextAsync(string text, bool showPreview = true)
    {
        text = text.Trim();
        // An HTTPS line containing user information is a proxy share link, not a subscription.
        bool subscription = !text.Any(char.IsWhiteSpace) && Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;
        var entries = Subscriptions.Read();
        if (subscription && entries.Any(entry => entry.Url == text)) throw new FormatException("该订阅已存在，可在线路页面更新。");
        var download = subscription ? await Subscriptions.FetchAsync(text, running ? S(profile, "listen") : null) : null;
        var result = ProfileImport.Parse(download?.Text ?? text);
        if (result.Nodes.Count == 0) throw new FormatException("没有可导入的线路。请检查链接或使用支持的协议。");
        if (showPreview && new ImportPreview(this, result).ShowDialog() != true) return;
        string name = "订阅 " + (entries.Count + 1); while (entries.Any(entry => entry.Name == name)) name += " ·";
        var candidate = Subscriptions.Merge(profile, result.Nodes, null, subscription ? name + " · " : "", out var names, out _);
        bool selected = ProfileWorkflow.SelectFirstImport(profile, candidate);
        if (subscription && download != null) entries.Add(new SubscriptionEntry(Guid.NewGuid().ToString("N"), name, text, names, DateTimeOffset.UtcNow, download.Etag, download.LastModified, download.Digest, result.Issues.Count, download.Usage));
        await SaveAsync(candidate, entries);
        ShowNotice($"已导入 {names.Length} 条线路。" + (selected ? "首条线路已选中，可以验证后连接。" : "当前出口保持不变。"));
    }

    private async void UseSelectedNode(object sender, RoutedEventArgs e)
    {
        await Safe(async () => { if (NodeGrid.SelectedItem is not NodeRow row) return; var candidate = profile.DeepClone().AsObject(); candidate["finalPolicy"] = row.Name; await SaveAsync(candidate); });
    }

    private async void ApplyDnsProvider(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (DnsProvider.SelectedItem is not string preset || preset == "自定义") { DnsAdvanced.IsExpanded = true; return; }
        var candidate = profile.DeepClone().AsObject(); ProfileWorkflow.ApplyDnsPreset(candidate, preset); await SaveAsync(candidate);
        ShowNotice("DNS 服务已保存，仅作用于经过 Harbor 解析器的请求。加密连接失败时不会回退到明文 DNS。");
    });

    private async void CompareExit(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (client == null || RehearsalPolicy.SelectedItem is not string policy) return;
        var candidate = profile.DeepClone().AsObject(); candidate["finalPolicy"] = policy;
        await CompareRoutesAsync(candidate);
    });

    private async Task CompareRoutesAsync(JsonObject candidate)
    {
        if (client == null) return;
        var result = await client.CallAsync("rehearse", new JsonObject { ["before"] = profile.DeepClone(), ["after"] = candidate, ["targets"] = RouteTargets(RehearsalTargets.Text) });
        var rows = result["rows"]!.AsArray().Select(row => new { Target = S(row!["target"]!, "host") + ":" + N(row["target"]!, "port") + " · " + S(row["target"]!, "protocol"), Before = S(row["before"]!, "outbound"), After = S(row["after"]!, "outbound"), Status = row["changed"]!.GetValue<bool>() ? "路径有变化" : "不变", Reason = S(row["after"]!, "reason") }).ToList();
        RehearsalGrid.ItemsSource = rows; RehearsalSummary.Text = $"{rows.Count} 个目标 · {rows.Count(row => row.Status != "不变")} 项变化 · 仅预览，未修改当前分流";
    }

    private async void EditRule(object sender, RoutedEventArgs e) { if (RuleGrid.SelectedItem is RuleRow row) await EditRuleAsync(row.Index); }
    private async Task EditRuleAsync(int? index)
    {
        var rule = index.HasValue ? profile["rules"]![index.Value] : null;
        var form = new FormDialog(this, index.HasValue ? "编辑分流规则" : "添加分流规则")
            .Field("kind", "匹配方式", ProfileWorkflow.RuleLabel(rule == null ? "domain_suffix" : S(rule, "kind")), ProfileWorkflow.RuleKinds.Select(v => v.Label).ToArray())
            .Field("value", "匹配内容（例如 example.com、443 或 tcp）", rule == null ? "" : S(rule, "value"))
            .Field("policy", "使用出口", rule == null ? S(profile, "finalPolicy") : S(rule, "policy"), Policies());
        if (form.ShowDialog() != true) return;
        await Safe(async () =>
        {
            var candidate = profile.DeepClone().AsObject(); var value = new JsonObject { ["kind"] = ProfileWorkflow.RuleKey(form.Get("kind")), ["value"] = form.Get("value").Trim(), ["policy"] = form.Get("policy"), ["enabled"] = rule?["enabled"]?.GetValue<bool>() ?? true };
            if (index.HasValue) candidate["rules"]![index.Value] = value; else candidate["rules"]!.AsArray().Add(value);
            await SaveAsync(candidate);
        });
    }

    private async void ToggleRule(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (RuleGrid.SelectedItem is not RuleRow row) return;
        var candidate = profile.DeepClone().AsObject(); var rule = candidate["rules"]![row.Index]!;
        rule["enabled"] = !(rule["enabled"]?.GetValue<bool>() ?? true); await SaveAsync(candidate); RuleGrid.SelectedIndex = row.Index;
    });

    private async Task RemoveOutboundAsync(string name, bool group)
    {
        bool referenced = S(profile, "finalPolicy") == name || profile["rules"]!.AsArray().Any(v => S(v!, "policy") == name) ||
            profile["groups"]!.AsArray().Any(v => v!["members"]!.AsArray().Any(m => m!.GetValue<string>() == name));
        string? replacement = null;
        if (referenced)
        {
            var choices = profile["nodes"]!.AsArray().Select(v => S(v!, "name")).Where(value => value != name).Concat(new[] { "REJECT", "DIRECT" }).ToArray();
            var form = new FormDialog(this, "移除 " + name).Field("replacement", "该出口正在被分流引用。移除后改用：", choices[0], choices);
            if (form.ShowDialog() != true) return;
            replacement = form.Get("replacement");
        }
        await Safe(async () =>
        {
            var candidate = profile.DeepClone().AsObject();
            if (replacement != null)
            {
                RenameReferences(candidate, name, replacement);
                foreach (var item in candidate["groups"]!.AsArray()) item!["members"] = new JsonArray(item["members"]!.AsArray().Select(v => v!.GetValue<string>()).Distinct().Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
            }
            var items = candidate[group ? "groups" : "nodes"]!.AsArray(); items.Remove(items.First(v => S(v!, "name") == name));
            var subscriptions = Subscriptions.Read();
            if (!group) for (int i = 0; i < subscriptions.Count; i++) subscriptions[i] = subscriptions[i] with { NodeNames = subscriptions[i].NodeNames.Where(value => value != name).ToArray() };
            await SaveAsync(candidate, subscriptions);
        });
    }
}
