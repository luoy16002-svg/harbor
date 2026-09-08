using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    private sealed record TrafficRouteRow(int Index, string Name, string State, string ToggleText, string Sources, string SourceDetail, string Exit, string Protection, string Facts, string Advice);
    private void SyncTrafficRoutes()
    {
        if (TrafficRouteCards == null) return;
        var routes = TrafficRoutes.Read(profile);
        var rows = routes.Select((route, index) => new TrafficRouteRow(index, route.Name,
            route.Enabled ? "已启用" : "已停用", route.Enabled ? "停用" : "启用", string.Join("、", route.Processes.Concat(route.Domains).Take(3)) + (route.Processes.Length + route.Domains.Length > 3 ? " …" : ""),
            string.Join("\n", route.Processes.Concat(route.Domains)), TrafficRoutes.PolicyLabel(profile, route.Policy),
            route.RequireEncryptedProxy ? "必须使用加密代理\n不满足即拦截" : "使用全局保护设置",
            TrafficRoutes.OutboundFacts(profile, route.Policy ?? S(profile, "finalPolicy"), route.RequireEncryptedProxy), TrafficRoutes.OverlapNotice(routes, index))).ToList();
        if (TrafficRouteCards.ItemsSource is not System.Collections.Generic.List<TrafficRouteRow> current || !current.SequenceEqual(rows))
            TrafficRouteCards.ItemsSource = rows;
        TrafficRouteEmpty.Visibility = routes.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var exceptions = DirectExceptions.Read(profile);
        var legacySources = exceptions.Processes.Concat(exceptions.Domains).ToArray();
        LegacyTrafficPath.Visibility = legacySources.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        LegacyTrafficSources.Text = string.Join("、", legacySources.Take(3)) + (legacySources.Length > 3 ? " …" : "");
        LegacyTrafficSources.ToolTip = string.Join("\n", legacySources);
        LegacyTrafficExit.Text = exceptions.Enabled ? "直连 · 原生网络" : "未启用 · 保留例外配置";
        TrafficRouteSummary.Text = $"{routes.Count(route => route.Enabled)} 条启用 · 从上到下，第一条命中即生效";
        TrafficDnsFacts.Text = TrafficRoutes.DnsFacts(profile) + " 仅覆盖由 Harbor 解析的请求；代理服务器仍可能解析目标域名。";
        TrafficDefault.Text = ProfileWorkflow.RoutingMode(profile) == "direct" ? "其余请求 → 原生网络" :
            "其余请求 → " + (ProfileWorkflow.RoutingMode(profile) == "rules" ? "匹配下方规则 → " : "") + TrafficRoutes.PolicyLabel(profile, S(profile, "finalPolicy"));
        TrafficProtectionFacts.Text = "全局保护：" + (profile["privacy"]?["blockDirect"]?.GetValue<bool>() == true ? "禁止非回环直连；" : "允许直连；") +
            (profile["privacy"]?["requireEncryptedProxy"]?.GetValue<bool>() == true ? "要求代理传输加密。" : "代理加密取决于线路和路径要求。") + "域名拦截优先于所有路径。";
    }
    private async void AddTrafficPath(object sender, RoutedEventArgs e) => await EditTrafficPathAsync(-1);
    private async void AddGamePath(object sender, RoutedEventArgs e) => await EditTrafficPathAsync(-1, new("原神 / 米哈游直连", true, DirectExceptions.GameDomains.ToArray(), DirectExceptions.GameProcesses.ToArray(), "DIRECT", false));
    private async void AddVideoPath(object sender, RoutedEventArgs e) => await EditTrafficPathAsync(-1, new("B 站直连", true, DirectExceptions.VideoDomains.ToArray(), [], "DIRECT", false));
    private async void EditTrafficPath(object sender, RoutedEventArgs e) { if (sender is Button { Tag: int index }) await EditTrafficPathAsync(index); }
    private async Task EditTrafficPathAsync(int index, TrafficRouteSetting? initial = null) => await Safe(async () =>
    {
        var routes = TrafficRoutes.Read(profile);
        var dialog = new TrafficRouteDialog(this, profile, index >= 0 ? routes[index] : initial ?? new("新路径", true, [], [], null, false), index);
        if (dialog.ShowDialog() != true || dialog.Result == null) return;
        if (index >= 0) routes[index] = dialog.Result; else routes.Add(dialog.Result);
        await SaveTrafficRoutesAsync(routes);
    });
    private async Task SaveTrafficRoutesAsync(System.Collections.Generic.IEnumerable<TrafficRouteSetting> routes)
    {
        var candidate = profile.DeepClone().AsObject(); candidate["trafficRoutes"] = TrafficRoutes.Serialize(routes);
        TrafficRoutes.Read(candidate); await SaveAsync(candidate);
        ShowNotice("流量路径已保存。" + (running ? "仅新连接使用新路径；已有连接保留原出口。" : "连接后生效。"));
    }
    private async void ToggleTrafficPath(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (sender is not Button { Tag: int index }) return;
        var routes = TrafficRoutes.Read(profile); routes[index] = routes[index] with { Enabled = !routes[index].Enabled }; await SaveTrafficRoutesAsync(routes);
    });
    private async void RemoveTrafficPath(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        if (sender is not Button { Tag: int index }) return;
        var routes = TrafficRoutes.Read(profile); routes.RemoveAt(index); await SaveTrafficRoutesAsync(routes);
    });
    private async void MoveTrafficPathUp(object sender, RoutedEventArgs e) => await MoveTrafficPathAsync(sender, -1);
    private async void MoveTrafficPathDown(object sender, RoutedEventArgs e) => await MoveTrafficPathAsync(sender, 1);
    private async Task MoveTrafficPathAsync(object sender, int delta) => await Safe(async () =>
    {
        if (sender is not Button { Tag: int index }) return;
        var routes = TrafficRoutes.Read(profile); int next = index + delta; if (next < 0 || next >= routes.Count) return;
        (routes[index], routes[next]) = (routes[next], routes[index]); await SaveTrafficRoutesAsync(routes);
    });
    private void ExplainConditionsChanged(object sender, RoutedEventArgs e)
    {
        if (ExplainPath == null) return;
        ExplainPath.Visibility = Visibility.Collapsed;
        ExplainResult.Text = "离线检查配置路径。填写进程名仅模拟该进程，不验证操作系统识别结果。";
    }
}
