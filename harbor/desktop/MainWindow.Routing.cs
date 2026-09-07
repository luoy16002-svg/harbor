using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    private void SyncRoutingControls()
    {
        if (HomeRoutingMode == null) return;
        bool previous = syncing; syncing = true;
        try
        {
            string mode = ProfileWorkflow.RoutingMode(profile);
            string label = ProfileWorkflow.RoutingLabel(profile);
            string[] labels = ProfileWorkflow.RoutingModes.Select(value => value.Label).ToArray();
            HomeRoutingMode.ItemsSource ??= labels; RoutingModeInput.ItemsSource ??= labels;
            RehearsalRoutingMode.ItemsSource ??= labels;
            HomeRoutingMode.SelectedItem = RoutingModeInput.SelectedItem = label;
            if (RehearsalRoutingMode.SelectedItem == null) RehearsalRoutingMode.SelectedItem = label;
            HomeRoutingMode.IsEnabled = RoutingModeInput.IsEnabled = !busy && client != null;
            string description = mode switch
            {
                "global" => "忽略分流规则，所有请求使用默认出口。",
                "direct" => "忽略分流规则，所有请求使用直连。",
                _ => "按顺序匹配规则，未命中时使用默认出口。"
            };
            bool directBlocked = mode == "direct" && profile["privacy"]?["blockDirect"]?.GetValue<bool>() == true;
            HomeRoutingDescription.Text = directBlocked ? "当前隐私设置禁止非回环直连。" : description;
            RoutingModeDescription.Text = description + "仅改变进入 Harbor 的新连接，已有连接保留原出口。隐私限制仍然生效。" +
                (directBlocked ? "当前已禁止非回环直连，这类请求会被拦截。" : "");
            RuleModeHint.Text = mode == "rules" ? "规则按顺序匹配；已停用的规则不参与匹配。" : "当前模式不匹配下方规则。规则保持保存，切回“按规则”后生效。";
            PolicySummary.Text = mode == "direct" ? "DIRECT" : S(profile, "finalPolicy");
            PolicyDetail.Text = label + " · " + description;
            FinalPolicy.IsEnabled = mode != "direct" && !busy;
            RehearsalPolicy.IsEnabled = RehearsalRoutingMode.SelectedItem as string != "全部直连";
        }
        finally { syncing = previous; }
    }

    private async void RoutingModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (syncing || sender is not ComboBox { SelectedItem: string label }) return;
        await Safe(async () =>
        {
            string mode = ProfileWorkflow.RoutingKey(label);
            if (mode == ProfileWorkflow.RoutingMode(profile)) return;
            var candidate = profile.DeepClone().AsObject(); candidate["routingMode"] = mode;
            await SaveAsync(candidate);
            ExplainResult.Text = "分流模式已改变，可重新检查目标路径。";
            ShowNotice("已切换到“" + label + "”。" + (running ? "新连接使用新模式，已建立的连接保留原出口。" : "连接后生效。"));
        });
        SyncHome();
    }

    private void RehearsalModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (RehearsalPolicy != null) RehearsalPolicy.IsEnabled = RehearsalRoutingMode.SelectedItem as string != "全部直连";
        PreviewConditionsChanged(sender, e);
    }

    private void PreviewConditionsChanged(object sender, RoutedEventArgs e) { if (!syncing) InvalidateRoutePreview(); }
    private void InvalidateRoutePreview()
    {
        if (RehearsalGrid?.ItemsSource == null) return;
        RehearsalGrid.ItemsSource = null;
        RehearsalSummary.Text = "配置或候选条件已变化，请重新比较路径。";
    }
}
