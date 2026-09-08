using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Harbor;

internal sealed class PoolDialog : Window
{
    internal TextBox NameInput { get; }
    internal TextBox UrlInput { get; }
    internal TextBox IntervalInput { get; }
    internal TextBox CheckTimeoutInput { get; }
    internal TextBox AttemptTimeoutInput { get; }
    internal TextBox CaInput { get; }
    internal TextBox SearchInput { get; }
    internal ComboBox KindInput { get; }
    internal ComboBox AttemptsInput { get; }
    internal CheckBox MonitorInput { get; }
    internal Button SaveButton { get; }
    internal Button VerifiedButton { get; }
    internal TextBlock ErrorText { get; }
    internal ListBox MemberList { get; }
    internal JsonObject? Result { get; private set; }
    private readonly List<(string Name, CheckBox Toggle)> members = [];
    private readonly TextBlock count;
    internal PoolDialog(Window owner, JsonObject profile, JsonNode? existing, IReadOnlyDictionary<string, LineCheck> checks)
    {
        Owner = owner; Title = existing == null ? "创建自动线路池" : "编辑自动线路池"; Width = 980; Height = 780; MinWidth = 760; MinHeight = 600;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = owner.FontFamily; Background = owner.Background;
        var root = new DockPanel { Margin = new Thickness(26) }; Content = root;
        var footer = new StackPanel { Margin = new Thickness(0, 14, 0, 0) }; DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
        ErrorText = new TextBlock { Foreground = Brushes.Firebrick, TextWrapping = TextWrapping.Wrap }; footer.Children.Add(ErrorText);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right }; footer.Children.Add(actions);
        actions.Children.Add(new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 10, 10, 0) });
        SaveButton = new Button { Content = "保存线路池", Style = (Style)FindResource("Primary"), Margin = new Thickness(0, 10, 0, 0) }; actions.Children.Add(SaveButton);
        var heading = new StackPanel(); DockPanel.SetDock(heading, Dock.Top); root.Children.Add(heading);
        heading.Children.Add(new TextBlock { Text = "选好主线，让备线接得上", FontSize = 23, FontWeight = FontWeights.SemiBold });
        heading.Children.Add(Hint("定期检查实际 HTTPS 连通性。建连失败时，在池内继续尝试；已发出数据的连接保持原出口。"));
        var columns = new Grid(); columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.1, GridUnitType.Star) }); columns.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) }); columns.ColumnDefinitions.Add(new ColumnDefinition()); root.Children.Add(columns);
        var left = new DockPanel(); columns.Children.Add(left);
        var toolbar = new StackPanel(); DockPanel.SetDock(toolbar, Dock.Top); left.Children.Add(toolbar);
        toolbar.Children.Add(Label("成员与优先顺序"));
        SearchInput = new TextBox { ToolTip = "按线路名称搜索", Margin = new Thickness(0, 0, 0, 10) }; toolbar.Children.Add(SearchInput);
        var buttons = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) }; toolbar.Children.Add(buttons);
        Button Action(string label, Action action) { var button = new Button { Content = label, Padding = new Thickness(9, 6, 9, 6), Margin = new Thickness(0, 0, 7, 7) }; button.Click += (_, _) => action(); buttons.Children.Add(button); return button; }
        Action("勾选筛选结果", () => { foreach (var m in members.Where(m => Matches(m.Name))) m.Toggle.IsChecked = true; });
        VerifiedButton = Action("仅选近期验证通过", () => { var now = DateTimeOffset.UtcNow; foreach (var m in members) m.Toggle.IsChecked = checks.TryGetValue(m.Name, out var check) && check.Success && check.Fresh(now); });
        Action("清空", () => { foreach (var m in members) m.Toggle.IsChecked = false; });
        count = Hint(""); toolbar.Children.Add(count);
        var move = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) }; DockPanel.SetDock(move, Dock.Bottom); left.Children.Add(move);
        var up = new Button { Content = "上移优先级", Margin = new Thickness(0, 0, 8, 0) }; var down = new Button { Content = "下移" }; move.Children.Add(up); move.Children.Add(down);
        MemberList = new ListBox { Background = Brushes.White, BorderThickness = new Thickness(0), Padding = new Thickness(6), HorizontalContentAlignment = HorizontalAlignment.Stretch }; left.Children.Add(MemberList);
        var included = (existing?["members"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToArray() ?? [];
        var nodes = (profile["nodes"] as JsonArray ?? []).Select(n => n!["name"]!.GetValue<string>()).ToArray();
        if (existing == null && nodes.Contains(profile["finalPolicy"]?.GetValue<string>())) included = [profile["finalPolicy"]!.GetValue<string>()];
        foreach (string member in included.Concat(nodes).Distinct(StringComparer.Ordinal))
        {
            var toggle = new CheckBox { Content = member, ToolTip = member, IsChecked = included.Contains(member), Margin = new Thickness(8, 9, 8, 9) };
            members.Add((member, toggle)); toggle.Checked += (_, _) => { MemberList.SelectedItem = toggle; UpdateCount(); }; toggle.Unchecked += (_, _) => UpdateCount();
        }
        bool Matches(string name) => name.Contains(SearchInput.Text.Trim(), StringComparison.OrdinalIgnoreCase);
        void RefreshMembers() => MemberList.ItemsSource = members.Where(m => Matches(m.Name)).Select(m => m.Toggle).ToArray();
        void Move(int delta)
        {
            var visible = members.Where(m => Matches(m.Name)).ToList(); int i = visible.FindIndex(m => m.Toggle == MemberList.SelectedItem); int next = i + delta;
            if (i < 0 || next < 0 || next >= visible.Count) return;
            var selected = visible[i]; int a = members.IndexOf(selected), b = members.IndexOf(visible[next]); (members[a], members[b]) = (members[b], members[a]); RefreshMembers(); MemberList.SelectedItem = selected.Toggle;
        }
        SearchInput.TextChanged += (_, _) => RefreshMembers(); up.Click += (_, _) => Move(-1); down.Click += (_, _) => Move(1); RefreshMembers(); UpdateCount();
        var right = new StackPanel(); var scroll = new ScrollViewer { Content = right, VerticalScrollBarVisibility = ScrollBarVisibility.Auto }; Grid.SetColumn(scroll, 2); columns.Children.Add(scroll);
        var options = existing?["pool"] is { } p ? PoolOptions.Read(p) : new PoolOptions();
        NameInput = Field(right, "线路池名称", existing?["name"]?.GetValue<string>() ?? "日常线路池");
        right.Children.Add(Label("选择方式")); KindInput = new ComboBox { ItemsSource = new[] { "稳定优先 · 保持当前可用线路", "低延迟优先 · 达到门槛后切换" }, SelectedIndex = existing?["kind"]?.GetValue<string>() == "latency" ? 1 : 0, Margin = new Thickness(0, 0, 0, 12) }; right.Children.Add(KindInput);
        right.Children.Add(Hint("稳定优先按左侧顺序起步，恢复后保持可用出口。HTTPS 检查通过的成员优先于尚未验证的成员。"));
        MonitorInput = new CheckBox { Content = "运行时自动检查 HTTPS 连通性", IsChecked = options.Monitor, Margin = new Thickness(0, 0, 0, 12) }; right.Children.Add(MonitorInput);
        UrlInput = Field(right, "检查地址 · HTTPS", options.CheckUrl, maxLength: 2048);
        right.Children.Add(Hint("每次发送一个 HEAD 请求，验证目标证书并检查响应。可填写自己的稳定检查服务；不会跟随跳转。"));
        IntervalInput = Field(right, "检查间隔（秒）", options.CheckIntervalSecs.ToString());
        var advanced = new StackPanel(); right.Children.Add(new Expander { Header = "超时、重试与检查证书", Content = advanced, Margin = new Thickness(0, 4, 0, 12) });
        advanced.Children.Add(Label("最多建连尝试 · 包含首次")); AttemptsInput = new ComboBox { ItemsSource = new[] { 1, 2, 3 }, SelectedItem = options.ConnectAttempts, Margin = new Thickness(0, 0, 0, 12) }; advanced.Children.Add(AttemptsInput);
        AttemptTimeoutInput = Field(advanced, "每次建连超时（毫秒）", options.AttemptTimeoutMs.ToString());
        CheckTimeoutInput = Field(advanced, "每次 HTTPS 检查超时（毫秒）", options.CheckTimeoutMs.ToString());
        CaInput = Field(advanced, "检查服务自定义 CA · PEM，可留空", options.CaPem, 90, 65536);
        advanced.Children.Add(Hint("留空使用系统信任证书。建连重试仍受全局连接总超时限制；检查结果仅证明 TCP/HTTPS 可用。"));
        SaveButton.Click += (_, _) =>
        {
            try
            {
                int Number(TextBox input) => int.TryParse(input.Text, out int n) ? n : throw new FormatException("间隔和超时须填写整数。");
                var value = new PoolOptions(MonitorInput.IsChecked == true, UrlInput.Text.Trim(), Number(IntervalInput), Number(CheckTimeoutInput), (int)(AttemptsInput.SelectedItem ?? 3), Number(AttemptTimeoutInput), CaInput.Text.Trim()); value.Validate();
                string name = NameInput.Text.Trim(), previous = existing?["name"]?.GetValue<string>() ?? ""; ProxyPools.ValidateName(profile, name, previous);
                var group = new JsonObject { ["name"] = name, ["kind"] = KindInput.SelectedIndex == 1 ? "latency" : "fallback", ["selected"] = null,
                    ["members"] = new JsonArray(members.Where(m => m.Toggle.IsChecked == true).Select(m => (JsonNode?)JsonValue.Create(m.Name)).ToArray()), ["pool"] = value.ToJson() };
                var candidate = profile.DeepClone().AsObject(); var groups = candidate["groups"]!.AsArray(); int index = groups.ToList().FindIndex(g => g?["name"]?.GetValue<string>() == previous);
                if (index < 0) groups.Add(group.DeepClone()); else groups[index] = group.DeepClone(); ProxyPools.Validate(candidate);
                Result = group; DialogResult = true;
            }
            catch (FormatException error) { Result = null; ErrorText.Text = error.Message; }
        };
    }
    internal void SelectMember(string name, bool selected) => members.Single(m => m.Name == name).Toggle.IsChecked = selected;
    private void UpdateCount() => count.Text = $"已选 {members.Count(m => m.Toggle.IsChecked == true)} / 128 条 · 稳定优先时按此顺序起步";
    private static TextBlock Label(string text) => new() { Text = text, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 7) };
    private static TextBlock Hint(string text) => new() { Text = text, Foreground = Brushes.DimGray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 14) };
    private static TextBox Field(Panel parent, string label, string text, double height = 38, int maxLength = 128)
    {
        parent.Children.Add(Label(label)); var field = new TextBox { Text = text, Height = height, MaxLength = maxLength, AcceptsReturn = height > 38, VerticalScrollBarVisibility = height > 38 ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden, Margin = new Thickness(0, 0, 0, 14) }; parent.Children.Add(field); return field;
    }
}
