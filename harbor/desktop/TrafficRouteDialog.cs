using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Harbor;

internal sealed class TrafficRouteDialog : Window
{
    private sealed record PolicyOption(string? Key, string Label);
    internal TextBox NameInput { get; }
    internal TextBox DomainsInput { get; }
    internal TextBox ProcessesInput { get; }
    internal CheckBox EnabledInput { get; }
    internal CheckBox EncryptedInput { get; }
    internal ComboBox PolicyInput { get; }
    internal Button SaveButton { get; }
    internal TextBlock ErrorText { get; }
    internal TrafficRouteSetting? Result { get; private set; }

    internal TrafficRouteDialog(Window owner, JsonObject profile, TrafficRouteSetting initial, int editIndex = -1)
    {
        Owner = owner; Title = "编辑流量路径"; Width = 760; Height = 760; MinWidth = 600; MinHeight = 570;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = owner.FontFamily;
        Background = new SolidColorBrush(Color.FromRgb(250, 251, 252));
        var root = new DockPanel { Margin = new Thickness(24) }; Content = root;
        var footer = new StackPanel(); DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
        footer.Children.Add(Hint("只作用于进入 Harbor 的新连接。进程识别失败时继续按域名和默认路径处理；已有连接保持原出口。"));
        ErrorText = new TextBlock { Foreground = Brushes.Firebrick, TextWrapping = TextWrapping.Wrap }; footer.Children.Add(ErrorText);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) }; footer.Children.Add(buttons);
        var cancel = new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) }; cancel.Click += (_, _) => DialogResult = false; buttons.Children.Add(cancel);
        SaveButton = new Button { Content = "保存路径", Style = (Style)FindResource("Primary") }; buttons.Children.Add(SaveButton);
        var content = new StackPanel(); root.Children.Add(new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        content.Children.Add(new TextBlock { Text = "谁的流量，走哪条路", FontSize = 22, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 16) });
        NameInput = Field(content, "路径名称", initial.Name);
        EnabledInput = new CheckBox { Content = "启用这条路径", IsChecked = initial.Enabled, Margin = new Thickness(0, 0, 0, 16) }; content.Children.Add(EnabledInput);
        content.Children.Add(Label("1  应用 / 网站 · 任意一项命中即可"));
        DomainsInput = Field(content, "域名后缀 · 每行一个，包含子域名", string.Join("\n", initial.Domains), 74);
        ProcessesInput = Field(content, "Windows 进程名 · 例如 YuanShen.exe，每行一个", string.Join("\n", initial.Processes), 74);
        content.Children.Add(Label("2  出口"));
        var options = new[] { new PolicyOption(null, "跟随默认出口"), new PolicyOption("DIRECT", "直连 · 原生网络"), new PolicyOption("REJECT", "拦截") }
            .Concat((profile["groups"] as JsonArray ?? []).Select(v => new PolicyOption(v!["name"]!.GetValue<string>(), "策略组 · " + v["name"]!.GetValue<string>())))
            .Concat((profile["nodes"] as JsonArray ?? []).Select(v => new PolicyOption(v!["name"]!.GetValue<string>(), "线路 · " + v["name"]!.GetValue<string>()))).ToArray();
        PolicyInput = new ComboBox { ItemsSource = options, DisplayMemberPath = "Label", SelectedItem = options.FirstOrDefault(v => v.Key == initial.Policy), Margin = new Thickness(0, 0, 0, 8) }; content.Children.Add(PolicyInput);
        var facts = Hint(""); content.Children.Add(facts);
        void UpdateFacts() => facts.Text = TrafficRoutes.OutboundFacts(profile, (PolicyInput.SelectedItem as PolicyOption)?.Key ?? profile["finalPolicy"]!.GetValue<string>());
        PolicyInput.SelectionChanged += (_, _) => UpdateFacts(); UpdateFacts();
        content.Children.Add(Label("3  保护要求"));
        EncryptedInput = new CheckBox { Content = "必须使用加密代理 · 不满足时拦截", IsChecked = initial.RequireEncryptedProxy, Margin = new Thickness(0, 0, 0, 8) }; content.Children.Add(EncryptedInput);
        content.Children.Add(Hint("自动组排除不符合 TCP / UDP 加密要求或已判定不可用的成员；未测试成员仍可尝试。固定出口不自动换线。该选项不保证匿名、IP 信誉或流量不可识别。"));
        SaveButton.Click += (_, _) =>
        {
            try
            {
                var entries = DirectExceptions.Parse(true, DomainsInput.Text, ProcessesInput.Text);
                var route = new TrafficRouteSetting(NameInput.Text.Trim(), EnabledInput.IsChecked == true, entries.Domains, entries.Processes,
                    (PolicyInput.SelectedItem as PolicyOption ?? throw new FormatException("请选择出口。")).Key, EncryptedInput.IsChecked == true);
                var candidate = profile.DeepClone().AsObject(); var routes = TrafficRoutes.Read(candidate);
                if (editIndex >= 0) routes[editIndex] = route; else routes.Add(route);
                candidate["trafficRoutes"] = TrafficRoutes.Serialize(routes); TrafficRoutes.Read(candidate);
                Result = route; DialogResult = true;
            }
            catch (FormatException error) { Result = null; ErrorText.Text = error.Message; }
        };
    }
    private static TextBlock Label(string text) => new() { Text = text, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
    private static TextBlock Hint(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 0, 0, 14) };
    private static TextBox Field(Panel parent, string label, string value, double height = 38)
    {
        parent.Children.Add(Label(label));
        var box = new TextBox { Text = value, Height = height, AcceptsReturn = height > 38, VerticalScrollBarVisibility = height > 38 ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden, Margin = new Thickness(0, 0, 0, 14), MaxLength = height > 38 ? 128 * 1024 : 128 };
        parent.Children.Add(box); return box;
    }
}
