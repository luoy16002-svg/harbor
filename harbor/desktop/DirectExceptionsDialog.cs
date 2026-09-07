using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Harbor;

internal sealed class DirectExceptionsDialog : Window
{
    internal CheckBox EnabledInput { get; }
    internal TextBox DomainsInput { get; }
    internal TextBox ProcessesInput { get; }
    internal Button GameButton { get; }
    internal Button VideoButton { get; }
    internal Button SaveButton { get; }
    internal Button CancelButton { get; }
    internal TextBlock ErrorText { get; }
    internal DirectExceptionSettings? Result { get; private set; }

    internal DirectExceptionsDialog(Window owner, DirectExceptionSettings settings)
    {
        Owner = owner; Title = "直连例外"; Width = 760; Height = 710; MinWidth = 600; MinHeight = 540;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = owner.FontFamily;
        Background = new SolidColorBrush(Color.FromRgb(250, 251, 252));
        var root = new DockPanel { Margin = new Thickness(24) }; Content = root;
        var footer = new StackPanel(); DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
        footer.Children.Add(new TextBlock { Text = "进程例外可覆盖直接访问 IP 的 TCP / UDP 流量。无法识别时按原出口处理。游戏流量须先进入 Harbor，通常需要 TUN；路径检查只检查域名。", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 12, 0, 0) });
        ErrorText = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Firebrick, Margin = new Thickness(0, 12, 0, 0) }; footer.Children.Add(ErrorText);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) }; footer.Children.Add(buttons);
        CancelButton = new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) };
        CancelButton.Click += (_, _) => DialogResult = false; buttons.Children.Add(CancelButton);
        SaveButton = new Button { Content = "保存直连例外", Style = (Style)FindResource("Primary") }; buttons.Children.Add(SaveButton);
        var content = new StackPanel(); root.Children.Add(new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        content.Children.Add(new TextBlock { Text = "全局代理，也能为游戏和视频直连", FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 12), TextWrapping = TextWrapping.Wrap });
        content.Children.Add(new TextBlock { Text = "例外优先于全局出口和分流规则；其余请求保持原出口。只影响进入 Harbor 的新连接，隐私限制仍生效。", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 0, 0, 16) });
        EnabledInput = new CheckBox { Content = "启用直连例外", IsChecked = settings.Enabled, Margin = new Thickness(0, 0, 0, 16) }; content.Children.Add(EnabledInput);
        var presets = new WrapPanel { Margin = new Thickness(0, 0, 0, 16) }; content.Children.Add(presets);
        GameButton = new Button { Content = "加入原神 / 米哈游", Margin = new Thickness(0, 0, 10, 0) }; presets.Children.Add(GameButton);
        VideoButton = new Button { Content = "加入 B 站" }; presets.Children.Add(VideoButton);
        content.Children.Add(Label("域名后缀 · 每行一个，包含其子域名"));
        DomainsInput = Editor(string.Join("\n", settings.Domains), 124); content.Children.Add(DomainsInput);
        content.Children.Add(Label("Windows 进程名 · 每行一个，例如 YuanShen.exe"));
        ProcessesInput = Editor(string.Join("\n", settings.Processes), 128); content.Children.Add(ProcessesInput);
        GameButton.Click += (_, _) => { DomainsInput.Text = DirectExceptions.Merge(DomainsInput.Text, DirectExceptions.GameDomains); ProcessesInput.Text = DirectExceptions.Merge(ProcessesInput.Text, DirectExceptions.GameProcesses); EnabledInput.IsChecked = true; };
        VideoButton.Click += (_, _) => { DomainsInput.Text = DirectExceptions.Merge(DomainsInput.Text, DirectExceptions.VideoDomains); EnabledInput.IsChecked = true; };
        SaveButton.Click += (_, _) =>
        {
            try { Result = DirectExceptions.Parse(EnabledInput.IsChecked == true, DomainsInput.Text, ProcessesInput.Text); DialogResult = true; }
            catch (FormatException error) { Result = null; ErrorText.Text = error.Message; }
        };
    }
    private static TextBlock Label(string text) => new() { Text = text, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap };
    private static TextBox Editor(string text, double height) => new() { Text = text, Height = height, AcceptsReturn = true, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 0, 12), MaxLength = 128 * 1024 };
}
