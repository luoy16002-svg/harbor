using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace Harbor;

internal sealed class SubscriptionUpdatePreview : Window
{
    internal Button ApplyButton { get; }
    internal Button CancelButton { get; }
    internal SubscriptionUpdatePreview(Window owner, SubscriptionUpdate update)
    {
        Owner = owner; Title = "检查订阅更新"; Width = 790; Height = 560; MinWidth = 600; MinHeight = 390;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = owner.FontFamily;
        Background = new SolidColorBrush(Color.FromRgb(250, 251, 252));
        var root = new DockPanel { Margin = new Thickness(24) }; Content = root;
        var heading = new TextBlock { Text = update.Entry.Name + " · 更新预览", FontSize = 19, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
        DockPanel.SetDock(heading, Dock.Top); root.Children.Add(heading);
        var summary = new TextBlock { Text = update.Summary, FontSize = 14, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
        DockPanel.SetDock(summary, Dock.Top); root.Children.Add(summary);
        var hint = new TextBlock
        {
            Text = "确认后才更新线路。被当前出口、规则或策略组引用的旧线路会保留；认证信息只显示是否变化。" +
                (update.Issues.Count > 0 ? $" 新订阅另有 {update.Issues.Count} 项不支持，请检查下方明细。" : ""),
            TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 0, 0, 18)
        };
        DockPanel.SetDock(hint, Dock.Top); root.Children.Add(hint);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
        DockPanel.SetDock(buttons, Dock.Bottom); root.Children.Add(buttons);
        CancelButton = new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) };
        CancelButton.Click += (_, _) => DialogResult = false; buttons.Children.Add(CancelButton);
        ApplyButton = new Button { Content = "应用订阅更新", Style = (Style)FindResource("Primary") };
        ApplyButton.Click += (_, _) => DialogResult = true; buttons.Children.Add(ApplyButton);
        var list = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, RowHeight = double.NaN, MinRowHeight = 43 };
        list.Columns.Add(new DataGridTextColumn { Header = "线路", Binding = new Binding("Name"), Width = 180 });
        list.Columns.Add(new DataGridTextColumn { Header = "变化", Binding = new Binding("Action"), Width = 80 });
        var wrapped = new Style(typeof(TextBlock)); wrapped.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
        list.Columns.Add(new DataGridTextColumn { Header = "说明", Binding = new Binding("Detail"), Width = new DataGridLength(1, DataGridLengthUnitType.Star), ElementStyle = wrapped });
        list.ItemsSource = update.Changes.Concat(update.Issues.Select(issue => new SubscriptionChange(issue.Name, "不支持", issue.Reason))).ToList();
        root.Children.Add(list);
    }
}
