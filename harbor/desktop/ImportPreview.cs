using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Harbor;
internal sealed class ImportPreview : Window
{
    public ImportPreview(Window owner, ImportResult result)
    {
        Owner = owner; Title = "检查导入内容"; Width = 740; Height = 530; MinWidth = 550; MinHeight = 350; WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = owner.FontFamily; Background = new SolidColorBrush(Color.FromRgb(250, 251, 252));
        var root = new DockPanel { Margin = new Thickness(24) }; Content = root;
        var heading = new TextBlock { Text = $"{result.Format} · 可导入 {result.Nodes.Count} 项 · 不支持 {result.Issues.Count} 项", FontSize = 17, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 12) }; DockPanel.SetDock(heading, Dock.Top); root.Children.Add(heading);
        var hint = new TextBlock { Text = "这是格式检查，尚未验证连通性。不支持的协议参数会逐项列出；导入后可以在线路页面验证。", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 0, 0, 18) }; DockPanel.SetDock(hint, Dock.Top); root.Children.Add(hint);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) }; DockPanel.SetDock(buttons, Dock.Bottom); root.Children.Add(buttons); buttons.Children.Add(new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) });
        var import = new Button { Content = $"导入 {result.Nodes.Count} 个节点", IsEnabled = result.Nodes.Count > 0, Style = (Style)FindResource("Primary") }; import.Click += (_, _) => DialogResult = true; buttons.Children.Add(import);
        var list = new DataGrid(); list.Columns.Add(new DataGridTextColumn { Header = "节点", Binding = new System.Windows.Data.Binding("Name"), Width = new DataGridLength(180) }); list.Columns.Add(new DataGridTextColumn { Header = "结果", Binding = new System.Windows.Data.Binding("Result"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        list.ItemsSource = result.Nodes.Select(n => new { Name = n!["name"]!.GetValue<string>(), Result = "可导入 · " + n["kind"]!.GetValue<string>() }).Concat(result.Issues.Select(i => new { Name = i.Name, Result = i.Reason })).ToList(); root.Children.Add(list);
    }
}
