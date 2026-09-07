using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace Harbor;

internal sealed record WorkspaceRestoreRequest(string Id, WorkspaceState Current, WorkspaceState Selected);

internal sealed class WorkspaceHistoryDialog : Window
{
    internal Button RestoreButton { get; }
    internal Button CancelButton { get; }
    internal Button ClearButton { get; }
    internal DataGrid Versions { get; }
    internal DataGrid Differences { get; }
    internal TextBlock Status { get; }
    internal WorkspaceRestoreRequest? Request { get; private set; }
    private readonly WorkspaceState current;
    private readonly bool canRestore;

    internal WorkspaceHistoryDialog(Window owner, WorkspaceState current, bool canRestore, Func<bool>? confirmClear = null)
    {
        this.current = WorkspaceHistory.Clone(current); this.canRestore = canRestore;
        Owner = owner; Title = "配置历史"; Width = 880; Height = 670; MinWidth = 660; MinHeight = 530;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; FontFamily = owner.FontFamily;
        Background = new SolidColorBrush(Color.FromRgb(250, 251, 252));
        var root = new DockPanel { Margin = new Thickness(24) }; Content = root;
        void Top(UIElement child) { DockPanel.SetDock(child, Dock.Top); root.Children.Add(child); }
        Top(new TextBlock { Text = "配置历史", FontSize = 21, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 10) });
        Top(new TextBlock { Text = "保留最近 10 次配置变更前的版本。密码与订阅地址随配置加密保存，差异只显示变更项目。",
            TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 0, 0, 16) });
        var footer = new StackPanel(); DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
        footer.Children.Add(new TextBlock { Text = "恢复后保持断开，当前配置会先保存为历史版本。订阅用量与缓存标记会清除，需手动刷新订阅。系统代理偏好与连接记录保持原样。",
            TextWrapping = TextWrapping.Wrap, Foreground = Brushes.DimGray, Margin = new Thickness(0, 14, 0, 14) });
        var actions = new DockPanel(); footer.Children.Add(actions);
        ClearButton = new Button { Content = "清空历史", HorizontalAlignment = HorizontalAlignment.Left };
        DockPanel.SetDock(ClearButton, Dock.Left); actions.Children.Add(ClearButton);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        actions.Children.Add(buttons);
        CancelButton = new Button { Content = "关闭", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) };
        CancelButton.Click += (_, _) => DialogResult = false; buttons.Children.Add(CancelButton);
        RestoreButton = new Button { Content = "恢复所选版本", IsEnabled = false, Style = (Style)FindResource("Primary") };
        buttons.Children.Add(RestoreButton);
        Versions = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, Height = 142, RowHeight = 40, SelectionMode = DataGridSelectionMode.Single };
        Versions.Columns.Add(new DataGridTextColumn { Header = "保存时间", Binding = new Binding("Time"), Width = 177 });
        Versions.Columns.Add(new DataGridTextColumn { Header = "历史版本", Binding = new Binding("Summary"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        Versions.SelectionChanged += (_, _) => Select(); Top(Versions);
        Status = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 15, 0, 12), FontWeight = FontWeights.SemiBold }; Top(Status);
        Differences = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, RowHeight = double.NaN, MinRowHeight = 43 };
        var wrapped = new Style(typeof(TextBlock)); wrapped.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
        Differences.Columns.Add(new DataGridTextColumn { Header = "项目", Binding = new Binding("Area"), Width = 165, ElementStyle = wrapped });
        Differences.Columns.Add(new DataGridTextColumn { Header = "变化", Binding = new Binding("Action"), Width = 62 });
        Differences.Columns.Add(new DataGridTextColumn { Header = "当前配置 → 历史版本", Binding = new Binding("Detail"), Width = new DataGridLength(1, DataGridLengthUnitType.Star), ElementStyle = wrapped });
        root.Children.Add(Differences);
        ClearButton.Click += (_, _) =>
        {
            bool accepted = confirmClear?.Invoke() ?? MessageBox.Show(this, "删除全部配置历史？当前配置会保留，已删除的历史无法恢复。", "清空配置历史", MessageBoxButton.OKCancel, MessageBoxImage.Question) == MessageBoxResult.OK;
            if (!accepted) return;
            try { WorkspaceHistory.Clear(); Reload(); }
            catch (Exception) { Status.Text = "清空失败，请检查历史文件的访问权限。当前配置保留。"; }
        };
        RestoreButton.Click += (_, _) =>
        {
            if (!RestoreButton.IsEnabled || Versions.SelectedItem is not WorkspaceRevision item) return;
            Request = new(item.Id, WorkspaceHistory.Clone(this.current), WorkspaceHistory.Clone(item.State)); DialogResult = true;
        };
        Reload();
    }

    private void Reload()
    {
        RestoreButton.IsEnabled = false; Request = null; Differences.ItemsSource = null;
        try
        {
            var revisions = WorkspaceHistory.Read(); Versions.ItemsSource = revisions;
            ClearButton.IsEnabled = File.Exists(WorkspaceHistory.FilePath);
            if (revisions.Count > 0) Versions.SelectedIndex = 0;
            else Status.Text = "还没有历史版本。下次修改配置时，会自动保存修改前的版本。";
        }
        catch (Exception)
        {
            Versions.ItemsSource = null; RestoreButton.IsEnabled = false; ClearButton.IsEnabled = File.Exists(WorkspaceHistory.FilePath);
            Status.Text = "配置历史无法读取，当前配置仍保留。可检查文件权限，或清空损坏的历史后继续保存。";
        }
    }

    private void Select()
    {
        RestoreButton.IsEnabled = false; Differences.ItemsSource = null;
        if (Versions.SelectedItem is not WorkspaceRevision selected) return;
        try
        {
            var changes = WorkspaceHistory.Compare(current, selected.State); Differences.ItemsSource = changes;
            Status.Text = changes.Count == 0 ? "与当前配置相同。" : $"恢复至 {selected.Time} · {changes.Count} 项差异";
            if (!canRestore) Status.Text += "  请先断开连接，再打开配置历史进行恢复。";
            WorkspaceHistory.PrepareRestore(selected.State);
            RestoreButton.IsEnabled = canRestore && changes.Count > 0;
        }
        catch (Exception) { Status.Text = "所选版本的数据无效，无法恢复。当前配置保留。"; }
    }
}
