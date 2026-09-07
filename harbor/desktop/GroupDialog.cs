using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;
internal sealed class GroupDialog : Window
{
    private readonly TextBox name;
    private readonly ComboBox kind, selected;
    private readonly List<(string Name, CheckBox Toggle)> members = [];
    private readonly TextBlock notice;
    private readonly ListBox list;
    public JsonObject? Value { get; private set; }
    public GroupDialog(Window owner, IEnumerable<string> choices, JsonNode? existing = null)
    {
        Owner = owner; Title = existing == null ? "添加策略组" : "编辑策略组"; Width = 550; Height = 620; MinHeight = 460; MinWidth = 480; FontFamily = owner.FontFamily; Background = owner.Background; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var root = new DockPanel { Margin = new Thickness(26) }; Content = root;
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) }; DockPanel.SetDock(buttons, Dock.Bottom); root.Children.Add(buttons);
        buttons.Children.Add(new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) });
        var save = new Button { Content = "保存策略组", Style = (Style)FindResource("Primary"), IsDefault = true }; buttons.Children.Add(save); save.Click += (_, _) => Save();
        var form = new StackPanel(); DockPanel.SetDock(form, Dock.Top); root.Children.Add(form);
        void Label(string text) => form.Children.Add(new TextBlock { Text = text, Margin = new Thickness(0, 10, 0, 7) });
        Label("名称"); name = new TextBox { Text = existing?["name"]?.GetValue<string>() ?? "" }; form.Children.Add(name);
        Label("选择方式"); kind = new ComboBox { ItemsSource = new[] { "手动选择", "按顺序故障切换", "优选低延迟" }, SelectedIndex = (existing?["kind"]?.GetValue<string>()) switch { "fallback" => 1, "latency" => 2, _ => 0 } }; form.Children.Add(kind);
        Label("手动出口"); selected = new ComboBox(); form.Children.Add(selected);
        notice = new TextBlock { Style = (Style)FindResource("Hint"), Margin = new Thickness(0, 12, 0, 16) }; form.Children.Add(notice);
        var order = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) }; DockPanel.SetDock(order, Dock.Top); root.Children.Add(order);
        var up = new Button { Content = "上移", Margin = new Thickness(0, 0, 8, 0) }; var down = new Button { Content = "下移" }; order.Children.Add(up); order.Children.Add(down);
        list = new ListBox { BorderThickness = new Thickness(0), Background = System.Windows.Media.Brushes.White, Padding = new Thickness(6) }; root.Children.Add(list);
        up.Click += (_, _) => Move(-1); down.Click += (_, _) => Move(1);
        var included = (existing?["members"] as JsonArray)?.Select(v => v!.GetValue<string>()).ToArray() ?? [];
        // Preserve order: fallback priority is meaningful, so existing members stay first.
        foreach (string member in included.Concat(choices).Distinct())
        {
            var toggle = new CheckBox { Content = member, IsChecked = included.Contains(member), Margin = new Thickness(8, 9, 8, 9) }; members.Add((member, toggle)); toggle.Checked += (_, _) => { list.SelectedItem = toggle; Refresh(); }; toggle.Unchecked += (_, _) => Refresh();
        }
        list.ItemsSource = members.Select(m => m.Toggle).ToArray();
        void Selection() { up.IsEnabled = list.SelectedIndex > 0; down.IsEnabled = list.SelectedIndex >= 0 && list.SelectedIndex < members.Count - 1; }
        list.SelectionChanged += (_, _) => Selection(); Selection();
        kind.SelectionChanged += (_, _) => Refresh(); Refresh(); selected.SelectedItem = existing?["selected"]?.GetValue<string>() ?? selected.SelectedItem;
    }
    private void Move(int delta)
    {
        int index = list.SelectedIndex, next = index + delta;
        if (index < 0 || next < 0 || next >= members.Count) return;
        var value = members[index]; members.RemoveAt(index); members.Insert(next, value);
        list.ItemsSource = members.Select(m => m.Toggle).ToArray(); list.SelectedIndex = next; Refresh();
    }
    private void Refresh()
    {
        string? previous = selected.SelectedItem as string; var names = members.Where(m => m.Toggle.IsChecked == true).Select(m => m.Name).ToArray(); selected.ItemsSource = names; selected.SelectedItem = names.Contains(previous) ? previous : names.FirstOrDefault(); selected.IsEnabled = kind.SelectedIndex == 0;
        notice.Text = kind.SelectedIndex switch { 1 => "按顺序选择 TCP 探测正常的成员；连续 TCP 失败后切换。端口正常不代表认证成功。DIRECT 表示直连备用。", 2 => "使用 TCP 延迟、连续成功判断和切换冷却时间。现有连接保留原出口。", _ => "勾选组内成员，再选择要使用的出口。" };
    }
    private void Save()
    {
        var names = members.Where(m => m.Toggle.IsChecked == true).Select(m => m.Name).ToArray(); if (string.IsNullOrWhiteSpace(name.Text) || names.Length == 0) { notice.Text = "请填写名称，并至少选择一个成员。"; return; }
        Value = new JsonObject { { "name", name.Text.Trim() }, { "kind", kind.SelectedIndex switch { 1 => "fallback", 2 => "latency", _ => "select" } }, { "members", new JsonArray(names.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()) }, { "selected", kind.SelectedIndex == 0 ? selected.SelectedItem as string : null } }; DialogResult = true;
    }
}
