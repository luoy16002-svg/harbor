using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Harbor;
internal sealed class TextDialog : Window
{
    private readonly TextBox editor;
    public string Text => editor.Text;
    public TextDialog AllowFileImport()
    {
        var root = (DockPanel)Content; var button = new Button { Content = "从文件读取…", HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 14) }; DockPanel.SetDock(button, Dock.Top); root.Children.Insert(1, button);
        button.Click += (_, _) => { var picker = new Microsoft.Win32.OpenFileDialog { Filter = "节点与订阅文件|*.yaml;*.yml;*.json;*.txt;*.conf|所有文件|*.*" }; if (picker.ShowDialog(this) != true) return; try { if (new System.IO.FileInfo(picker.FileName).Length > ProfileImport.MaximumBytes) throw new System.IO.IOException("文件超过 2 MiB。"); editor.Text = System.IO.File.ReadAllText(picker.FileName, new System.Text.UTF8Encoding(false, true)); } catch (Exception error) { MessageBox.Show(this, error.Message, "无法读取文件"); } };
        return this;
    }
    public TextDialog(Window owner, string title, string description, string text, bool multiline = true)
    {
        Owner = owner; Title = title; Width = multiline ? 760 : 540; Height = multiline ? 580 : 250; MinWidth = 460; MinHeight = 230;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; Background = new SolidColorBrush(Color.FromRgb(248, 250, 249)); FontFamily = owner.FontFamily;
        var root = new DockPanel { Margin = new Thickness(24) }; Content = root;
        var hint = new TextBlock { Text = description, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16), Foreground = Brushes.DimGray }; DockPanel.SetDock(hint, Dock.Top); root.Children.Add(hint);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) }; DockPanel.SetDock(buttons, Dock.Bottom); root.Children.Add(buttons);
        var cancel = new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) }; buttons.Children.Add(cancel);
        var save = new Button { Content = "确定", IsDefault = !multiline, Style = (Style)FindResource("Primary") }; save.Click += (_, _) => { DialogResult = true; }; buttons.Children.Add(save);
        editor = new TextBox { Text = text, AcceptsReturn = multiline, AcceptsTab = multiline, FontFamily = new FontFamily(multiline ? "Cascadia Mono, Consolas" : "Segoe UI"), FontSize = 13, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, TextWrapping = TextWrapping.NoWrap };
        root.Children.Add(editor); Loaded += (_, _) => editor.Focus();
    }
}

internal sealed class FormDialog : Window
{
    private readonly Dictionary<string, Control> fields = new();
    private readonly Dictionary<string, StackPanel> rows = new();
    private readonly StackPanel body;
    public FormDialog(Window owner, string title)
    {
        Owner = owner; Title = title; Width = 500; SizeToContent = SizeToContent.Height; MaxHeight = 780; ResizeMode = ResizeMode.NoResize; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(248, 250, 249)); FontFamily = owner.FontFamily;
        var root = new DockPanel { Margin = new Thickness(26) }; Content = root;
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 22, 0, 0) }; DockPanel.SetDock(buttons, Dock.Bottom); root.Children.Add(buttons);
        buttons.Children.Add(new Button { Content = "取消", IsCancel = true, Margin = new Thickness(0, 0, 10, 0) });
        var save = new Button { Content = "保存", IsDefault = true, Style = (Style)FindResource("Primary") }; save.Click += (_, _) => DialogResult = true; buttons.Children.Add(save);
        body = new StackPanel(); root.Children.Add(new ScrollViewer { Content = body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
    }
    public FormDialog Field(string key, string label, string value = "", string[]? choices = null, bool secret = false)
    {
        var row = new StackPanel(); rows[key] = row; body.Children.Add(row);
        row.Children.Add(new TextBlock { Text = label, Margin = new Thickness(0, 12, 0, 7), Foreground = Brushes.DimGray, FontSize = 12, TextWrapping = TextWrapping.Wrap });
        Control control = choices != null ? new ComboBox { ItemsSource = choices, SelectedItem = string.IsNullOrEmpty(value) ? choices[0] : value } : secret ? new PasswordBox { Password = value } : new TextBox { Text = value };
        fields[key] = control; row.Children.Add(control); return this;
    }
    public void Visible(string key, bool visible) => rows[key].Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
    public void Changed(string key, Action action) { if (fields[key] is ComboBox combo) combo.SelectionChanged += (_, _) => action(); }
    public string Get(string key) => fields[key] switch { TextBox t => t.Text.Trim(), PasswordBox p => p.Password, ComboBox c => c.SelectedItem?.ToString() ?? "", _ => "" };
}
