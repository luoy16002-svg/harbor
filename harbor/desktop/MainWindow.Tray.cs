using System;
using System.Drawing;
using System.Windows;
using Forms = System.Windows.Forms;

namespace Harbor;

public partial class MainWindow
{
    private Icon? trayStoppedIcon, trayConnectedIcon;
    private Forms.ToolStripMenuItem? trayToggle, trayRoute, trayCopy, trayExit;
    private void InitializeTray()
    {
        trayStoppedIcon = BrandIcon.Load("harbor-stopped"); trayConnectedIcon = BrandIcon.Load("harbor-connected");
        tray = new Forms.NotifyIcon { Text = "Harbor · 已停止", Icon = trayStoppedIcon, Visible = true };
        tray.DoubleClick += (_, _) => Dispatcher.Invoke(ShowMainWindow);
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("打开 Harbor", null, (_, _) => Dispatcher.Invoke(ShowMainWindow));
        trayToggle = new Forms.ToolStripMenuItem("连接", null, (_, _) => Dispatcher.Invoke(() =>
        {
            if (busy || client == null) return;
            if (ProfileWorkflow.NeedsFirstNode(profile)) ShowMainWindow();
            ToggleEngine(this, new RoutedEventArgs());
        }));
        menu.Items.Add(trayToggle); menu.Items.Add(new Forms.ToolStripSeparator());
        trayRoute = new Forms.ToolStripMenuItem { Enabled = false }; menu.Items.Add(trayRoute);
        menu.Items.Add("选择线路…", null, (_, _) => Dispatcher.Invoke(() => { ShowMainWindow(); Navigate(NavNodes, new RoutedEventArgs()); }));
        trayCopy = new Forms.ToolStripMenuItem("复制本地代理地址", null, (_, _) => Dispatcher.Invoke(() =>
        {
            try { Clipboard.SetText(S(profile, "listen")); tray.ShowBalloonTip(1800, "Harbor", "已复制 " + S(profile, "listen"), Forms.ToolTipIcon.Info); }
            catch (Exception error) { ShowNotice("复制失败：" + error.Message); }
        }));
        menu.Items.Add(trayCopy); menu.Items.Add(new Forms.ToolStripSeparator());
        trayExit = new Forms.ToolStripMenuItem("退出并恢复网络", null, (_, _) => Dispatcher.Invoke(() => { if (!busy) { quitting = true; Close(); } }));
        menu.Items.Add(trayExit);
        menu.Opening += (_, _) => SyncTray(); tray.ContextMenuStrip = menu; SyncTray();
    }
    private void ShowMainWindow() { Show(); if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal; Activate(); }
    private void SyncTray()
    {
        if (tray == null) return;
        string route = profile["finalPolicy"]?.GetValue<string>() ?? "未选择";
        if (ProfileWorkflow.RoutingMode(profile) == "direct") route = "DIRECT";
        tray.Icon = running ? trayConnectedIcon : trayStoppedIcon;
        string text = "Harbor · " + (running ? "已连接 · " + route : "已停止"); tray.Text = text.Length > 63 ? text[..60] + "…" : text;
        trayToggle!.Text = busy ? "正在处理…" : running ? "断开并恢复网络" : "连接";
        trayToggle.Enabled = !busy && !quitting && client != null;
        trayRoute!.Text = ProfileWorkflow.RoutingLabel(profile) + " · " + (route.Length > 42 ? route[..39] + "…" : route); trayRoute.ToolTipText = route;
        trayCopy!.Enabled = client != null && !string.IsNullOrEmpty(S(profile, "listen")); trayExit!.Enabled = !busy;
    }
    private void DisposeTray()
    {
        if (tray != null) { tray.Visible = false; tray.ContextMenuStrip?.Dispose(); tray.Dispose(); tray = null; }
        trayStoppedIcon?.Dispose(); trayConnectedIcon?.Dispose();
    }
}
