using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace Harbor;
internal static class VisualCheck
{
    // Developer-only rendering of this application's own visual tree. No desktop capture or OS input.
    public static async Task RunAsync(MainWindow window, string directory)
    {
        Directory.CreateDirectory(directory);
        File.Delete(Path.Combine(directory, "visual-check.json"));
        File.Delete(Path.Combine(directory, "visual-error.txt"));
        ((CheckBox)window.FindName("SystemProxy")).IsChecked = false;
        ((CheckBox)window.FindName("MinimizeToTray")).IsChecked = false;
        if (!window.InitializationCompleted) throw new InvalidOperationException("Desktop initialization failed: " + ((TextBlock)window.FindName("NoticeText")).Text);
        ((UIElement)window.FindName("Notice")).Visibility = Visibility.Collapsed;
        var scrollbars = new List<object>(); bool wheelChecked = false;
        window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        Render(window, Path.Combine(directory, "overview-1280.png"));
        var button = (Button)window.FindName("ConnectButton");
        var foreground = button.Foreground as SolidColorBrush; var background = button.Background as SolidColorBrush;
        double contrast = Ratio(foreground!.Color, background!.Color);
        if (contrast < 4.5) throw new InvalidOperationException("Primary button text contrast is insufficient.");
        string[] pages = ["Nodes", "Subscriptions", "Routing", "Dns", "Privacy", "Network", "Diagnostics", "Settings", "Connections"];
        foreach (var page in pages)
        {
            ((Button)window.FindName("Nav" + page)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            foreach (var bar in Descendants<ScrollBar>(window).Where(bar => bar.IsVisible))
            {
                var thumb = Descendants<Thumb>(bar).FirstOrDefault(); double breadth = bar.Orientation == Orientation.Vertical ? bar.ActualWidth : bar.ActualHeight;
                if (breadth > 12.01) throw new InvalidOperationException("Scrollbar exceeds the 12 px hit area.");
                scrollbars.Add(new { page, orientation = bar.Orientation.ToString(), breadth, thumbWidth = thumb?.ActualWidth, thumbHeight = thumb?.ActualHeight });
            }
            Render(window, Path.Combine(directory, page.ToLowerInvariant() + ".png"));
            if (page == "Routing" && SystemParameters.ClientAreaAnimation && SystemParameters.WheelScrollLines != 0)
            {
                var viewer = (ScrollViewer)window.FindName("RoutingPage");
                if (viewer.ScrollableHeight > 0)
                {
                    viewer.ScrollToTop(); window.UpdateLayout();
                    var wheel = new MouseWheelEventArgs(Mouse.PrimaryDevice, Environment.TickCount, -120) { RoutedEvent = Mouse.PreviewMouseWheelEvent };
                    viewer.RaiseEvent(wheel); await Task.Delay(220); window.UpdateLayout();
                    if (!wheel.Handled || viewer.VerticalOffset <= 0 || viewer.VerticalOffset > viewer.ScrollableHeight) throw new InvalidOperationException($"Smooth wheel scrolling did not move within bounds. handled={wheel.Handled} offset={viewer.VerticalOffset} limit={viewer.ScrollableHeight} enabled={SmoothScroll.GetEnabled(viewer)} modifiers={Keyboard.Modifiers}");
                    wheelChecked = true; Render(window, Path.Combine(directory, "routing-scrolled.png")); viewer.ScrollToTop(); window.UpdateLayout();
                }
            }
        }
        foreach (var dialog in new Window[] { window.CreateNodeForm(null), new GroupDialog(window, new[] { "DIRECT", "REJECT" }), new ImportPreview(window, ProfileImport.Parse("trojan://local-fixture@proxy.invalid:443#线路甲\nhysteria2://local-fixture@proxy.invalid:443#待支持线路")) })
        {
            dialog.Show(); dialog.UpdateLayout(); await dialog.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); Render(dialog, Path.Combine(directory, dialog is FormDialog ? "node-editor.png" : dialog is GroupDialog ? "group-editor.png" : "import-preview.png")); dialog.Close();
        }
        ((Button)window.FindName("NavOverview")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        window.Width = 980; window.Height = 700; window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); Render(window, Path.Combine(directory, "overview-980.png"));
        window.Width = 1280; window.Height = 840; window.UpdateLayout();
        var guided = await window.CheckGuidedWorkflowAsync(async () =>
        {
            window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); Render(window, Path.Combine(directory, "overview-configured.png"));
            foreach (string page in new[] { "Nodes", "Routing", "Dns" })
            {
                ((Button)window.FindName("Nav" + page)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); window.UpdateLayout();
                Render(window, Path.Combine(directory, page.ToLowerInvariant() + "-configured.png"));
            }
            ((Button)window.FindName("NavOverview")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        });
        var batch = await window.CheckBatchWorkflowAsync(async () =>
        {
            window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            Render(window, Path.Combine(directory, "nodes-batch-1280.png"));
            window.Width = 980; window.Height = 700; window.UpdateLayout();
            await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            Render(window, Path.Combine(directory, "nodes-batch-980.png"));
            window.Width = 1280; window.Height = 840; window.UpdateLayout();
        });
        var subscriptions = await window.CheckSubscriptionWorkflowAsync(async (surface, name) =>
        {
            surface.UpdateLayout(); await surface.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            Render(surface, Path.Combine(directory, name + ".png"));
        });
        var routing = await window.CheckRoutingWorkflowAsync(async (surface, name) =>
        {
            surface.UpdateLayout(); await surface.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            Render(surface, Path.Combine(directory, name + ".png"));
        });
        var history = await window.CheckHistoryWorkflowAsync(async (surface, name) =>
        {
            surface.UpdateLayout(); await surface.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
            Render(surface, Path.Combine(directory, name + ".png"));
        });
        var traffic = await window.CheckLoopbackTrafficAsync(async () =>
        {
            window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); Render(window, Path.Combine(directory, "overview-live.png"));
            ((Button)window.FindName("NavConnections")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            window.UpdateLayout(); Render(window, Path.Combine(directory, "connections-live.png"));
            ((Button)window.FindName("NavOverview")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            window.Width = 980; window.Height = 700; window.UpdateLayout(); await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle); window.UpdateLayout(); Render(window, Path.Combine(directory, "overview-live-980.png"));
            window.Width = 1280; window.Height = 840;
        });
        string assemblyHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(typeof(VisualCheck).Assembly.Location)));
        File.WriteAllText(Path.Combine(directory, "visual-check.json"), JsonSerializer.Serialize(new { checkedAt = DateTimeOffset.UtcNow, passed = true, applicationSha256 = assemblyHash, primaryButtonContrast = contrast, primaryText = foreground.Color.ToString(), primaryBackground = background.Color.ToString(), navigation = "vector paths; CJK text uses Microsoft YaHei UI", pages = pages.Length + 1, scrollbars, wheelChecked, guided, batch, subscriptions, routing, history, traffic }, Storage.Json));
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i); if (child is T value) yield return value;
            foreach (var descendant in Descendants<T>(child)) yield return descendant;
        }
    }
    private static double Ratio(Color a, Color b)
    {
        double L(Color c) { double Channel(byte v) { double s = v / 255.0; return s <= 0.04045 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4); } return .2126 * Channel(c.R) + .7152 * Channel(c.G) + .0722 * Channel(c.B); }
        double x = L(a), y = L(b); return (Math.Max(x, y) + .05) / (Math.Min(x, y) + .05);
    }
    private static void Render(Window window, string path)
    {
        var content = (FrameworkElement)window.Content; double width = Math.Ceiling(content.ActualWidth + content.Margin.Left + content.Margin.Right), height = Math.Ceiling(content.ActualHeight + content.Margin.Top + content.Margin.Bottom);
        var bitmap = new RenderTargetBitmap((int)width, (int)height, 96, 96, PixelFormats.Pbgra32); var background = new DrawingVisual(); using (var drawing = background.RenderOpen()) drawing.DrawRectangle(window.Background, null, new Rect(0, 0, width, height)); bitmap.Render(background); bitmap.Render(content);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap)); using var stream = File.Create(path); encoder.Save(stream);
    }
}
