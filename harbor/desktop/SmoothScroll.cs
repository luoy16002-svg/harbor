using System;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Harbor;
public static class SmoothScroll
{
    private sealed class Motion { public double Target; public long LastInput; }
    private static readonly ConditionalWeakTable<ScrollViewer, Motion> Motions = new();
    public static readonly DependencyProperty EnabledProperty = DependencyProperty.RegisterAttached("Enabled", typeof(bool), typeof(SmoothScroll), new PropertyMetadata(false, Changed));
    private static readonly DependencyProperty OffsetProperty = DependencyProperty.RegisterAttached("Offset", typeof(double), typeof(SmoothScroll), new PropertyMetadata(0.0, (d, e) => ((ScrollViewer)d).ScrollToVerticalOffset((double)e.NewValue)));
    public static bool GetEnabled(DependencyObject value) => (bool)value.GetValue(EnabledProperty);
    public static void SetEnabled(DependencyObject value, bool enabled) => value.SetValue(EnabledProperty, enabled);
    private static void Changed(DependencyObject value, DependencyPropertyChangedEventArgs args)
    {
        if (value is not ScrollViewer viewer) return;
        if ((bool)args.NewValue) { viewer.PreviewMouseWheel += Wheel; viewer.PreviewMouseDown += CancelMouse; viewer.PreviewKeyDown += CancelKey; viewer.Unloaded += CancelUnload; }
        else { viewer.PreviewMouseWheel -= Wheel; viewer.PreviewMouseDown -= CancelMouse; viewer.PreviewKeyDown -= CancelKey; viewer.Unloaded -= CancelUnload; Cancel(viewer); }
    }
    private static void CancelMouse(object sender, MouseButtonEventArgs args) => Cancel((ScrollViewer)sender);
    private static void CancelKey(object sender, KeyEventArgs args) => Cancel((ScrollViewer)sender);
    private static void CancelUnload(object sender, RoutedEventArgs args) => Cancel((ScrollViewer)sender);
    private static void Cancel(ScrollViewer viewer)
    {
        double offset = viewer.VerticalOffset; viewer.BeginAnimation(OffsetProperty, null); viewer.SetCurrentValue(OffsetProperty, offset); Motions.Remove(viewer);
    }
    private static bool LogicalScrolling(DependencyObject root, ScrollViewer viewer)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is ScrollViewer) continue;
            if (child is Panel panel && child is IScrollInfo info && info.ScrollOwner == viewer)
                return panel is not VirtualizingPanel || ItemsControl.GetItemsOwner(panel) is not { } owner || VirtualizingPanel.GetScrollUnit(owner) != ScrollUnit.Pixel;
            if (LogicalScrolling(child, viewer)) return true;
        }
        return false;
    }
    private static void Wheel(object sender, MouseWheelEventArgs args)
    {
        if (args.Handled || !SystemParameters.ClientAreaAnimation || SystemParameters.WheelScrollLines == 0 || Keyboard.Modifiers != ModifierKeys.None) return;
        var viewer = (ScrollViewer)sender;
        if (viewer.CanContentScroll && LogicalScrolling(viewer, viewer)) return;
        DependencyObject? source = args.OriginalSource as DependencyObject;
        while (source != null && source != viewer)
        {
            if (source is ScrollViewer nested && ((args.Delta < 0 && nested.VerticalOffset < nested.ScrollableHeight) || (args.Delta > 0 && nested.VerticalOffset > 0))) return;
            source = source is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(source) : LogicalTreeHelper.GetParent(source);
        }
        if (viewer.ScrollableHeight <= 0 || args.Delta < 0 && viewer.VerticalOffset >= viewer.ScrollableHeight || args.Delta > 0 && viewer.VerticalOffset <= 0) return;
        var motion = Motions.GetOrCreateValue(viewer); long now = Environment.TickCount64;
        if (now - motion.LastInput > 180) motion.Target = viewer.VerticalOffset;
        motion.LastInput = now;
        double step = SystemParameters.WheelScrollLines < 0 ? viewer.ViewportHeight : Math.Max(1, SystemParameters.WheelScrollLines) * 18;
        motion.Target = Math.Clamp(motion.Target - args.Delta / 120.0 * step, 0, viewer.ScrollableHeight);
        double target = motion.Target;
        var animation = new DoubleAnimation(viewer.VerticalOffset, target, TimeSpan.FromMilliseconds(150)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        animation.Completed += (_, _) => { viewer.BeginAnimation(OffsetProperty, null); viewer.SetCurrentValue(OffsetProperty, target); };
        viewer.BeginAnimation(OffsetProperty, animation, HandoffBehavior.SnapshotAndReplace);
        args.Handled = true;
    }
}
