using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

namespace Harbor;
public sealed class TrafficChart : FrameworkElement
{
    private readonly List<(long Time, double Down, double Up)> points = new();
    public int WindowSeconds { get; set; } = 90;
    public void Clear() { points.Clear(); InvalidateVisual(); }
    public void Push(double down, double up) { long now = Environment.TickCount64; points.Add((now, down, up)); points.RemoveAll(p => now - p.Time > Math.Max(10, WindowSeconds) * 1000); InvalidateVisual(); }
    protected override void OnRender(DrawingContext drawing)
    {
        base.OnRender(drawing); double width = ActualWidth, height = ActualHeight - 24;
        if (width < 20 || height < 20) return;
        var grid = new Pen(new SolidColorBrush(Color.FromRgb(234, 239, 238)), 1);
        for (int i = 0; i <= 3; i++) drawing.DrawLine(grid, new Point(0, i * height / 3), new Point(width, i * height / 3));
        double max = 1024; foreach (var p in points) max = Math.Max(max, Math.Max(p.Down, p.Up) * 1.2);
        var blue = new SolidColorBrush(Color.FromRgb(57, 122, 170)); var green = new SolidColorBrush(Color.FromRgb(87, 155, 133));
        void Line(bool download, Brush brush)
        {
            if (points.Count < 2) return;
            long now = points[^1].Time;
            Point At(int i) => new(Math.Clamp(1 - (now - points[i].Time) / (Math.Max(10, WindowSeconds) * 1000.0), 0, 1) * width, height - (download ? points[i].Down : points[i].Up) / max * height);
            var area = new StreamGeometry(); using (var context = area.Open())
            { context.BeginFigure(new Point(At(0).X, height), true, true); for (int i = 0; i < points.Count; i++) context.LineTo(At(i), true, false); context.LineTo(new Point(At(points.Count - 1).X, height), true, false); }
            area.Freeze(); drawing.PushOpacity(download ? .08 : .04); drawing.DrawGeometry(brush, null, area); drawing.Pop();
            var geometry = new StreamGeometry(); using (var context = geometry.Open())
            { for (int i = 0; i < points.Count; i++) { if (i == 0) context.BeginFigure(At(i), false, false); else context.LineTo(At(i), true, false); } }
            geometry.Freeze(); drawing.DrawGeometry(null, new Pen(brush, 1.8), geometry);
        }
        Line(true, blue); Line(false, green);
        var text = new FormattedText($"过去 {Math.Max(10, WindowSeconds)} 秒", System.Globalization.CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Microsoft YaHei UI"), 11, new SolidColorBrush(Color.FromRgb(128, 139, 142)), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        drawing.DrawText(text, new Point(0, height + 9));
        var scale = new FormattedText(Format.Bytes(max) + "/s", System.Globalization.CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Microsoft YaHei UI"), 11, new SolidColorBrush(Color.FromRgb(128, 139, 142)), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        drawing.DrawText(scale, new Point(width - scale.Width, height + 9));
    }
}
internal static class Format
{
    public static string Bytes(double value) { string[] units = ["B", "KB", "MB", "GB", "TB"]; int i = 0; while (value >= 1024 && i < units.Length - 1) { value /= 1024; i++; } return $"{value:0.#} {units[i]}"; }
}
