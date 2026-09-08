using System;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace Harbor;

public sealed class PoolTrend : FrameworkElement
{
    public static readonly DependencyProperty SamplesProperty = DependencyProperty.Register(nameof(Samples), typeof(object), typeof(PoolTrend), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public object? Samples { get => GetValue(SamplesProperty); set => SetValue(SamplesProperty, value); }
    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc); var samples = Samples as double?[] ?? [];
        double width = ActualWidth, height = ActualHeight; if (width < 1 || height < 1) return;
        var baseline = new Pen(new SolidColorBrush(Color.FromRgb(218, 227, 221)), 1);
        dc.DrawLine(baseline, new Point(0, height - 2), new Point(width, height - 2));
        if (samples.Length == 0) return;
        double max = Math.Max(1, samples.Max(v => v ?? 0)); double step = width / 20;
        for (int i = 0; i < samples.Length && i < 20; i++)
        {
            double x = i * step + step / 2;
            if (samples[i] is double value)
                dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromRgb(68, 137, 108)), null, new Rect(x - 1.5, height - 2 - Math.Max(3, (height - 5) * value / max), 3, Math.Max(3, (height - 5) * value / max)), 1, 1);
            else dc.DrawEllipse(new SolidColorBrush(Color.FromRgb(185, 99, 75)), null, new Point(x, height / 2), 2, 2);
        }
    }
}
