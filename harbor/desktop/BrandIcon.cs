using System;
using System.Drawing;
using System.Windows;

namespace Harbor;

internal static class BrandIcon
{
    internal static Icon Load(string name)
    {
        var resource = Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{name}.ico"))
            ?? throw new InvalidOperationException("缺少 Harbor 图标资源。");
        using var stream = resource.Stream;
        using var source = new Icon(stream, System.Windows.Forms.SystemInformation.SmallIconSize);
        return (Icon)source.Clone();
    }
}
