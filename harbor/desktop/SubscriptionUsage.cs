using System;
using System.Collections.Generic;
using System.Globalization;

namespace Harbor;

internal sealed record SubscriptionUsage(ulong Upload, ulong Download, ulong Total, DateTimeOffset? ExpiresAt, DateTimeOffset RecordedAt)
{
    internal decimal Used => (decimal)Upload + Download;
    internal double Percent => Total == 0 ? 0 : (double)Math.Clamp(Used * 100 / Total, 0, 100);
    internal string Summary => FormatBytes(Used) + (Total > 0 ? " / " + FormatBytes(Total) : " · 额度未提供");
    internal string Remaining => Total == 0 ? "服务商未提供有效总额度" : Used >= Total ? "用量已达到服务商额度" : "剩余 " + FormatBytes(Total - Used);
    internal string Expiry(DateTimeOffset now) => ExpiresAt is not { } expires ? "未提供到期时间" :
        (expires <= now ? "已到期 · " : expires <= now.AddDays(7) ? $"{Math.Max(1, Math.Ceiling((expires - now).TotalDays))} 天后到期 · " : "到期 ") + expires.ToLocalTime().ToString("yyyy-MM-dd");
    internal string Detail => $"服务商提供于 {RecordedAt.ToLocalTime():yyyy-MM-dd HH:mm}\n上传 {FormatBytes(Upload)} · 下载 {FormatBytes(Download)}\n服务商统计可能延迟，与 Harbor 本机流量计数独立。";

    internal static SubscriptionUsage? Parse(string? header, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(header) || header.Length > 2048) return null;
        var values = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        string[] fields = header.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length > 16) return null;
        foreach (string field in fields)
        {
            int separator = field.IndexOf('=');
            if (separator <= 0) return null;
            string key = field[..separator].Trim();
            if (!key.Equals("upload", StringComparison.OrdinalIgnoreCase) && !key.Equals("download", StringComparison.OrdinalIgnoreCase) &&
                !key.Equals("total", StringComparison.OrdinalIgnoreCase) && !key.Equals("expire", StringComparison.OrdinalIgnoreCase)) continue;
            if (!ulong.TryParse(field[(separator + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out ulong value) || !values.TryAdd(key, value)) return null;
        }
        if (!values.TryGetValue("upload", out ulong upload) || !values.TryGetValue("download", out ulong download) || !values.TryGetValue("total", out ulong total)) return null;
        DateTimeOffset? expires = null;
        if (values.TryGetValue("expire", out ulong epoch) && epoch != 0)
        {
            // Unix timestamps outside DateTimeOffset's range are not valid metadata.
            if (epoch > 253402300799) return null;
            expires = DateTimeOffset.FromUnixTimeSeconds((long)epoch);
        }
        return new(upload, download, total, expires, now);
    }

    internal static string FormatBytes(decimal value)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return value.ToString(unit == 0 ? "0" : "0.##", CultureInfo.InvariantCulture) + " " + units[unit];
    }
}
