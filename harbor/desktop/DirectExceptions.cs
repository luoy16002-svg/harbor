using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json.Nodes;

namespace Harbor;

internal sealed record DirectExceptionSettings(bool Enabled, string[] Domains, string[] Processes)
{
    public JsonObject ToJson() => new()
    {
        ["enabled"] = Enabled,
        ["domains"] = new JsonArray(Domains.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()),
        ["processes"] = new JsonArray(Processes.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray())
    };
    public string Summary => (Enabled ? "已启用" : "未启用") + $" · {Domains.Length} 个域名 · {Processes.Length} 个进程";
}

internal static class DirectExceptions
{
    // Scoped presets; sources and limitations are in docs/direct-exceptions.md.
    internal static readonly string[] GameDomains = ["mihoyo.com", "miyoushe.com", "mhystatic.com", "yuanshen.com", "genshinimpact.com", "hoyoverse.com", "hoyolab.com", "hoyo.link"];
    internal static readonly string[] GameProcesses = ["YuanShen.exe", "GenshinImpact.exe", "ZFGameBrowser.exe", "HYP.exe", "HYPHelper.exe", "HYUpdater.exe"];
    internal static readonly string[] VideoDomains = ["bilibili.com", "bilibili.cn", "bilibili.net", "b23.tv", "biliapi.com", "biliapi.net", "acgvideo.com", "bilivideo.com", "bilivideo.cn", "bilivideo.net", "hdslb.com", "hdslb.org", "biliimg.com", "bilicdn1.com", "bilicdn2.com", "bilicdn3.com", "bilicdn4.com", "bilicdn5.com"];

    internal static DirectExceptionSettings Read(JsonObject profile)
    {
        if (profile["directExceptions"] == null) return new(false, [], []);
        if (profile["directExceptions"] is not JsonObject value || value.Any(pair => pair.Key is not ("enabled" or "domains" or "processes")))
            throw new FormatException("直连例外配置格式无效。");
        string[] List(string key)
        {
            if (value[key] == null) return [];
            if (value[key] is not JsonArray array || array.Count > 256) throw new FormatException("直连例外列表格式无效或超过 256 项。");
            return array.Select(v => v?.GetValue<string>() ?? throw new FormatException("直连例外不能包含空值。")).ToArray();
        }
        var domains = List("domains"); var processes = List("processes");
        if (domains.Any(v => !ValidDomain(v)) || processes.Any(v => !ValidProcess(v))) throw new FormatException("直连例外中有无效域名或进程名。");
        return new(value["enabled"]?.GetValue<bool>() == true, domains, processes);
    }

    internal static DirectExceptionSettings Parse(bool enabled, string domains, string processes)
    {
        string[] Lines(string text, Func<string, bool> valid, string error, bool domain)
        {
            if (text.Length > 128 * 1024) throw new FormatException("直连例外文本过长。");
            var values = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(v => v.Trim()).Where(v => v.Length > 0).ToArray();
            if (values.Any(v => !valid(v))) throw new FormatException(error);
            values = values.Select(v => domain ? v.TrimEnd('.').ToLowerInvariant() : v).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (values.Length > 256) throw new FormatException("域名和进程列表各支持最多 256 项。");
            return values;
        }
        return new(enabled, Lines(domains, ValidDomain, "每行填写一个纯域名；不要填写网址、IP 或通配符。", true),
            Lines(processes, ValidProcess, "每行填写一个英文可执行文件名，例如 YuanShen.exe；不要填写路径或通配符。", false));
    }

    internal static string Merge(string existing, IEnumerable<string> additions) => string.Join("\n",
        existing.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(v => v.Trim()).Where(v => v.Length > 0).Concat(additions).Distinct(StringComparer.OrdinalIgnoreCase));

    internal static bool ValidDomain(string domain)
    {
        var value = domain.EndsWith('.') ? domain[..^1] : domain;
        return value.Length is > 0 and <= 253 && !IPAddress.TryParse(value, out _) && value.Split('.').All(label =>
            label.Length is > 0 and <= 63 && !label.StartsWith('-') && !label.EndsWith('-') && label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'));
    }
    internal static bool ValidProcess(string value) => value.Length is > 4 and <= 260 && value == value.Trim()
        && value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
        && value.All(c => c <= 127 && !char.IsControl(c) && !"<>:\"/\\|?*".Contains(c));
}
