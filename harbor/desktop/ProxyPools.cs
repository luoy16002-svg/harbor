using System;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Security.Cryptography.X509Certificates;

namespace Harbor;

internal sealed record PoolOptions(bool Monitor = true, string CheckUrl = "https://www.example.com/", int CheckIntervalSecs = 120,
    int CheckTimeoutMs = 8000, int ConnectAttempts = 3, int AttemptTimeoutMs = 3000, string CaPem = "")
{
    internal JsonObject ToJson() => new() { ["monitor"] = Monitor, ["checkUrl"] = CheckUrl, ["checkIntervalSecs"] = CheckIntervalSecs,
        ["checkTimeoutMs"] = CheckTimeoutMs, ["connectAttempts"] = ConnectAttempts, ["attemptTimeoutMs"] = AttemptTimeoutMs, ["caPem"] = CaPem };
    internal static PoolOptions Read(JsonNode? node)
    {
        if (node is not JsonObject obj) throw new FormatException("线路池设置格式无效。");
        if (obj.Any(p => p.Key is not ("monitor" or "checkUrl" or "checkIntervalSecs" or "checkTimeoutMs" or "connectAttempts" or "attemptTimeoutMs" or "caPem")))
            throw new FormatException("线路池含有当前版本无法识别的设置。");
        try
        {
            var value = new PoolOptions(obj["monitor"]?.GetValue<bool>() ?? true, obj["checkUrl"]?.GetValue<string>() ?? "https://www.example.com/",
                obj["checkIntervalSecs"]?.GetValue<int>() ?? 120, obj["checkTimeoutMs"]?.GetValue<int>() ?? 8000,
                obj["connectAttempts"]?.GetValue<int>() ?? 3, obj["attemptTimeoutMs"]?.GetValue<int>() ?? 3000, obj["caPem"]?.GetValue<string>() ?? "");
            value.Validate(); return value;
        }
        catch (InvalidOperationException error) { throw new FormatException("线路池设置的数据类型无效。", error); }
    }
    internal void Validate()
    {
        if (CheckUrl.Length is 0 or > 2048 || CheckUrl.Trim() != CheckUrl || CheckUrl.Any(char.IsControl) ||
            !Uri.TryCreate(CheckUrl, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host.Length == 0 || uri.Port == 0 || uri.UserInfo.Length > 0 || uri.Fragment.Length > 0)
            throw new FormatException("检查地址须为完整的 HTTPS URL，不能包含账号密码或片段（#）。");
        if (CheckIntervalSecs is < 30 or > 3600) throw new FormatException("检查间隔须为 30–3600 秒。");
        if (CheckTimeoutMs is < 1000 or > 15000) throw new FormatException("检查超时须为 1000–15000 毫秒。");
        if (ConnectAttempts is < 1 or > 3) throw new FormatException("建连尝试次数须为 1–3 次，包含首次尝试。");
        if (AttemptTimeoutMs is < 500 or > 10000) throw new FormatException("每次建连超时须为 500–10000 毫秒。");
        if (Encoding.UTF8.GetByteCount(CaPem) > 65536) throw new FormatException("检查证书不能超过 64 KiB。");
        if (CaPem.Length > 0)
        {
            var certificates = new X509Certificate2Collection();
            try { certificates.ImportFromPem(CaPem); if (certificates.Count == 0) throw new FormatException("未找到有效的 PEM 证书。"); }
            catch (System.Security.Cryptography.CryptographicException error) { throw new FormatException("检查证书格式无效。", error); }
            finally { foreach (var certificate in certificates) certificate.Dispose(); }
        }
    }
}

internal static class ProxyPools
{
    internal static void Validate(JsonObject profile)
    {
        var groups = profile["groups"] as JsonArray ?? [];
        var pools = groups.Where(g => g?["pool"] != null).ToArray();
        if (pools.Length > 8) throw new FormatException("最多创建 8 个自动线路池。");
        var nodes = (profile["nodes"] as JsonArray ?? []).Select(n => n?["name"]?.GetValue<string>()).ToHashSet(StringComparer.Ordinal);
        int total = 0;
        foreach (var group in pools)
        {
            PoolOptions.Read(group!["pool"]);
            if (group["kind"]?.GetValue<string>() is not ("fallback" or "latency")) throw new FormatException("线路池须使用稳定优先或低延迟优先。");
            if (group["members"] is not JsonArray members || members.Count is 0 or > 128) throw new FormatException("每个线路池须选择 1–128 条线路。");
            var names = members.Select(n => n?.GetValue<string>()).ToArray();
            if (names.Any(n => n is null or "DIRECT" or "REJECT" || !nodes.Contains(n)) || names.Distinct(StringComparer.Ordinal).Count() != names.Length)
                throw new FormatException("线路池只能包含不重复的具体代理线路。");
            total += members.Count;
        }
        if (total > 256) throw new FormatException("所有线路池的成员条目合计不能超过 256。");
    }
    internal static void ValidateName(JsonObject profile, string name, string? previous)
    {
        if (name.Length == 0 || name.Trim() != name || Encoding.UTF8.GetByteCount(name) > 128 || name.Any(char.IsControl) || name is "DIRECT" or "REJECT")
            throw new FormatException("请填写有效的线路池名称（最多 128 字节）。");
        if ((profile["nodes"] as JsonArray ?? []).Concat(profile["groups"] as JsonArray ?? []).Any(n => n?["name"]?.GetValue<string>() == name && name != previous))
            throw new FormatException("此名称已被其他线路或策略组使用。");
    }
}
