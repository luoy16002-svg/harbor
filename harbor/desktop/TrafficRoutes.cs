using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

namespace Harbor;

internal sealed record TrafficRouteSetting(string Name, bool Enabled, string[] Domains, string[] Processes, string? Policy, bool RequireEncryptedProxy)
{
    internal JsonObject ToJson() => new()
    {
        ["name"] = Name, ["enabled"] = Enabled,
        ["domains"] = new JsonArray(Domains.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()),
        ["processes"] = new JsonArray(Processes.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()),
        ["policy"] = Policy, ["requireEncryptedProxy"] = RequireEncryptedProxy
    };
}

internal static class TrafficRoutes
{
    internal static List<TrafficRouteSetting> Read(JsonObject profile)
    {
        if (profile["trafficRoutes"] == null) return [];
        if (profile["trafficRoutes"] is not JsonArray array || array.Count > 64) throw new FormatException("流量路径最多支持 64 条。");
        var routes = new List<TrafficRouteSetting>(); var names = new HashSet<string>(StringComparer.Ordinal);
        var policies = new HashSet<string>(["DIRECT", "REJECT"], StringComparer.Ordinal);
        foreach (string key in new[] { "nodes", "groups" })
            foreach (var item in profile[key] as JsonArray ?? []) if (item?["name"]?.GetValue<string>() is string name) policies.Add(name);
        foreach (var raw in array)
        {
            if (raw is not JsonObject value || value.Any(p => p.Key is not ("name" or "enabled" or "domains" or "processes" or "policy" or "requireEncryptedProxy"))) throw new FormatException("流量路径格式无效。");
            string[] Values(string key) => value[key] == null ? [] : value[key] is JsonArray entries && entries.Count <= 256
                ? entries.Select(v => v?.GetValue<string>() ?? throw new FormatException("流量路径不能包含空值。")).ToArray() : throw new FormatException("每条路径的域名和进程各支持 256 项。");
            var route = new TrafficRouteSetting(value["name"]?.GetValue<string>() ?? "", value["enabled"]?.GetValue<bool>() == true,
                Values("domains"), Values("processes"), value["policy"]?.GetValue<string>(), value["requireEncryptedProxy"]?.GetValue<bool>() == true);
            if (route.Name.Length == 0 || Encoding.UTF8.GetByteCount(route.Name) > 128 || route.Name.Trim() != route.Name || route.Name.Any(char.IsControl) || !names.Add(route.Name)) throw new FormatException("路径名称不能为空、重复或超过 128 字节。");
            if (route.Domains.Length + route.Processes.Length == 0 || route.Domains.Any(v => !DirectExceptions.ValidDomain(v)) || route.Processes.Any(v => !DirectExceptions.ValidProcess(v))) throw new FormatException("请填写有效的域名后缀或进程名。");
            if (route.Policy != null && !policies.Contains(route.Policy)) throw new FormatException("路径引用的出口不存在，请先更换出口。");
            if (route.RequireEncryptedProxy && route.Policy == "DIRECT") throw new FormatException("要求加密代理的路径不能选择直连。");
            routes.Add(route);
        }
        if (routes.Sum(v => v.Domains.Length + v.Processes.Length) > 2048) throw new FormatException("流量路径总共支持 2048 个域名和进程。");
        return routes;
    }

    internal static JsonArray Serialize(IEnumerable<TrafficRouteSetting> routes) => new(routes.Select(v => (JsonNode?)v.ToJson()).ToArray());
    internal static bool Encrypted(JsonNode node, string protocol) => node["kind"]?.GetValue<string>() switch
    {
        "shadowsocks" or "trojan" or "vless" or "vmess" => true,
        "https" => protocol == "tcp",
        "socks5" or "http" => node["tls"]?.GetValue<bool>() == true && protocol == "tcp",
        _ => false
    };
    internal static string PolicyLabel(JsonObject profile, string? policy) => policy == null ? "跟随默认出口 · " + PolicyLabel(profile, profile["finalPolicy"]?.GetValue<string>() ?? "DIRECT") : policy switch
    {
        "DIRECT" => "直连 · 原生网络", "REJECT" => "拦截",
        _ => policy
    };
    internal static string OutboundFacts(JsonObject profile, string policy)
    {
        if (policy == "DIRECT") return "使用原生出口 IP；网站 HTTPS 由应用负责。";
        if (policy == "REJECT") return "连接被拦截，不使用其他出口。";
        var node = (profile["nodes"] as JsonArray ?? []).FirstOrDefault(v => v?["name"]?.GetValue<string>() == policy);
        if (node != null)
        {
            string kind = node["kind"]?.GetValue<string>() ?? "";
            bool tls = node["tls"]?.GetValue<bool>() == true || kind is "https" or "trojan" or "vless";
            string transport = tls ? node["transport"]?.GetValue<string>() == "ws" ? "WSS · 证书验证" : "TLS · 证书验证" : Encrypted(node, "tcp") ? "协议加密" : "无代理层加密";
            string udp = kind is "http" or "https" ? "UDP 不支持" : Encrypted(node, "udp") ? "UDP 加密" : "UDP 无代理层加密";
            return transport + " · " + udp;
        }
        var group = (profile["groups"] as JsonArray ?? []).FirstOrDefault(v => v?["name"]?.GetValue<string>() == policy);
        string member = group?["selected"]?.GetValue<string>() ?? group?["members"]?[0]?.GetValue<string>() ?? "";
        string MemberFacts() => member is "DIRECT" or "REJECT" || (profile["nodes"] as JsonArray ?? []).Any(v => v?["name"]?.GetValue<string>() == member)
            ? OutboundFacts(profile, member) : "成员配置待检查";
        return group?["kind"]?.GetValue<string>() switch
        {
            "select" => "固定成员 · " + member + " · " + MemberFacts(),
            "fallback" => "故障切换 · 尽量保留当前出口，连续探测失败后切换新连接。",
            "latency" => "优选低延迟 · 达到切换门槛后，新连接使用新出口。",
            _ => "出口信息未知"
        };
    }
    internal static string DnsFacts(JsonObject profile) => (profile["dnsTls"] as JsonArray)?.Count > 0
        ? "Harbor DNS 已配置加密，失败不回退明文；查询直达所选 DNS 服务。"
        : "Harbor DNS 使用明文上游。";
    internal static string ExplainReason(string reason) => reason
        .Replace("PATH · ", "路径 · ", StringComparison.Ordinal)
        .Replace("Protection: no healthy encrypted outbound for this transport", "保护要求：没有符合本次传输要求的可选加密出口", StringComparison.Ordinal)
        .Replace("Protection: an encrypted proxy is required for this transport", "保护要求：本次传输必须使用加密代理", StringComparison.Ordinal);
}
