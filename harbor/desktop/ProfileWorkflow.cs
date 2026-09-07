using System;
using System.Linq;
using System.Text.Json.Nodes;

namespace Harbor;

// Shared by the guided importer and manual editor; existing routing choices are preserved.
internal static class ProfileWorkflow
{
    public static readonly (string Key, string Label)[] RoutingModes =
    [("rules", "按规则"), ("global", "统一出口"), ("direct", "全部直连")];
    public static string RoutingMode(JsonObject profile) => profile["routingMode"]?.GetValue<string>() ?? "rules";
    public static string RoutingLabel(JsonObject profile) => RoutingModes.First(v => v.Key == RoutingMode(profile)).Label;
    public static string RoutingKey(string label) => RoutingModes.First(v => v.Label == label).Key;
    public static bool NeedsFirstNode(JsonObject profile) => (profile["nodes"] as JsonArray)?.Count == 0 && RoutingMode(profile) != "direct";

    public static bool SelectFirstImport(JsonObject before, JsonObject after)
    {
        if ((before["nodes"] as JsonArray)?.Count != 0 || before["finalPolicy"]?.GetValue<string>() != "DIRECT") return false;
        string? first = (after["nodes"] as JsonArray)?.FirstOrDefault()?["name"]?.GetValue<string>();
        if (first == null) return false;
        after["finalPolicy"] = first;
        return true;
    }

    public static readonly (string Key, string Label)[] RuleKinds =
    [ ("domain_suffix", "域名及子域名"), ("domain", "完整域名"), ("domain_keyword", "域名包含"),
      ("ip_cidr", "IP 网段"), ("port", "目标端口"), ("protocol", "TCP / UDP") ];
    public static string RuleLabel(string key) => RuleKinds.FirstOrDefault(v => v.Key == key).Label ?? key;
    public static string RuleKey(string label) => RuleKinds.First(v => v.Label == label).Key;

    public static string DnsPreset(JsonObject profile)
    {
        var tls = profile["dnsTls"] as JsonArray;
        if (tls?.Count is 1 or 2 && tls.All(v => v?["caPem"] == null || string.IsNullOrEmpty(v["caPem"]?.GetValue<string>())))
        {
            if (tls.Count == 2 && tls.All(v => v?["httpsPath"]?.GetValue<string>() == "/dns-query") &&
                tls[0]?["address"]?.GetValue<string>() == "223.5.5.5:443" && tls[0]?["serverName"]?.GetValue<string>() == "dns.alidns.com" &&
                tls[1]?["address"]?.GetValue<string>() == "1.1.1.1:443" && tls[1]?["serverName"]?.GetValue<string>() == "cloudflare-dns.com") return "自动 · 加密解析";
            bool Match(string a, string b, string name, bool https) => tls.All(v => v?["serverName"]?.GetValue<string>() == name &&
                (https ? v?["httpsPath"]?.GetValue<string>() == "/dns-query" : v?["httpsPath"] == null)) &&
                tls.Select(v => v!["address"]!.GetValue<string>()).Order().SequenceEqual((tls.Count == 1 ? new[] { a } : new[] { a, b }).Order());
            if (Match("1.1.1.1:443", "1.0.0.1:443", "cloudflare-dns.com", true) || Match("1.1.1.1:853", "1.0.0.1:853", "cloudflare-dns.com", false)) return "Cloudflare · 加密解析";
            if (Match("94.140.14.14:443", "94.140.15.15:443", "dns.adguard-dns.com", true) || Match("94.140.14.14:853", "94.140.15.15:853", "dns.adguard-dns.com", false)) return "AdGuard · 广告与追踪过滤";
            if (Match("223.5.5.5:443", "223.6.6.6:443", "dns.alidns.com", true)) return "阿里 DNS · 加密解析";
        }
        return "自定义";
    }

    public static void ApplyDnsPreset(JsonObject profile, string preset)
    {
        string[] addresses; string name;
        switch (preset)
        {
            case "自动 · 加密解析":
                profile["dnsTls"] = new JsonArray(
                    new JsonObject { ["address"] = "223.5.5.5:443", ["serverName"] = "dns.alidns.com", ["httpsPath"] = "/dns-query" },
                    new JsonObject { ["address"] = "1.1.1.1:443", ["serverName"] = "cloudflare-dns.com", ["httpsPath"] = "/dns-query" });
                return;
            case "阿里 DNS · 加密解析": addresses = ["223.5.5.5:443", "223.6.6.6:443"]; name = "dns.alidns.com"; break;
            case "Cloudflare · 加密解析": addresses = ["1.1.1.1:443", "1.0.0.1:443"]; name = "cloudflare-dns.com"; break;
            case "AdGuard · 广告与追踪过滤": addresses = ["94.140.14.14:443", "94.140.15.15:443"]; name = "dns.adguard-dns.com"; break;
            default: throw new ArgumentException("请选择 DNS 服务。");
        }
        profile["dnsTls"] = new JsonArray(addresses.Select(address => (JsonNode)new JsonObject { ["address"] = address, ["serverName"] = name, ["httpsPath"] = "/dns-query" }).ToArray());
    }

    public static bool UpgradeDefaultDns(JsonObject profile)
    {
        if (DnsPreset(profile) != "Cloudflare · 加密解析" || profile["dnsTls"]![0]?["httpsPath"] != null) return false;
        ApplyDnsPreset(profile, "自动 · 加密解析");
        return true;
    }

    public static bool UpgradeEgress(JsonObject profile)
    {
        if (profile["egressMode"] != null) return false;
        profile["egressMode"] = "physical";
        return true;
    }

    public static string DnsEndpointText(JsonNode server) => server["address"]!.GetValue<string>() + " " + server["serverName"]!.GetValue<string>() +
        (server["httpsPath"] is JsonValue path ? " " + path.GetValue<string>() : "");

    public static JsonArray ParseDnsEndpoints(string text, JsonArray? previous)
    {
        var endpoints = new JsonArray();
        foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length is not (2 or 3)) throw new FormatException("每行填写 IP:端口、TLS 服务器名；使用 DoH 时再填写 /dns-query 等 HTTPS 路径。");
            string? path = parts.Length == 3 ? parts[2] : null;
            var existing = previous?.FirstOrDefault(v => v?["address"]?.GetValue<string>() == parts[0] && v?["serverName"]?.GetValue<string>() == parts[1] && v?["httpsPath"]?.GetValue<string>() == path);
            var endpoint = existing?.DeepClone().AsObject() ?? new JsonObject { ["address"] = parts[0], ["serverName"] = parts[1] };
            if (path != null) endpoint["httpsPath"] = path;
            endpoints.Add(endpoint);
        }
        if (endpoints.Count == 0) throw new FormatException("请至少填写一个加密 DNS 服务。");
        return endpoints;
    }
}
