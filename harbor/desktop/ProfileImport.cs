using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.RepresentationModel;

namespace Harbor;

internal sealed record ImportIssue(int Position, string Name, string Reason);
internal sealed record ImportResult(JsonArray Nodes, List<ImportIssue> Issues, string Format);

internal static class ProfileImport
{
    public const int MaximumBytes = 2 * 1024 * 1024;
    private static readonly HashSet<string> UsableKinds = new(StringComparer.OrdinalIgnoreCase) { "http", "https", "socks5", "trojan", "shadowsocks", "vless", "vmess" };
    public static ImportResult Parse(string input)
    {
        if (Encoding.UTF8.GetByteCount(input) > MaximumBytes) throw new FormatException("订阅超过 2 MiB。");
        input = input.Trim().TrimStart('\uFEFF');
        if (input.Length == 0) throw new FormatException("订阅内容为空。");
        var nodes = new JsonArray(); var issues = new List<ImportIssue>(); string format;
        void Add(int position, string name, Func<JsonObject> read)
        {
            try
            {
                var node = read(); ValidateNode(node);
                string original = Text(node, "name"); string unique = original; int suffix = 2;
                while (nodes.Any(n => Text(n!, "name") == unique) || unique is "DIRECT" or "REJECT") unique = original + " (" + suffix++ + ")";
                node["name"] = unique; nodes.Add(node);
            }
            catch (Exception e) when (e is FormatException or JsonException or ArgumentException or OverflowException or InvalidOperationException)
            { issues.Add(new ImportIssue(position, SafeName(name), e is JsonException ? "节点 JSON 无效。" : e.Message)); }
        }
        if (input.StartsWith('{') || input.StartsWith('['))
        {
            JsonNode root;
            try { root = JsonNode.Parse(input, documentOptions: new JsonDocumentOptions { MaxDepth = 32 }) ?? throw new FormatException("空 JSON。"); }
            catch (JsonException) { throw new FormatException("订阅 JSON 无效。"); }
            if (root is JsonObject obj && obj["nodes"] is JsonArray harbor)
            { format = "Harbor JSON"; int i = 0; foreach (var node in harbor) { var captured = node; Add(++i, Text(node!, "name"), () => captured!.DeepClone().AsObject()); } }
            else
            {
                var servers = root as JsonArray ?? (root as JsonObject)?["servers"] as JsonArray;
                if (servers == null) throw new FormatException("无法识别 JSON 订阅结构。");
                format = "Shadowsocks SIP008"; int i = 0;
                foreach (var node in servers)
                {
                    var item = node!; Add(++i, Text(item, "remarks"), () =>
                    {
                        if (!string.IsNullOrEmpty(Text(item, "plugin"))) throw new FormatException("此节点需要 Shadowsocks 插件，当前未启用该传输。");
                        return Make(Text(item, "remarks"), "shadowsocks", Text(item, "server"), Integer(item, "server_port"), Text(item, "password"), cipher: Text(item, "method"));
                    });
                }
            }
        }
        else if (input.Contains("proxies:", StringComparison.Ordinal) || input.StartsWith("- name:"))
        {
            format = "Clash YAML"; try { GuardYaml(input); } catch (YamlException) { throw new FormatException("订阅 YAML 无效。"); }
            var yaml = new YamlStream();
            try { yaml.Load(new StringReader(input)); } catch (YamlException) { throw new FormatException("订阅 YAML 无效。"); }
            if (yaml.Documents.Count != 1) throw new FormatException("仅接受单个 YAML 文档。");
            var root = yaml.Documents[0].RootNode;
            var sequence = root as YamlSequenceNode ?? (root is YamlMappingNode map && map.Children.TryGetValue(new YamlScalarNode("proxies"), out var proxies) ? proxies as YamlSequenceNode : null);
            if (sequence == null) throw new FormatException("YAML 中没有 proxies 数组。");
            int i = 0; foreach (var entry in sequence) { var captured = entry; Add(++i, entry is YamlMappingNode m ? Y(m, "name") : "", () => FromClash(captured as YamlMappingNode ?? throw new FormatException("节点必须是映射。"))); }
        }
        else
        {
            format = "分享链接";
            if (!input.Contains("://", StringComparison.Ordinal)) { input = Decode(input); format = "Base64 分享链接订阅"; }
            var lines = input.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (lines.Length > 2048) throw new FormatException("订阅节点数超过 2048。");
            int i = 0; foreach (var line in lines) { if (line.StartsWith('#')) continue; var captured = line; Add(++i, "第 " + i + " 项", () => FromLink(captured)); }
        }
        if (nodes.Count + issues.Count > 2048) throw new FormatException("订阅节点数超过 2048。");
        if (nodes.Count == 0 && issues.Count == 0) throw new FormatException("订阅中没有节点。");
        return new ImportResult(nodes, issues, format);
    }
    public static JsonArray Nodes(string input) { var result = Parse(input); if (result.Issues.Count > 0) throw new FormatException($"{result.Issues.Count} 项无法使用：{result.Issues[0].Reason}"); return result.Nodes; }
    private static void GuardYaml(string input)
    {
        var parser = new Parser(new StringReader(input)); int count = 0, depth = 0;
        while (parser.MoveNext())
        {
            if (++count > 60000) throw new FormatException("YAML 结构过大。");
            if (parser.Current is AnchorAlias) throw new FormatException("订阅不接受 YAML 别名引用。");
            if (parser.Current is SequenceStart or MappingStart && ++depth > 24) throw new FormatException("YAML 嵌套过深。");
            if (parser.Current is SequenceEnd or MappingEnd) depth--;
        }
    }
    private static JsonObject FromClash(YamlMappingNode node)
    {
        string kind = Y(node, "type") switch { "ss" => "shadowsocks", "hy2" => "hysteria2", var value => value };
        if (!UsableKinds.Contains(kind)) throw new FormatException($"已识别 {kind}，当前引擎尚不支持此协议。");
        foreach (string option in new[] { "plugin", "reality-opts", "flow", "smux", "dialer-proxy", "grpc-opts", "h2-opts", "http-opts", "packet-encoding", "client-fingerprint", "fingerprint", "alpn", "interface-name", "routing-mark", "ip-version", "certificate", "private-key", "encryption" })
            if (node.Children.TryGetValue(new YamlScalarNode(option), out var v) && v.ToString() is not ("" or "false")) throw new FormatException($"需要尚未支持的 {option} 参数。");
        if (Y(node, "skip-cert-verify").Equals("true", StringComparison.OrdinalIgnoreCase)) throw new FormatException("节点要求跳过证书校验，已拒绝降级。");
        if (kind == "vmess" && Y(node, "alterId", "0") != "0") throw new FormatException("仅支持 VMess AEAD（alterId=0）。");
        string network = Y(node, "network", "tcp"); if (network is not ("tcp" or "ws")) throw new FormatException($"已识别 {network} 传输，当前尚不支持。");
        bool tls = kind is "trojan" or "https" || Y(node, "tls").Equals("true", StringComparison.OrdinalIgnoreCase);
        var output = Make(Y(node, "name"), kind, Y(node, "server"), int.Parse(Y(node, "port"), CultureInfo.InvariantCulture), Y(node, "password"), Y(node, "username"), Y(node, "cipher", "chacha20-ietf-poly1305"));
        output["uuid"] = Y(node, "uuid"); output["tls"] = tls; output["tlsServerName"] = Y(node, "servername", Y(node, "sni")); output["transport"] = network;
        output["security"] = Y(node, "cipher", "auto");
        if (node.Children.TryGetValue(new YamlScalarNode("ws-opts"), out var ws) && ws is YamlMappingNode options)
        {
            if (Y(options, "max-early-data", "0") != "0") throw new FormatException("WebSocket early data 暂不支持。");
            output["wsPath"] = Y(options, "path", "/");
            if (options.Children.TryGetValue(new YamlScalarNode("headers"), out var headers) && headers is YamlMappingNode hm)
            { foreach (var key in hm.Children.Keys) if (key.ToString() != "Host") throw new FormatException("WebSocket 暂只支持 Host 自定义头。"); output["wsHost"] = Y(hm, "Host"); }
        }
        return output;
    }
    private static JsonObject FromLink(string line)
    {
        if (line.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            JsonNode obj = JsonNode.Parse(Decode(line[8..])) ?? throw new FormatException("无效 VMess 链接。");
            if (Text(obj, "allowInsecure").ToLowerInvariant() is "1" or "true") throw new FormatException("节点要求跳过证书校验，已拒绝降级。");
            if (Text(obj, "alpn").Length > 0 || Text(obj, "fp").Length > 0) throw new FormatException("自定义 ALPN / TLS 指纹尚不支持。");
            if (Text(obj, "tls") is not ("" or "tls")) throw new FormatException("VMess TLS 扩展尚不支持。");
            if (Text(obj, "aid", "0") != "0") throw new FormatException("仅支持 VMess AEAD（alterId=0）。");
            string vmNetwork = Text(obj, "net", "tcp"); if (vmNetwork is not ("tcp" or "ws")) throw new FormatException($"VMess {vmNetwork} 传输暂不支持。");
            if (Text(obj, "type", "none") != "none") throw new FormatException("VMess TCP 伪装头暂不支持。");
            var node = Make(Text(obj, "ps"), "vmess", Text(obj, "add"), Integer(obj, "port")); node["uuid"] = Text(obj, "id"); node["tls"] = Text(obj, "tls") == "tls"; node["tlsServerName"] = Text(obj, "sni"); node["transport"] = vmNetwork; node["wsPath"] = Text(obj, "path", "/"); node["wsHost"] = Text(obj, "host"); node["security"] = Text(obj, "scy", "auto"); return node;
        }
        if (line.StartsWith("ss://", StringComparison.OrdinalIgnoreCase) && !line[5..].Split('#')[0].Contains('@'))
        { var parts = line[5..].Split('#', 2); line = "ss://" + Decode(parts[0]) + (parts.Length > 1 ? "#" + parts[1] : ""); }
        if (!Uri.TryCreate(line, UriKind.Absolute, out var uri)) throw new FormatException("无效分享链接。");
        string kind = uri.Scheme switch { "ss" => "shadowsocks", "socks" => "socks5", "hy2" => "hysteria2", var value => value };
        if (!UsableKinds.Contains(kind)) throw new FormatException($"已识别 {kind}，当前引擎尚不支持此协议。");
        var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)) { var pair = field.Split('=', 2); if (!query.TryAdd(Uri.UnescapeDataString(pair[0]), pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "")) throw new FormatException("分享链接包含重复参数。"); }
        string security = query.GetValueOrDefault("security") ?? (kind == "vless" ? "none" : "tls");
        if (security == "reality" || query.ContainsKey("pbk")) throw new FormatException("已识别 VLESS REALITY，当前未实现该握手，不能当普通 TLS 导入。");
        if (query.GetValueOrDefault("allowInsecure") is "1" or "true" || query.GetValueOrDefault("insecure") is "1" or "true") throw new FormatException("节点要求跳过证书校验，已拒绝降级。");
        if (query.GetValueOrDefault("flow") is { Length: > 0 }) throw new FormatException("VLESS Vision flow 暂不支持。");
        string network = query.GetValueOrDefault("type") ?? "tcp"; if (network is not ("tcp" or "ws")) throw new FormatException($"已识别 {network} 传输，当前尚不支持。");
        var accepted = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "sni", "peer", "allowInsecure", "insecure", "security", "type", "path", "host", "encryption", "flow" };
        foreach (string key in query.Keys) if (!accepted.Contains(key)) throw new FormatException($"分享链接参数 {SafeName(key)} 暂不支持。");
        string user = Uri.UnescapeDataString(uri.UserInfo), username = "", password = "", cipher = "chacha20-ietf-poly1305", uuid = "";
        if (kind == "shadowsocks") { if (!user.Contains(':')) user = Decode(user); var pair = user.Split(':', 2); if (pair.Length != 2) throw new FormatException("Shadowsocks 凭据无效。"); cipher = pair[0]; password = pair[1]; }
        else if (kind == "trojan") password = user;
        else if (kind == "vless") { uuid = user; if (query.GetValueOrDefault("encryption") is { } enc && enc != "none") throw new FormatException("VLESS encryption 扩展暂不支持。"); }
        else { var pair = user.Split(':', 2); username = pair[0]; if (pair.Length == 2) password = pair[1]; }
        int port = uri.Port; if (port < 1) port = kind switch { "trojan" or "vless" => 443, "socks5" => 1080, _ => throw new FormatException("节点缺少端口。") };
        var result = Make(Uri.UnescapeDataString(uri.Fragment.TrimStart('#')), kind, uri.Host.Trim('[', ']'), port, password, username, cipher);
        result["uuid"] = uuid; result["tls"] = kind is "trojan" or "https" || kind == "vless" && security == "tls"; result["tlsServerName"] = query.GetValueOrDefault("sni") ?? query.GetValueOrDefault("peer") ?? ""; result["transport"] = network; result["wsPath"] = query.GetValueOrDefault("path") ?? "/"; result["wsHost"] = query.GetValueOrDefault("host") ?? ""; return result;
    }
    private static JsonObject Make(string name, string kind, string server, int port, string password = "", string username = "", string cipher = "chacha20-ietf-poly1305") => new() { { "name", string.IsNullOrWhiteSpace(name) ? server + ":" + port : name }, { "kind", kind }, { "server", server }, { "port", port }, { "password", password }, { "username", username }, { "cipher", cipher }, { "tlsServerName", "" }, { "uuid", "" }, { "tls", kind is "trojan" or "https" }, { "transport", "tcp" }, { "wsPath", "/" }, { "wsHost", "" }, { "security", "auto" } };
    private static void ValidateNode(JsonObject node)
    {
        string kind = Text(node, "kind"); if (!UsableKinds.Contains(kind)) throw new FormatException($"当前不支持 {SafeName(kind)}。");
        if (string.IsNullOrWhiteSpace(Text(node, "server")) || Integer(node, "port") is < 1 or > 65535) throw new FormatException("服务器或端口无效。");
        if (kind is "vless" or "vmess" && !Guid.TryParse(Text(node, "uuid"), out _)) throw new FormatException("UUID 无效。");
        if (kind == "shadowsocks" && Text(node, "cipher") is not ("aes-128-gcm" or "aes-256-gcm" or "chacha20-ietf-poly1305" or "2022-blake3-aes-128-gcm" or "2022-blake3-aes-256-gcm")) throw new FormatException("该 Shadowsocks 加密方法尚未实现。");
        if (kind == "shadowsocks" && Text(node, "cipher").StartsWith("2022-", StringComparison.Ordinal))
        {
            if (Text(node, "password").Contains(':')) throw new FormatException("SS2022 EIH 多级身份密钥暂不支持。");
            int expected = Text(node, "cipher").Contains("128", StringComparison.Ordinal) ? 16 : 32;
            byte[] key; try { key = Convert.FromBase64String(Text(node, "password")); } catch (FormatException) { throw new FormatException("SS2022 需要 Base64 格式的随机 PSK。"); }
            try { if (key.Length != expected) throw new FormatException($"SS2022 PSK 需要 {expected} 字节。"); } finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(key); }
        }
        if (kind is "trojan" or "shadowsocks" && string.IsNullOrEmpty(Text(node, "password"))) throw new FormatException("节点缺少密码。");
        if (kind == "vless" && node["tls"]?.GetValue<bool>() != true) throw new FormatException("VLESS 本身不加密，当前只允许经过证书验证的 TLS。");
        if (kind == "vmess" && Text(node, "security", "auto") is not ("auto" or "aes-128-gcm" or "chacha20-poly1305")) throw new FormatException("仅允许 VMess AEAD 加密，拒绝 none/zero 降级。");
        if (Text(node, "transport", "tcp") == "ws" && kind is not ("vless" or "vmess" or "trojan")) throw new FormatException("此协议不支持 WebSocket 封装。");
    }
    private static string Text(JsonNode node, string key, string fallback = "") { var value = node[key]; return value == null ? fallback : value is JsonValue j && j.TryGetValue<string>(out var text) ? text : value.ToJsonString(); }
    private static int Integer(JsonNode node, string key) => int.Parse(Text(node, key), CultureInfo.InvariantCulture);
    private static string Y(YamlMappingNode node, string key, string fallback = "") => node.Children.TryGetValue(new YamlScalarNode(key), out var value) ? value is YamlScalarNode scalar ? scalar.Value ?? fallback : throw new FormatException($"{key} 应为标量。") : fallback;
    private static string SafeName(string value) => new(value.Where(c => !char.IsControl(c)).Take(80).ToArray());
    private static string Decode(string text)
    {
        try { text = string.Concat(text.Where(c => !char.IsWhiteSpace(c))).Replace('-', '+').Replace('_', '/'); if (text.Length > MaximumBytes * 2) throw new FormatException(); return new UTF8Encoding(false, true).GetString(Convert.FromBase64String(text.PadRight((text.Length + 3) / 4 * 4, '='))); }
        catch (Exception e) when (e is FormatException or DecoderFallbackException) { throw new FormatException("订阅 Base64 或 UTF-8 编码无效。"); }
    }
}
