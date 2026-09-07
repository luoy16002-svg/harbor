using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Harbor;

internal sealed record LineCheck(string Name, string Fingerprint, bool Success, ulong ElapsedMs, DateTimeOffset CheckedAt, string Failure)
{
    public bool Fresh(DateTimeOffset now) => CheckedAt <= now.AddMinutes(5) && CheckedAt >= now.AddHours(-24);
    public string Summary(DateTimeOffset now) => (Success ? $"上次成功 · {ElapsedMs} ms" : "上次未通过 · " + Failure) + (Fresh(now) ? "" : " · 需复测");
    public string Detail => $"{CheckedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss} · www.example.com HTTPS\n" +
        (Success ? "当时成功建立代理隧道、通过目标证书验证并收到 HTTP 响应。耗时包含整个过程，不是下载速度。" : Failure) +
        "\n历史结果不代表当前网络可用；24 小时后标为需复测。";
}

internal sealed class VerificationHistory
{
    private readonly Dictionary<string, LineCheck> records = new(StringComparer.Ordinal);
    private static string FilePath => Path.Combine(Storage.Root, "line-checks.dat");
    internal static VerificationHistory Load()
    {
        var history = new VerificationHistory();
        foreach (var item in (Storage.Read<List<LineCheck>>(FilePath) ?? []).Take(512))
            if (item.Name is { Length: > 0 and <= 512 } && item.Fingerprint is { Length: 64 } && item.Failure is { Length: <= 160 }) history.records[item.Name] = item;
        return history;
    }
    internal LineCheck? Get(JsonObject profile, string name) => records.TryGetValue(name, out var value) && value.Fingerprint == Fingerprint(profile, name) ? value : null;
    internal Dictionary<string, LineCheck> ForProfile(JsonObject profile)
    {
        string context = ContextFingerprint(profile);
        var matched = new Dictionary<string, LineCheck>(StringComparer.Ordinal);
        foreach (var node in (profile["nodes"] as JsonArray) ?? [])
            if (node?["name"]?.GetValue<string>() is string name && records.TryGetValue(name, out var record) && record.Fingerprint == NodeFingerprint(context, node)) matched[name] = record;
        return matched;
    }
    internal void Record(JsonObject profile, string name, bool success, ulong elapsedMs, DateTimeOffset now, string failure = "")
    {
        string? key = Fingerprint(profile, name);
        if (key == null) return;
        var current = ForProfile(profile);
        foreach (string old in records.Keys.Where(old => !current.ContainsKey(old) || records[old].CheckedAt < now.AddDays(-7)).ToArray()) records.Remove(old);
        records[name] = new LineCheck(name, key, success, elapsedMs, now, failure.Length <= 160 ? failure : failure[..160]);
        Storage.Write(FilePath, records.Values.OrderByDescending(value => value.CheckedAt).Take(512).ToList());
    }
    internal void Clear() { if (File.Exists(FilePath)) File.Delete(FilePath); records.Clear(); }

    internal static string? Fingerprint(JsonObject profile, string name)
    {
        var node = (profile["nodes"] as JsonArray)?.FirstOrDefault(value => value?["name"]?.GetValue<string>() == name);
        if (node == null) return null;
        return NodeFingerprint(ContextFingerprint(profile), node);
    }
    private static string ContextFingerprint(JsonObject profile)
    {
        var context = new JsonObject();
        // These settings do not participate in explicit outbound HTTPS verification.
        foreach (var property in profile)
            if (property.Key is not ("nodes" or "groups" or "rules" or "finalPolicy" or "listen" or "dnsListen" or "tun")) context[property.Key] = property.Value?.DeepClone();
        return Hash(context);
    }
    private static string NodeFingerprint(string context, JsonNode node) => Hash(new JsonObject { ["context"] = context, ["outbound"] = node.DeepClone() });
    private static string Hash(JsonNode value)
    {
        using var bytes = new MemoryStream();
        using (var writer = new Utf8JsonWriter(bytes)) WriteCanonical(writer, value);
        return Convert.ToHexStringLower(SHA256.HashData(bytes.GetBuffer().AsSpan(0, (int)bytes.Length)));
    }
    private static void WriteCanonical(Utf8JsonWriter writer, JsonNode? value)
    {
        if (value is JsonObject obj)
        {
            writer.WriteStartObject();
            foreach (var property in obj.OrderBy(property => property.Key, StringComparer.Ordinal)) { writer.WritePropertyName(property.Key); WriteCanonical(writer, property.Value); }
            writer.WriteEndObject();
        }
        else if (value is JsonArray array) { writer.WriteStartArray(); foreach (var item in array) WriteCanonical(writer, item); writer.WriteEndArray(); }
        else if (value == null) writer.WriteNullValue();
        else value.WriteTo(writer);
    }
}
