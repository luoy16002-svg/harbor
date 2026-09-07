using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;

namespace Harbor;

internal sealed record SubscriptionChange(string Name, string Action, string Detail);
internal sealed record SubscriptionUpdate(JsonObject Profile, SubscriptionEntry Entry, IReadOnlyList<SubscriptionChange> Changes,
    IReadOnlyList<ImportIssue> Issues, int Added, int Changed, int Removed, int Retained, int Unchanged, bool ContentUnchanged)
{
    internal string Summary => $"新增 {Added} · 变更 {Changed} · 移除 {Removed} · 引用保留 {Retained} · 不变 {Unchanged}";

    internal static SubscriptionUpdate Prepare(JsonObject profile, SubscriptionEntry previous, DownloadedSubscription download, DateTimeOffset now)
    {
        var entry = previous with { UpdatedAt = now, Etag = download.Etag, LastModified = download.LastModified, Digest = download.Digest, Usage = download.Usage };
        if (download.NotModified || (previous.Digest.Length > 0 && download.Digest == previous.Digest))
            return new(profile.DeepClone().AsObject(), entry, [], [], 0, 0, 0, 0, previous.NodeNames.Length, true);
        var imported = ProfileImport.Parse(download.Text);
        if (imported.Nodes.Count == 0) throw new IOException("新订阅没有可用的受支持线路，现有线路已保留。");
        var candidate = Subscriptions.Merge(profile, imported.Nodes, previous, previous.Name + " · ", out var names, out int retained, out var retainedNames);
        entry = entry with { NodeNames = names, UnsupportedCount = imported.Issues.Count };
        var before = profile["nodes"]!.AsArray().ToDictionary(node => node!["name"]!.GetValue<string>(), node => node!);
        var after = candidate["nodes"]!.AsArray().ToDictionary(node => node!["name"]!.GetValue<string>(), node => node!);
        var keep = retainedNames.ToHashSet(StringComparer.Ordinal);
        var changes = new List<SubscriptionChange>();
        int added = 0, changed = 0, removed = 0, unchanged = 0;
        foreach (string name in previous.NodeNames.Concat(names).Distinct(StringComparer.Ordinal))
        {
            before.TryGetValue(name, out var oldNode); after.TryGetValue(name, out var newNode);
            if (keep.Contains(name)) changes.Add(new(name, "引用保留", "新订阅没有同名线路，当前出口、规则或策略组仍在使用。"));
            else if (oldNode == null && newNode != null) { added++; changes.Add(new(name, "新增", "将加入订阅线路。")); }
            else if (oldNode != null && newNode == null) { removed++; changes.Add(new(name, "移除", "新订阅没有同名线路，且没有分流引用。")); }
            else if (oldNode != null && newNode != null && !JsonNode.DeepEquals(oldNode, newNode))
            {
                changed++; changes.Add(new(name, "变更", ChangedFields(oldNode, newNode)));
            }
            else if (oldNode != null && newNode != null) unchanged++;
        }
        return new(candidate, entry, changes, imported.Issues, added, changed, removed, retained, unchanged, false);
    }

    private static string ChangedFields(JsonNode before, JsonNode after)
    {
        var labels = new List<string>();
        bool Any(params string[] keys) => keys.Any(key => !JsonNode.DeepEquals(before[key], after[key]));
        if (Any("kind", "cipher", "security")) labels.Add("协议或加密方式");
        if (Any("server", "port")) labels.Add("服务器地址或端口");
        if (Any("username", "password", "uuid")) labels.Add("认证信息");
        if (Any("tls", "tlsServerName", "caPem", "transport", "wsPath", "wsHost")) labels.Add("传输或 TLS 设置");
        return (labels.Count == 0 ? "其他线路设置" : string.Join("、", labels)) + "将更新；已有连接保留原配置。";
    }
}
