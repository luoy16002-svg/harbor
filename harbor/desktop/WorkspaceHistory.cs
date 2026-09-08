using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;

namespace Harbor;

internal sealed record WorkspaceRevision(string Id, DateTimeOffset SavedAt, WorkspaceState State)
{
    [JsonIgnore] public string Time => SavedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    [JsonIgnore] public string Summary => $"{State.Profile["nodes"]?.AsArray().Count ?? 0} 条线路 · {State.Subscriptions.Count} 个订阅 · {ProfileWorkflow.RoutingLabel(State.Profile)}";
}
internal sealed record WorkspaceHistoryFile(int Version, List<WorkspaceRevision> Revisions);
internal sealed record WorkspaceChange(string Area, string Action, string Detail);

internal static class WorkspaceHistory
{
    internal const int Capacity = 10;
    internal const int MaximumBytes = 64 * 1024 * 1024;
    internal static string FilePath => Path.Combine(Storage.Root, "workspace-history.dat");

    internal static List<WorkspaceRevision> Read()
    {
        var file = Storage.Read<WorkspaceHistoryFile>(FilePath, MaximumBytes);
        if (file == null)
        {
            if (File.Exists(FilePath)) throw new InvalidDataException("配置历史为空或格式不完整。");
            return [];
        }
        if (file.Version != 1 || file.Revisions == null || file.Revisions.Count > Capacity)
            throw new InvalidDataException("配置历史版本或记录数量无效。");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in file.Revisions)
        {
            if (item == null || !Guid.TryParseExact(item.Id, "N", out _) || !ids.Add(item.Id) || item.SavedAt == default)
                throw new InvalidDataException("配置历史记录不完整。");
            ValidateStructure(item.State);
        }
        return file.Revisions;
    }

    private static void ValidateStructure(WorkspaceState state)
    {
        if (state == null || state.Profile == null || state.Subscriptions == null || state.Subscriptions.Count > 512)
            throw new InvalidDataException("配置历史缺少工作空间数据。");
        foreach (var entry in state.Subscriptions)
            if (entry == null || string.IsNullOrWhiteSpace(entry.Id) || entry.Name == null || entry.Url == null ||
                entry.NodeNames == null || entry.NodeNames.Length > 512 || entry.NodeNames.Any(string.IsNullOrEmpty))
                throw new InvalidDataException("配置历史中的订阅记录不完整。");
        foreach (string key in new[] { "nodes", "groups", "rules" })
            if (state.Profile[key] != null && state.Profile[key] is not JsonArray)
                throw new InvalidDataException("配置历史中的列表格式无效。");
        if (state.Profile["routingMode"] != null &&
            (state.Profile["routingMode"] is not JsonValue mode || !mode.TryGetValue<string>(out string? name) || name is not ("rules" or "global" or "direct")))
            throw new InvalidDataException("配置历史中的分流模式无效。");
        DirectExceptions.Read(state.Profile);
        TrafficRoutes.Read(state.Profile);
        ProxyPools.Validate(state.Profile);
    }

    internal static WorkspaceState Clone(WorkspaceState value) => new(value.Profile.DeepClone().AsObject(),
        value.Subscriptions.Select(entry => entry with { NodeNames = entry.NodeNames.ToArray() }).ToList());

    internal static bool SameConfiguration(WorkspaceState left, WorkspaceState right) =>
        JsonNode.DeepEquals(left.Profile, right.Profile) && left.Subscriptions.Count == right.Subscriptions.Count &&
        left.Subscriptions.Zip(right.Subscriptions).All(pair => pair.First.Id == pair.Second.Id && pair.First.Name == pair.Second.Name &&
            pair.First.Url == pair.Second.Url && pair.First.NodeNames.SequenceEqual(pair.Second.NodeNames));

    internal static void RecordBeforeSave(WorkspaceState? before, WorkspaceState after)
    {
        // Quota, fetch timestamps, and HTTP validators do not create revisions.
        if (before == null || SameConfiguration(before, after)) return;
        ValidateStructure(before);
        var revisions = Read();
        // A failed workspace replacement may already have saved this exact predecessor.
        if (revisions.Count > 0 && SameConfiguration(revisions[0].State, before)) return;
        revisions.Insert(0, new WorkspaceRevision(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, Clone(before)));
        Storage.Write(FilePath, new WorkspaceHistoryFile(1, revisions.Take(Capacity).ToList()), MaximumBytes);
    }

    internal static WorkspaceState PrepareRestore(WorkspaceState saved)
    {
        ValidateStructure(saved);
        var candidate = Clone(saved);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var names = (candidate.Profile["nodes"] as JsonArray ?? []).Select(node => node?["name"]?.GetValue<string>() ?? "").ToHashSet(StringComparer.Ordinal);
        foreach (var entry in candidate.Subscriptions)
            if (!ids.Add(entry.Id) || !Uri.TryCreate(entry.Url, UriKind.Absolute, out var url) || url.Scheme != "https" || url.UserInfo.Length != 0 ||
                entry.NodeNames.Any(name => !names.Contains(name)))
                throw new InvalidDataException("历史订阅的地址或线路引用无效，无法恢复。");
        // Old nodes must get a full feed on the next manual refresh, never a stale 304.
        return candidate with { Subscriptions = candidate.Subscriptions.Select(entry => entry with
            { Etag = "", LastModified = "", Digest = "", Usage = null }).ToList() };
    }

    internal static void Clear() => File.Delete(FilePath);

    internal static List<WorkspaceChange> Compare(WorkspaceState current, WorkspaceState saved)
    {
        var changes = new List<WorkspaceChange>();
        var labels = new Dictionary<string, string>
        {
            ["kind"] = "类型", ["server"] = "服务器地址", ["port"] = "端口", ["username"] = "认证信息", ["password"] = "认证信息", ["uuid"] = "认证信息",
            ["cipher"] = "加密方式", ["tls"] = "TLS", ["tlsServerName"] = "TLS 服务器名称", ["transport"] = "传输方式", ["wsPath"] = "传输参数",
            ["wsHost"] = "传输参数", ["security"] = "加密方式", ["members"] = "成员", ["selected"] = "选中出口"
        };
        void NamedItems(string key, string title)
        {
            var oldItems = (current.Profile[key] as JsonArray ?? []).OfType<JsonObject>().ToList();
            var newItems = (saved.Profile[key] as JsonArray ?? []).OfType<JsonObject>().ToList();
            string Name(JsonObject item) => item["name"]?.GetValue<string>() ?? "未命名";
            foreach (var item in oldItems)
                if (!newItems.Any(other => Name(other) == Name(item))) changes.Add(new(title + " · " + Name(item), "移除", "恢复后移除此项。"));
            foreach (var item in newItems)
            {
                var old = oldItems.FirstOrDefault(other => Name(other) == Name(item));
                if (old == null) { changes.Add(new(title + " · " + Name(item), "添加", "恢复历史版本中的此项。")); continue; }
                if (!JsonNode.DeepEquals(old, item))
                {
                    var fields = old.Select(pair => pair.Key).Union(item.Select(pair => pair.Key)).Where(field => !JsonNode.DeepEquals(old[field], item[field]));
                    changes.Add(new(title + " · " + Name(item), "修改", string.Join("、", fields.Select(field => labels.GetValueOrDefault(field, "其他参数")).Distinct()) + "有变化。"));
                }
            }
            if (oldItems.Count == newItems.Count && !oldItems.Select(Name).SequenceEqual(newItems.Select(Name)) &&
                oldItems.Select(Name).Order().SequenceEqual(newItems.Select(Name).Order())) changes.Add(new(title, "排序", "恢复历史排列顺序。"));
        }
        NamedItems("nodes", "线路"); NamedItems("groups", "策略组");
        NamedItems("trafficRoutes", "流量路径");
        if (ProfileWorkflow.RoutingMode(current.Profile) != ProfileWorkflow.RoutingMode(saved.Profile))
            changes.Add(new("分流模式", "修改", ProfileWorkflow.RoutingLabel(current.Profile) + " → " + ProfileWorkflow.RoutingLabel(saved.Profile)));
        if (!JsonNode.DeepEquals(current.Profile["finalPolicy"], saved.Profile["finalPolicy"]))
            changes.Add(new("默认出口", "修改", (current.Profile["finalPolicy"]?.GetValue<string>() ?? "DIRECT") + " → " + (saved.Profile["finalPolicy"]?.GetValue<string>() ?? "DIRECT")));
        if (!JsonNode.DeepEquals(current.Profile["rules"], saved.Profile["rules"]))
            changes.Add(new("分流规则", "修改", $"{(current.Profile["rules"] as JsonArray)?.Count ?? 0} 条 → {(saved.Profile["rules"] as JsonArray)?.Count ?? 0} 条；规则内容、启用状态或顺序有变化。"));
        if (!JsonNode.DeepEquals(current.Profile["directExceptions"], saved.Profile["directExceptions"]))
            changes.Add(new("直连例外", "修改", DirectExceptions.Read(current.Profile).Summary + " → " + DirectExceptions.Read(saved.Profile).Summary));
        foreach (var group in new[] { ("DNS", new[] { "dnsServers", "dnsTls", "dnsListen", "fakeIp" }), ("隐私保护", new[] { "privacy" }),
            ("监听与网络", new[] { "listen", "tun", "egressMode", "tunName", "tunAddress" }) })
            if (group.Item2.Any(key => !JsonNode.DeepEquals(current.Profile[key], saved.Profile[key]))) changes.Add(new(group.Item1, "修改", "恢复该部分的历史设置。"));
        string[] known = ["nodes", "groups", "rules", "routingMode", "directExceptions", "trafficRoutes", "finalPolicy", "dnsServers", "dnsTls", "dnsListen", "fakeIp", "privacy", "listen", "tun", "egressMode", "tunName", "tunAddress"];
        if (current.Profile.Select(pair => pair.Key).Union(saved.Profile.Select(pair => pair.Key)).Except(known).Any(key => !JsonNode.DeepEquals(current.Profile[key], saved.Profile[key])))
            changes.Add(new("其他配置", "修改", "其他配置参数有变化。"));
        foreach (var entry in current.Subscriptions)
            if (!saved.Subscriptions.Any(other => other.Id == entry.Id)) changes.Add(new("订阅 · " + entry.Name, "移除", "移除订阅记录；线路按上方差异恢复。"));
        foreach (var entry in saved.Subscriptions)
        {
            var old = current.Subscriptions.FirstOrDefault(other => other.Id == entry.Id);
            if (old == null) changes.Add(new("订阅 · " + entry.Name, "添加", "恢复订阅地址与线路归属。"));
            else if (old.Name != entry.Name || old.Url != entry.Url || !old.NodeNames.SequenceEqual(entry.NodeNames))
                changes.Add(new("订阅 · " + entry.Name, "修改", string.Join("、", new[] { old.Name != entry.Name ? "名称" : null,
                    old.Url != entry.Url ? "订阅地址" : null, !old.NodeNames.SequenceEqual(entry.NodeNames) ? "线路归属" : null }.Where(text => text != null)) + "有变化。"));
        }
        if (changes.Count == 0 && !SameConfiguration(current, saved)) changes.Add(new("配置", "修改", "配置格式或排列顺序有变化。"));
        return changes;
    }
}
