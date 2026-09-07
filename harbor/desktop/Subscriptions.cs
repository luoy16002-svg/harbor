using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Harbor;

internal sealed record SubscriptionEntry(string Id, string Name, string Url, string[] NodeNames, DateTimeOffset UpdatedAt, string Etag, string LastModified, string Digest, int UnsupportedCount, SubscriptionUsage? Usage = null);
internal sealed record DownloadedSubscription(string Text, string Etag, string LastModified, string Digest, bool NotModified, SubscriptionUsage? Usage = null);
internal static class Subscriptions
{
    public static string PathName => Path.Combine(Storage.Root, "subscriptions.dat");
    public static List<SubscriptionEntry> Read() => Storage.LoadWorkspace()?.Subscriptions ?? [];
    public static void Save(List<SubscriptionEntry> entries)
    {
        var state = Storage.LoadWorkspace() ?? throw new IOException("尚未保存工作空间。");
        Storage.SaveWorkspace(state.Profile, entries);
    }
    public static string DisplayAddress(string url) => Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host + " / ••••••••" : "已加密保存";

    public static async Task<DownloadedSubscription> FetchAsync(string url, string? proxy = null, SubscriptionEntry? previous = null, CancellationToken cancellationToken = default)
    {
        using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli };
        if (proxy != null) handler.Proxy = new WebProxy("http://" + proxy);
        return await FetchWithHandlerAsync(url, handler, previous, cancellationToken);
    }
    internal static async Task<DownloadedSubscription> FetchWithHandlerAsync(string url, HttpMessageHandler handler, SubscriptionEntry? previous = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo)) throw new FormatException("订阅必须是 HTTPS 地址，不能在 URL 中携带 HTTP 用户名和密码。");
        if (previous != null && !string.Equals(previous.Url.Trim(), url.Trim(), StringComparison.Ordinal)) previous = null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var client = new HttpClient(handler, false) { Timeout = Timeout.InfiniteTimeSpan };
        try
        {
            for (int redirects = 0; redirects <= 5; redirects++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                var version = typeof(Subscriptions).Assembly.GetName().Version;
                request.Headers.UserAgent.ParseAdd($"Harbor/{version?.Major ?? 0}.{version?.Minor ?? 0}.{version?.Build ?? 0}");
                request.Headers.Accept.ParseAdd("application/yaml, application/json, text/plain, */*;q=0.5");
                if (redirects == 0 && previous != null)
                {
                    if (EntityTagHeaderValue.TryParse(previous.Etag, out var etag)) request.Headers.IfNoneMatch.Add(etag);
                    if (DateTimeOffset.TryParse(previous.LastModified, out var modified)) request.Headers.IfModifiedSince = modified;
                }
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                if (response.StatusCode == HttpStatusCode.NotModified)
                {
                    if (previous == null || (!request.Headers.IfNoneMatch.Any() && request.Headers.IfModifiedSince == null)) throw new IOException("订阅服务器返回了未请求的 304 响应，请稍后重试。");
                    return new("", response.Headers.ETag?.ToString() ?? previous.Etag, response.Content.Headers.LastModified?.ToString("R") ?? previous.LastModified, previous.Digest, true, ReadUsage(response, previous.Usage));
                }
                if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
                {
                    var location = response.Headers.Location ?? throw new IOException("订阅重定向没有目标地址。");
                    var next = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    if (next.Scheme != "https" || !string.IsNullOrEmpty(next.UserInfo)) throw new IOException("已拒绝不安全的订阅重定向。");
                    uri = next; continue;
                }
                if (!response.IsSuccessStatusCode) throw new IOException($"订阅服务器返回 HTTP {(int)response.StatusCode}。");
                if (response.Content.Headers.ContentLength > ProfileImport.MaximumBytes) throw new IOException("订阅超过 2 MiB。");
                await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
                using var output = new MemoryStream(); var buffer = new byte[8192];
                byte[]? bytes = null;
                try
                {
                    while (true) { int read = await stream.ReadAsync(buffer, timeout.Token); if (read == 0) break; if (output.Length + read > ProfileImport.MaximumBytes) throw new IOException("解压后的订阅超过 2 MiB。"); output.Write(buffer, 0, read); }
                    bytes = output.ToArray(); var text = new UTF8Encoding(false, true).GetString(bytes);
                    return new(text, response.Headers.ETag?.ToString() ?? "", response.Content.Headers.LastModified?.ToString("R") ?? "", Convert.ToHexString(SHA256.HashData(bytes)), false, ReadUsage(response));
                }
                finally { CryptographicOperations.ZeroMemory(buffer); if (bytes != null) CryptographicOperations.ZeroMemory(bytes); if (output.TryGetBuffer(out var segment)) CryptographicOperations.ZeroMemory(segment.AsSpan()); }
            }
            throw new IOException("订阅重定向超过 5 次。");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException("订阅下载已取消。", cancellationToken); }
        catch (OperationCanceledException) { throw new IOException("订阅下载超过 30 秒，已取消。"); }
        catch (HttpRequestException) { throw new IOException("订阅连接失败。请检查网络、地址和服务器证书；完整地址不会写入日志。"); }
        catch (DecoderFallbackException) { throw new IOException("订阅不是有效的 UTF-8 文本。"); }
    }

    private static SubscriptionUsage? ReadUsage(HttpResponseMessage response, SubscriptionUsage? absent = null)
    {
        if (!response.Headers.TryGetValues("Subscription-Userinfo", out var values)) return absent;
        // Ambiguous duplicate headers are ignored; malformed metadata must not block a valid feed.
        string[] headers = values.Take(2).ToArray();
        return headers.Length == 1 ? SubscriptionUsage.Parse(headers[0], DateTimeOffset.UtcNow) : null;
    }

    public static JsonObject Merge(JsonObject profile, JsonArray incoming, SubscriptionEntry? previous, string prefix, out string[] names, out int retained)
        => Merge(profile, incoming, previous, prefix, out names, out retained, out _);

    internal static JsonObject Merge(JsonObject profile, JsonArray incoming, SubscriptionEntry? previous, string prefix, out string[] names, out int retained, out string[] retainedNames)
    {
        var candidate = profile.DeepClone().AsObject(); var nodes = candidate["nodes"]!.AsArray();
        var owned = previous?.NodeNames.ToHashSet() ?? [];
        var referenced = new HashSet<string> { candidate["finalPolicy"]!.GetValue<string>() };
        foreach (var rule in candidate["rules"]!.AsArray()) referenced.Add(rule!["policy"]!.GetValue<string>());
        foreach (var route in candidate["trafficRoutes"] as JsonArray ?? []) if (route?["policy"]?.GetValue<string>() is string policy) referenced.Add(policy);
        foreach (var group in candidate["groups"]!.AsArray()) foreach (var member in group!["members"]!.AsArray()) referenced.Add(member!.GetValue<string>());
        var incomingNames = new HashSet<string>(); var pending = new List<JsonObject>();
        foreach (var raw in incoming)
        {
            var node = raw!.DeepClone().AsObject(); string name = prefix + node["name"]!.GetValue<string>();
            string original = name; int suffix = 2;
            while (nodes.Any(n => n!["name"]!.GetValue<string>() == name && !owned.Contains(name)) || incomingNames.Contains(name)) name = original + " (" + suffix++ + ")";
            node["name"] = name; incomingNames.Add(name); pending.Add(node);
        }
        var keep = new List<string>();
        for (int i = nodes.Count - 1; i >= 0; i--)
        {
            string name = nodes[i]!["name"]!.GetValue<string>(); if (!owned.Contains(name)) continue;
            if (incomingNames.Contains(name) || !referenced.Contains(name)) nodes.RemoveAt(i);
            else keep.Add(name);
        }
        foreach (var node in pending) nodes.Add(node);
        retainedNames = keep.ToArray(); retained = keep.Count;
        names = incomingNames.Concat(retainedNames).ToArray();
        return candidate;
    }
}
