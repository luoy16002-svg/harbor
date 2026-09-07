using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Harbor;

internal sealed class EngineClient : IAsyncDisposable
{
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonObject>> pending = new();
    private readonly SemaphoreSlim writer = new(1, 1);
    private long next;
    public Process Process { get; }
    public event Action<string>? Exited;
    public EngineClient(string path)
    {
        var start = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardInputEncoding = new UTF8Encoding(false), StandardOutputEncoding = Encoding.UTF8, WorkingDirectory = Path.GetDirectoryName(path)! };
        if (App.Isolated) start.ArgumentList.Add("--isolated");
        Process = Process.Start(start) ?? throw new IOException("无法启动网络引擎。");
        _ = ReadAsync(); _ = ObserveExitAsync();
    }
    private async Task ReadAsync()
    {
        try
        {
            while (await Process.StandardOutput.ReadLineAsync() is { } line)
            {
                if (line.Length > 4 * 1024 * 1024) throw new IOException("引擎响应超过大小限制。");
                var value = JsonNode.Parse(line)?.AsObject() ?? throw new IOException("无效的引擎响应。");
                if (value["id"]?.GetValue<long>() is long id && pending.TryRemove(id, out var source)) source.TrySetResult(value);
            }
        }
        catch (Exception error) { foreach (var source in pending.Values) source.TrySetException(error); }
    }
    private async Task ObserveExitAsync()
    {
        var errorTask = Process.StandardError.ReadToEndAsync(); await Process.WaitForExitAsync();
        string error = await errorTask;
        foreach (var source in pending.Values) source.TrySetException(new IOException("网络引擎已退出。"));
        Exited?.Invoke(string.IsNullOrWhiteSpace(error) ? "网络引擎已退出。" : error.Trim());
    }
    public async Task<JsonNode> CallAsync(string command, JsonObject? fields = null, int timeoutSeconds = 20)
    {
        long id = Interlocked.Increment(ref next); var source = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        var message = fields ?? new JsonObject(); message["id"] = id; message["command"] = command;
        string serialized = message.ToJsonString(); if (Encoding.UTF8.GetByteCount(serialized) > 2 * 1024 * 1024) throw new IOException("配置请求超过 2 MiB，请缩减规则或节点数量。");
        pending[id] = source;
        try
        {
            await writer.WaitAsync();
            try { await Process.StandardInput.WriteLineAsync(serialized); await Process.StandardInput.FlushAsync(); }
            finally { writer.Release(); }
            var response = await source.Task.WaitAsync(TimeSpan.FromSeconds(timeoutSeconds));
            if (response["ok"]?.GetValue<bool>() != true) throw new IOException(response["error"]?.GetValue<string>() ?? "引擎请求失败。");
            return response["result"]?.DeepClone() ?? new JsonObject();
        }
        finally { pending.TryRemove(id, out _); }
    }
    public async ValueTask DisposeAsync()
    {
        if (!Process.HasExited)
        {
            try { await CallAsync("shutdown", timeoutSeconds: 3); await Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)); }
            catch { if (!Process.HasExited) Process.Kill(true); }
        }
        Process.Dispose(); writer.Dispose();
    }
}
