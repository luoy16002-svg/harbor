using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckBatchWorkflowAsync(Func<Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Batch checks require isolation.");
        var previous = profile.DeepClone().AsObject(); var subscriptions = Subscriptions.Read();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException("Batch workflow: " + message); }
        int entered = 0;
        var bothEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task HoldProxy()
        {
            using var peer = await listener.AcceptTcpClientAsync(deadline.Token);
            var stream = peer.GetStream(); using var header = new MemoryStream(); byte[] one = new byte[1];
            while (!Encoding.ASCII.GetString(header.ToArray()).EndsWith("\r\n\r\n", StringComparison.Ordinal))
            {
                Require(header.Length < 8192 && await stream.ReadAsync(one, deadline.Token) == 1, "incomplete local CONNECT"); header.WriteByte(one[0]);
            }
            Require(Encoding.ASCII.GetString(header.ToArray()).StartsWith("CONNECT www.example.com:443 ", StringComparison.Ordinal), "unexpected verification destination");
            if (Interlocked.Increment(ref entered) == 2) bothEntered.TrySetResult();
            Require(await stream.ReadAsync(one, deadline.Token) == 0, "cancel did not close the verification connection");
        }
        Task? held = null;
        try
        {
            var candidate = (await client.CallAsync("default_config")).AsObject();
            candidate["listen"] = "127.0.0.1:" + FreePort(); candidate["dnsListen"] = "127.0.0.1:" + FreePort();
            candidate["finalPolicy"] = "DIRECT"; candidate["rules"] = new JsonArray();
            candidate["nodes"] = new JsonArray(new[] { "批量测试甲", "批量测试乙", "排队线路丙" }.Select(name => (JsonNode)new JsonObject
            {
                ["name"] = name, ["kind"] = "http", ["server"] = "127.0.0.1", ["port"] = ((IPEndPoint)listener.LocalEndpoint).Port
            }).ToArray());
            await SaveAsync(candidate); ClearLineChecks(this, new RoutedEventArgs());
            var now = DateTimeOffset.UtcNow;
            // Synthetic history is used only to check sorting and cancellation retention.
            lineChecks.Record(profile, "批量测试甲", true, 450, now);
            lineChecks.Record(profile, "批量测试乙", true, 80, now);
            lineChecks.Record(profile, "排队线路丙", true, 1, now.AddHours(-25));
            RefreshNodes(); NodeSort.SelectedIndex = 1;
            Require(NodeGrid.Items.OfType<NodeRow>().Select(row => row.Name).SequenceEqual(new[] { "批量测试乙", "批量测试甲", "排队线路丙" }), "HTTPS sort was lexical or ranked expired success first");
            ResetNodeFilter(this, new RoutedEventArgs());
            var saved = VerificationHistory.Load().Get(profile, "批量测试甲");
            await StartAsync();
            held = Task.WhenAll(HoldProxy(), HoldProxy());
            VerifyVisibleButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await bothEntered.Task.WaitAsync(deadline.Token);
            Require(verifying && BatchProgress.Maximum == 3 && BatchProgress.Value == 0 && CancelVerificationButton.IsEnabled && !VerifyVisibleButton.IsEnabled && !ClearLineChecksButton.IsEnabled, "batch controls or progress were incorrect");
            NodeSearch.Text = "不存在";
            Require(NodeGrid.Items.Count == 0 && verifying && BatchProgress.Maximum == 3, "filter changed an active batch");
            NodeSearch.Text = ""; Navigate(NavNodes, new RoutedEventArgs()); Notice.Visibility = Visibility.Collapsed;
            await capture();
            CancelVerificationButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            await CancelVerificationAsync();
            for (int i = 0; verifying && i < 50; i++) await Task.Delay(10, deadline.Token);
            await held.WaitAsync(deadline.Token);
            Require(!verifying && entered == 2 && !listener.Pending() && BatchStatus.Text.Contains("已取消", StringComparison.Ordinal), "cancel scheduled queued nodes or failed to settle");
            Require(VerificationHistory.Load().Get(profile, "批量测试甲") == saved && running && (await client.CallAsync("snapshot"))["running"]!.GetValue<bool>(), "cancel changed history or stopped the active engine");
            await StopAsync();
            var blocked = profile.DeepClone().AsObject(); blocked["privacy"]!["blockedDomains"] = new JsonArray("www.example.com");
            await SaveAsync(blocked); ClearLineChecks(this, new RoutedEventArgs()); NodeSearch.Text = "测试乙";
            VerifyVisibleButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); NodeSearch.Text = "";
            if (verificationTask is { } batch) await batch;
            for (int i = 0; verifying && i < 50; i++) await Task.Delay(10, deadline.Token);
            Require(!verifying && lineChecks.ForProfile(profile).Count == 1 && VerificationHistory.Load().Get(profile, "批量测试乙") is { Success: false }, "batch did not persist only the originally filtered node");
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0, ["fixture"] = "Two loopback CONNECT stalls; synthetic historical results only for sorting/retention", ["checks"] = new JsonArray("numeric HTTPS ordering excludes expired success", "two active checks show progress and cancellation controls", "filter changes preserve the original batch snapshot", "cancel closes both sockets and leaves queued nodes untouched", "cancel preserves stored history and running listeners", "filtered batch persists a real privacy-blocked failure") };
        }
        finally
        {
            await CancelVerificationAsync(); if (running) await StopAsync(); deadline.Cancel(); listener.Stop();
            if (held != null) { try { await held; } catch (Exception) when (deadline.IsCancellationRequested) { } }
            ResetNodeFilter(this, new RoutedEventArgs()); lineChecks.Clear(); await SaveAsync(previous, subscriptions);
            verificationStatus = "按当前列表逐条检查 HTTPS；耗时不代表下载速度。"; SyncHome(); Notice.Visibility = Visibility.Collapsed;
            Navigate(NavOverview, new RoutedEventArgs());
        }
    }
}
