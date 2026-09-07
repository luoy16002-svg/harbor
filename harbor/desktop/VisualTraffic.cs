using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Harbor;
public partial class MainWindow
{
    // Developer check, reachable only through --visual-check. Every byte stays on loopback.
    internal async Task<JsonObject> CheckLoopbackTrafficAsync(Func<Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || running || client == null)
            throw new InvalidOperationException("Visual traffic checks require a stopped, isolated instance.");
        var previous = profile;
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        var echo = new TcpListener(IPAddress.Loopback, 0); echo.Start();
        var workers = new List<Task>();
        Task responder = AcceptAsync();
        var transfers = new List<Task>(); long transferred = 0;
        try
        {
            profile = (await client.CallAsync("default_config")).AsObject();
            profile["listen"] = "127.0.0.1:" + FreePort(); profile["dnsListen"] = "127.0.0.1:" + FreePort();
            profile["tun"] = false; profile["nodes"] = new JsonArray(); profile["rules"] = new JsonArray(); profile["groups"] = new JsonArray();
            profile["finalPolicy"] = "DIRECT"; profile["dnsTls"] = new JsonArray(); profile["dnsServers"] = new JsonArray("127.0.0.1:9");
            profile["privacy"] = new JsonObject { ["blockDirect"] = true, ["requireEncryptedProxy"] = true, ["hideMetadata"] = false, ["historySecs"] = 300, ["blockedDomains"] = new JsonArray("tracker.fixture.invalid"), ["allowedDomains"] = new JsonArray() };
            SyncProfile(); Chart.WindowSeconds = 30; await StartAsync();
            for (int index = 0; index < 4; index++) transfers.Add(TransferAsync(index, cancel.Token));
            await Task.Delay(TimeSpan.FromSeconds(32), cancel.Token);
            if (transfers.Any(task => task.IsFaulted)) await Task.WhenAll(transfers.Where(task => task.IsFaulted));
            await BlockedConnectionAsync(cancel.Token);
            timer.Stop(); while (refreshing) await Task.Delay(10, cancel.Token);
            await RefreshAsync();
            if (N(snapshot!, "activeConnections") != 4 || transferred < 256 * 1024) throw new InvalidOperationException("Loopback traffic did not reach the desktop snapshot.");
            var blockedFlow = flows.FirstOrDefault(flow => flow.State == "失败" && flow.Destination.StartsWith("tracker.fixture.invalid", StringComparison.Ordinal));
            if (blockedFlow == null || blockedFlow.Failure == "—" || string.IsNullOrEmpty(blockedFlow.Error) || !RecentGrid.Items.Contains(blockedFlow)) throw new InvalidOperationException("The home table did not display the real connection failure.");
            OverviewSubtitle.Text = "本机回环验证 · 4 条真实连接 · 1 条本地拦截";
            ModeLabel.Text = "隔离验证 · 仅本机回环";
            await capture();
            return new JsonObject { ["fixture"] = "4 SOCKS5 streams to the application's own loopback echo server and one local blocked request", ["isolated"] = true, ["externalRequests"] = 0, ["verifiedPayloadBytes"] = Interlocked.Read(ref transferred), ["activeFlowsAtCapture"] = 4, ["failureReasonDisplayed"] = true, ["chartWindowSeconds"] = 30 };
        }
        finally
        {
            cancel.Cancel(); echo.Stop();
            try
            {
                try { await Task.WhenAll(transfers); } catch (OperationCanceledException) { }
                try { await responder; } catch (OperationCanceledException) { } catch (SocketException) when (cancel.IsCancellationRequested) { }
            }
            finally { if (running) await StopAsync(); profile = previous; Chart.WindowSeconds = 90; SyncProfile(); }
        }
        async Task AcceptAsync()
        {
            try
            {
                while (!cancel.IsCancellationRequested)
                {
                    var connection = await echo.AcceptTcpClientAsync(cancel.Token);
                    workers.Add(EchoAsync(connection));
                }
            }
            finally { await Task.WhenAll(workers); }
        }
        async Task EchoAsync(TcpClient connection)
        {
            using (connection)
            {
                try
                {
                    var stream = connection.GetStream(); var bytes = new byte[32768]; int length;
                    while ((length = await stream.ReadAsync(bytes, cancel.Token)) > 0) await stream.WriteAsync(bytes.AsMemory(0, length), cancel.Token);
                }
                catch (OperationCanceledException) { }
            }
        }
        async Task TransferAsync(int index, CancellationToken token)
        {
            using var connection = new TcpClient();
            var endpoint = IPEndPoint.Parse(profile["listen"]!.GetValue<string>());
            await connection.ConnectAsync(endpoint.Address, endpoint.Port, token); var stream = connection.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, token); var hello = new byte[2]; await stream.ReadExactlyAsync(hello, token);
            if (!hello.SequenceEqual(new byte[] { 5, 0 })) throw new InvalidOperationException("SOCKS5 handshake failed.");
            int port = ((IPEndPoint)echo.LocalEndpoint).Port;
            await stream.WriteAsync(new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port }, token);
            var reply = new byte[10]; await stream.ReadExactlyAsync(reply, token);
            if (reply[1] != 0 || reply[3] != 1) throw new InvalidOperationException("SOCKS5 connect failed.");
            var bytes = new byte[16384]; var returned = new byte[bytes.Length]; Array.Fill(bytes, (byte)(37 + index));
            var clock = Stopwatch.StartNew();
            while (!token.IsCancellationRequested)
            {
                int length = 1024 + (int)((Math.Sin(clock.Elapsed.TotalSeconds * .65 + index * .2) + 1) * 6000);
                await stream.WriteAsync(bytes.AsMemory(0, length), token); await stream.ReadExactlyAsync(returned.AsMemory(0, length), token);
                if (!bytes.AsSpan(0, length).SequenceEqual(returned.AsSpan(0, length))) throw new InvalidOperationException("Loopback payload changed.");
                Interlocked.Add(ref transferred, length); await Task.Delay(45 + index * 2, token);
            }
        }
        async Task BlockedConnectionAsync(CancellationToken token)
        {
            using var connection = new TcpClient();
            var endpoint = IPEndPoint.Parse(profile["listen"]!.GetValue<string>());
            await connection.ConnectAsync(endpoint.Address, endpoint.Port, token); var stream = connection.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, token); var hello = new byte[2]; await stream.ReadExactlyAsync(hello, token);
            if (!hello.SequenceEqual(new byte[] { 5, 0 })) throw new InvalidOperationException("Blocked fixture SOCKS handshake failed.");
            byte[] name = System.Text.Encoding.ASCII.GetBytes("tracker.fixture.invalid");
            var request = new byte[] { 5, 1, 0, 3, (byte)name.Length }.Concat(name).Concat(new byte[] { 1, 187 }).ToArray();
            await stream.WriteAsync(request, token); var reply = new byte[10]; await stream.ReadExactlyAsync(reply, token);
            if (reply[1] == 0) throw new InvalidOperationException("Local block rule allowed the fixture.");
        }
    }
    private static int FreePort()
    {
        for (int i = 0; i < 20; i++)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            try { int port = ((IPEndPoint)listener.LocalEndpoint).Port; using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port)); return port; }
            catch (SocketException) { }
            finally { listener.Stop(); }
        }
        throw new InvalidOperationException("No loopback fixture port is available.");
    }
}
