using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckPoolsAsync(Func<Window, string, Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Pool checks require isolation.");
        var previous = profile.DeepClone().AsObject(); var subscriptions = Subscriptions.Read(); var previousSnapshot = snapshot;
        bool timerWasEnabled = timer.IsEnabled; timer.Stop(); var checks = new List<string>();
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        // Schannel cannot serve TLS from an ephemeral RSA handle. Re-import a
        // temporary user key; disposing the certificate removes its key container.
        byte[] pfx = generated.Export(X509ContentType.Pfx);
        using var certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet);
        CryptographicOperations.ZeroMemory(pfx);
        using var bad = new TcpListener(IPAddress.Loopback, 0); using var good = new TcpListener(IPAddress.Loopback, 0); bad.Start(); good.Start();
        int badRequests = 0, goodRequests = 0;
        var fixtureErrors = new List<string>();
        Task badServer = Accept(bad, false), goodServer = Accept(good, true);
        void Require(bool value, string message) { if (!value) throw new InvalidOperationException("Automatic pools: " + message); }
        void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        async Task Settled() { for (int i = 0; busy && i < 150; i++) await Task.Delay(20, cancel.Token); Require(!busy, "action did not settle"); UpdateLayout(); }
        PoolDialog Dialog(JsonNode? value, Func<PoolDialog, Task> action)
        {
            var dialog = new PoolDialog(this, profile, value, lineChecks.ForProfile(profile)); Exception? error = null;
            dialog.Loaded += async (_, _) => { try { await action(dialog); } catch (Exception failure) { error = failure; dialog.DialogResult = false; } };
            dialog.ShowDialog(); if (error != null) throw new InvalidOperationException("Pool editor failed", error); return dialog;
        }
        try
        {
            var fixture = (await client.CallAsync("default_config")).AsObject();
            fixture["listen"] = "127.0.0.1:" + FreePort(); fixture["dnsListen"] = "127.0.0.1:" + FreePort();
            fixture["dnsTls"] = new JsonArray(); fixture["dnsServers"] = new JsonArray("127.0.0.1:9"); fixture["probeIntervalSecs"] = 3600;
            fixture["rules"] = new JsonArray(); fixture["groups"] = new JsonArray(); fixture["trafficRoutes"] = new JsonArray(); fixture["routingMode"] = "global";
            fixture["nodes"] = new JsonArray(
                new JsonObject { ["name"] = "主线 · 认证失败演示", ["kind"] = "http", ["server"] = "127.0.0.1", ["port"] = ((IPEndPoint)bad.LocalEndpoint).Port },
                new JsonObject { ["name"] = "备线 · 本机 HTTPS 服务", ["kind"] = "http", ["server"] = "127.0.0.1", ["port"] = ((IPEndPoint)good.LocalEndpoint).Port });
            fixture["finalPolicy"] = "主线 · 认证失败演示"; await SaveAsync(fixture, []);
            Require(PoolEmpty.Visibility == Visibility.Visible, "legacy workspace did not show setup");
            byte[] disk = File.ReadAllBytes(Storage.WorkspacePath);
            Dialog(null, dialog => { dialog.SelectMember("备线 · 本机 HTTPS 服务", true); dialog.DialogResult = false; return Task.CompletedTask; });
            Require(disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)), "cancel changed the workspace");
            var editor = Dialog(null, async dialog =>
            {
                dialog.SelectMember("备线 · 本机 HTTPS 服务", true); dialog.MonitorInput.IsChecked = false;
                dialog.UrlInput.Text = "http://localhost/"; Click(dialog.SaveButton);
                Require(dialog.Result == null && dialog.ErrorText.Text.Length > 0, "editor accepted an unencrypted check URL");
                dialog.UrlInput.Text = "https://localhost:9443/health"; dialog.CaInput.Text = certificate.ExportCertificatePem();
                dialog.NameInput.Text = "日常工作 · 自动备用"; dialog.ErrorText.Text = "";
                await capture(dialog, "pool-editor-980"); Click(dialog.SaveButton);
            });
            Require(editor.Result != null, "valid pool did not save"); await SavePoolAsync(null, editor.Result!);
            Click(PoolUseDefault); await Settled(); Require(S(profile, "finalPolicy") == "日常工作 · 自动备用", "default button did not save policy");
            Require(Storage.LoadWorkspace()!.Profile["groups"]![0]!["pool"] != null, "encrypted workspace omitted pool options");
            checks.Add("editor validates HTTPS, cancellation preserves disk, and pool creation/default selection persist options");
            await StartAsync();
            using var transfer = new TcpClient(); var endpoint = IPEndPoint.Parse(S(profile, "listen")); await transfer.ConnectAsync(endpoint.Address, endpoint.Port, cancel.Token);
            var stream = transfer.GetStream(); await stream.WriteAsync(new byte[] { 5, 1, 0 }, cancel.Token); var greeting = new byte[2]; await stream.ReadExactlyAsync(greeting, cancel.Token);
            await stream.WriteAsync(new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, 36, 228 }, cancel.Token); var reply = new byte[10]; await stream.ReadExactlyAsync(reply, cancel.Token); Require(reply[1] == 0, "SOCKS pool did not recover");
            byte[] payload = Encoding.UTF8.GetBytes("one application payload"), returned = new byte[payload.Length];
            await stream.WriteAsync(payload, cancel.Token); await stream.ReadExactlyAsync(returned, cancel.Token); Require(payload.SequenceEqual(returned), "recovered transfer changed bytes");
            await RefreshAsync(); Require(PoolRecovered.Text == "1" && PoolLastOutbound.Text == "备线 · 本机 HTTPS 服务", "recovery counters/winner not visible");
            var flow = flows.Single(); Navigate(NavConnections, new RoutedEventArgs()); FlowGrid.SelectedItem = flow;
            Require(FlowDetail.Text.Contains("主线 · 认证失败演示（未接通") && FlowDetail.Text.Contains("备线 · 本机 HTTPS 服务（已接通"), "connection detail omitted attempts");
            Notice.Visibility = Visibility.Collapsed; await capture(this, "pool-recovery-connection");
            checks.Add("actual SOCKS ingress recovers from proxy authentication failure and displays both attempts and actual winner");
            Navigate(NavPools, new RoutedEventArgs());
            Click(PoolToggle); await Settled();
            for (int i = 0; i < 100; i++) { await RefreshAsync(); if (PoolHealthCount.Text == "1 / 2") break; await Task.Delay(30, cancel.Token); }
            Require(PoolHealthCount.Text == "1 / 2", "real TLS/HTTP checks did not reach dashboard: " + snapshot?["pools"]?.ToJsonString() + " " + string.Join("; ", fixtureErrors));
            Require(PoolMemberGrid.Items.Cast<PoolMemberRow>().Any(r => r.State == "HTTPS 可用"), "healthy row missing");
            Require(PoolMemberGrid.Items.Cast<PoolMemberRow>().Any(r => r.State is "HTTPS 不可用" or "建连冷却"), "failed row missing");
            var source = PoolMemberGrid.ItemsSource; RefreshPoolState(); Require(ReferenceEquals(source, PoolMemberGrid.ItemsSource), "unchanged refresh rebuilt members");
            Notice.Visibility = Visibility.Collapsed; Width = 1280; Height = 840; await capture(this, "pools-live-1280"); Width = 980; Height = 700; await capture(this, "pools-live-980");
            checks.Add("dashboard displays real loopback HTTPS checks, recovery totals and recent samples without rebuilding unchanged rows");
            var group = SelectedPool!.DeepClone().AsObject(); group["name"] = "改名后的自动线路池"; await SavePoolAsync("日常工作 · 自动备用", group);
            Require(S(profile, "finalPolicy") == "改名后的自动线路池", "pool rename lost default reference");
            await stream.WriteAsync(payload, cancel.Token); await stream.ReadExactlyAsync(returned, cancel.Token); Require(payload.SequenceEqual(returned), "pool rename interrupted established transfer");
            disk = File.ReadAllBytes(Storage.WorkspacePath); File.SetAttributes(Storage.WorkspacePath, FileAttributes.ReadOnly); bool rejected = false;
            try { var changed = group.DeepClone().AsObject(); changed["pool"]!["monitor"] = false; await SavePoolAsync(S(group, "name"), changed); }
            catch (IOException) { rejected = true; } catch (UnauthorizedAccessException) { rejected = true; }
            finally { File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal); }
            Require(rejected && disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)) && SelectedPool!["pool"]!["monitor"]!.GetValue<bool>(), "failed save did not roll back pool");
            Require((await client.CallAsync("snapshot"))["pools"]![0]!["monitor"]!.GetValue<bool>(), "failed save did not restore engine monitoring");
            Require(WorkspaceHistory.Read().Any(revision => (revision.State.Profile["groups"] as JsonArray ?? []).Any(g => g?["pool"] != null)), "history omitted pool revisions");
            checks.Add("pool rename updates references without moving established flows; failed save restores disk and runtime; history retains options");
            Click(PoolToggle); await Settled(); await Task.Delay(350, cancel.Token);
            int count = goodRequests + badRequests; await Task.Delay(350, cancel.Token); Require(count == goodRequests + badRequests, "pause kept scheduling checks");
            Require(!PoolCheck.IsEnabled && PoolToggle.Content as string == "恢复监测", "pause controls did not update");
            checks.Add("pause stops monitoring and disables manual checks until resumed");
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0, ["fixture"] = "Loopback 407 proxy plus trusted local TLS/HTTP responder; real recovered SOCKS payload", ["checks"] = new JsonArray(checks.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()) };
        }
        finally
        {
            if (File.Exists(Storage.WorkspacePath)) File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal);
            if (running) await StopAsync(); cancel.Cancel(); bad.Stop(); good.Stop();
            try { await Task.WhenAll(badServer, goodServer); } catch (OperationCanceledException) { } catch (SocketException) when (cancel.IsCancellationRequested) { }
            snapshot = previousSnapshot; Width = 1280; Height = 840; await SaveAsync(previous, subscriptions); Navigate(NavOverview, new RoutedEventArgs()); Notice.Visibility = Visibility.Collapsed;
            if (timerWasEnabled) timer.Start();
        }
        async Task Accept(TcpListener listener, bool working)
        {
            var workers = new List<Task>();
            try { while (!cancel.IsCancellationRequested) workers.Add(Respond(await listener.AcceptTcpClientAsync(cancel.Token), working)); }
            finally { await Task.WhenAll(workers); }
        }
        async Task<string> Header(Stream stream)
        {
            var bytes = new List<byte>(); var one = new byte[1];
            while (bytes.Count < 8192)
            {
                if (await stream.ReadAsync(one, cancel.Token) == 0) return ""; bytes.Add(one[0]);
                if (bytes.Count >= 4 && bytes.TakeLast(4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) return Encoding.ASCII.GetString(bytes.ToArray());
            }
            throw new InvalidOperationException("Fixture header limit exceeded");
        }
        async Task Respond(TcpClient peer, bool working)
        {
            using (peer)
            {
                try
                {
                    var stream = peer.GetStream(); string header = await Header(stream); if (header.Length == 0) return;
                    if (!working) { Interlocked.Increment(ref badRequests); await stream.WriteAsync("HTTP/1.1 407 Authentication Required\r\n\r\n"u8.ToArray(), cancel.Token); return; }
                    Interlocked.Increment(ref goodRequests); await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), cancel.Token);
                    if (header.StartsWith("CONNECT localhost:9443 ", StringComparison.Ordinal))
                    {
                        using var tls = new SslStream(stream); await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, cancel.Token);
                        Require((await Header(tls)).StartsWith("HEAD /health HTTP/1.1", StringComparison.Ordinal), "monitor did not request configured health path");
                        await tls.WriteAsync("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"u8.ToArray(), cancel.Token);
                    }
                    else
                    {
                        byte[] bytes = new byte[4096]; int length;
                        while ((length = await stream.ReadAsync(bytes, cancel.Token)) > 0) await stream.WriteAsync(bytes.AsMemory(0, length), cancel.Token);
                    }
                }
                catch (OperationCanceledException) { }
                catch (IOException error) { fixtureErrors.Add(error.Message); }
                catch (System.Security.Authentication.AuthenticationException error) { fixtureErrors.Add(error.Message); }
            }
        }
    }
}
