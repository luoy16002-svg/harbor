using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    internal async Task<JsonObject> CheckDirectExceptionsAsync(Func<Window, string, Task> capture)
    {
        if (!App.Isolated || !NetworkSafety.SystemWritesProhibited || client == null || running) throw new InvalidOperationException("Exception checks require isolation.");
        var previous = profile.DeepClone().AsObject(); var entries = Subscriptions.Read();
        bool timerWasEnabled = timer.IsEnabled; timer.Stop();
        var checks = new List<string>();
        void Require(bool value, string message) { if (!value) throw new InvalidOperationException("Direct exceptions: " + message); }
        void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        DirectExceptionsDialog Dialog(Func<DirectExceptionsDialog, Task> action)
        {
            var dialog = new DirectExceptionsDialog(this, DirectExceptions.Read(profile)); Exception? failure = null;
            dialog.Loaded += async (_, _) => { try { await action(dialog); } catch (Exception error) { failure = error; dialog.DialogResult = false; } };
            dialog.ShowDialog(); if (failure != null) throw new InvalidOperationException("Exception dialog failed", failure);
            return dialog;
        }
        async Task<JsonObject> Explain(string host) => (await client.CallAsync("explain", new JsonObject { ["host"] = host, ["port"] = 443 })).AsObject();
        try
        {
            var fixture = (await client.CallAsync("default_config")).AsObject(); fixture.Remove("directExceptions");
            fixture["listen"] = "127.0.0.1:" + FreePort(); fixture["dnsListen"] = "127.0.0.1:" + FreePort();
            fixture["dnsTls"] = new JsonArray(); fixture["dnsServers"] = new JsonArray("127.0.0.1:9");
            fixture["nodes"] = new JsonArray(new JsonObject { ["name"] = "本机工作线路", ["kind"] = "socks5", ["server"] = "127.0.0.1", ["port"] = 9 });
            fixture["finalPolicy"] = "本机工作线路"; fixture["routingMode"] = "direct";
            await SaveAsync(fixture, []); await StartAsync();
            fixture = profile.DeepClone().AsObject(); fixture["routingMode"] = "global"; await SaveAsync(fixture);
            byte[] disk = File.ReadAllBytes(Storage.WorkspacePath);
            Dialog(dialog => { Click(dialog.GameButton); Click(dialog.VideoButton); Click(dialog.CancelButton); return Task.CompletedTask; });
            Require(disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)) && !DirectExceptions.Read(profile).Enabled, "cancel modified saved settings");
            checks.Add("cancel after editing both presets leaves disk and active settings untouched");
            var accepted = Dialog(async dialog =>
            {
                Click(dialog.GameButton); Click(dialog.GameButton); Click(dialog.VideoButton);
                var draft = DirectExceptions.Parse(dialog.EnabledInput.IsChecked == true, dialog.DomainsInput.Text, dialog.ProcessesInput.Text);
                Require(draft.Processes.Length == 6 && draft.Domains.Length == 26, "presets did not merge idempotently");
                await capture(dialog, "direct-exceptions-editor"); dialog.Width = 620; dialog.Height = 560; await capture(dialog, "direct-exceptions-editor-620");
                Click(dialog.SaveButton);
            });
            Require(accepted.Result != null, "save button did not produce settings");
            await ApplyDirectExceptionsAsync(accepted.Result!);
            Require(DirectExceptions.Read(Storage.LoadWorkspace()!.Profile).Enabled && HomeRoutingDescription.Text.Contains("例外"), "save did not update disk and mode description");
            Require(S(await Explain("api.bilibili.com"), "outbound") == "DIRECT" && S(await Explain("sdk.mihoyo.com"), "outbound") == "DIRECT", "global mode skipped domain exceptions");
            Require(S(await Explain("work.fixture.invalid"), "outbound") == "本机工作线路" && S(await Explain("notbilibili.com"), "outbound") == "本机工作线路", "global fallback changed for nonmatching domains");
            checks.Add("preset save preserves global mode, directs game and video domains, and keeps unrelated work on the chosen outbound");
            Require(WorkspaceHistory.Read().Any(v => !DirectExceptions.Read(v.State.Profile).Enabled), "save omitted previous exception settings from history");
            checks.Add("normal save retains the previous exception configuration in encrypted history");
            Dialog(dialog =>
            {
                dialog.DomainsInput.Text = "https://bilibili.com"; Click(dialog.SaveButton);
                Require(dialog.Result == null && dialog.ErrorText.Text.Length > 0 && dialog.IsVisible, "invalid input closed or saved the dialog");
                Click(dialog.CancelButton); return Task.CompletedTask;
            });
            checks.Add("invalid domain input stays in the editor with an actionable error");
            disk = File.ReadAllBytes(Storage.WorkspacePath); File.SetAttributes(Storage.WorkspacePath, FileAttributes.ReadOnly);
            bool rejected = false;
            try { await ApplyDirectExceptionsAsync(accepted.Result! with { Enabled = false }); } catch (IOException) { rejected = true; } catch (UnauthorizedAccessException) { rejected = true; }
            finally { File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal); }
            Require(rejected && disk.SequenceEqual(File.ReadAllBytes(Storage.WorkspacePath)) && DirectExceptions.Read(profile).Enabled && S(await Explain("bilibili.com"), "outbound") == "DIRECT", "failed save did not restore disk, UI and live policy");
            checks.Add("failed atomic persistence restores the saved and running exception policy");
            Navigate(NavRouting, new RoutedEventArgs()); RoutingPage.ScrollToTop(); Notice.Visibility = Visibility.Collapsed;
            Width = 1280; Height = 840; await capture(this, "routing-exceptions-1280"); Width = 980; Height = 700; await capture(this, "routing-exceptions-980");
            await ApplyDirectExceptionsAsync(accepted.Result! with { Enabled = false });
            Require(DirectExceptions.Read(profile).Domains.Length == 26 && S(await Explain("bilibili.com"), "outbound") == "本机工作线路", "disable discarded presets or retained the bypass");
            checks.Add("disabling exceptions preserves both lists and restores the default outbound");
            return new JsonObject { ["passed"] = true, ["externalRequests"] = 0, ["checks"] = new JsonArray(checks.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()) };
        }
        finally
        {
            if (File.Exists(Storage.WorkspacePath)) File.SetAttributes(Storage.WorkspacePath, FileAttributes.Normal);
            if (running) await StopAsync(); Width = 1280; Height = 840;
            await SaveAsync(previous, entries); Navigate(NavOverview, new RoutedEventArgs()); Notice.Visibility = Visibility.Collapsed;
            if (timerWasEnabled) timer.Start();
        }
    }
}
