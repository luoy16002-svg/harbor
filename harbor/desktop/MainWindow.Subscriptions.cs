using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Harbor;

public partial class MainWindow
{
    private CancellationTokenSource? subscriptionCancellation;
    private Task? subscriptionTask;
    private bool applyingSubscription;
    private string subscriptionStatus = "更新前可检查线路变化；下载过程中可以取消。";

    private void RefreshSubscriptionGrid()
    {
        try
        {
            string? selected = (SubscriptionGrid.SelectedItem as SubscriptionRow)?.Id;
            var rows = Subscriptions.Read().Select(entry => new SubscriptionRow(entry.Id, entry.Name, Subscriptions.DisplayAddress(entry.Url),
                entry.NodeNames.Length, entry.UnsupportedCount, entry.UpdatedAt.ToLocalTime().ToString("MM-dd HH:mm"), entry.Usage?.Summary ?? "服务商未提供", entry.Usage?.ExpiresAt is { } expires ? expires.ToLocalTime().ToString("yyyy-MM-dd") : "未提供", entry.Usage)).ToList();
            SubscriptionGrid.ItemsSource = rows;
            SubscriptionGrid.SelectedItem = rows.FirstOrDefault(row => row.Id == selected) ?? rows.FirstOrDefault();
            SyncSubscriptionControls();
        }
        catch (Exception error) { ShowNotice(error.Message); }
    }

    private async void AddSubscription(object sender, RoutedEventArgs e)
    {
        if (subscriptionCancellation != null || busy) return;
        var form = new FormDialog(this, "添加订阅").Field("name", "订阅名称", "订阅 " + (Subscriptions.Read().Count + 1)).Field("url", "HTTPS 订阅地址", "", secret: true);
        if (form.ShowDialog() != true) return;
        await Safe(async () =>
        {
            string name = form.Get("name").Trim();
            if (string.IsNullOrWhiteSpace(name) || name.Length > 40) throw new FormatException("订阅名称须为 1–40 个字符。");
            var entries = Subscriptions.Read();
            if (entries.Any(entry => entry.Name == name)) throw new FormatException("已有同名订阅。");
            string url = form.Get("url").Trim();
            if (entries.Any(entry => entry.Url == url)) throw new FormatException("该订阅已存在，可直接更新。");
            var download = await Subscriptions.FetchAsync(url, running ? S(profile, "listen") : null);
            var result = ProfileImport.Parse(download.Text);
            if (new ImportPreview(this, result).ShowDialog() != true) return;
            var candidate = Subscriptions.Merge(profile, result.Nodes, null, name + " · ", out var names, out _);
            ProfileWorkflow.SelectFirstImport(profile, candidate);
            entries.Add(new SubscriptionEntry(Guid.NewGuid().ToString("N"), name, url, names, DateTimeOffset.UtcNow, download.Etag, download.LastModified, download.Digest, result.Issues.Count, download.Usage));
            await SaveAsync(candidate, entries); ShowNotice($"已添加订阅，导入 {names.Length} 个节点。");
        });
    }

    private async void RefreshSubscription(object sender, RoutedEventArgs e)
    {
        if (SubscriptionGrid.SelectedItem is SubscriptionRow row) await BeginSubscriptionRefreshAsync(row.Id);
    }

    private async Task BeginSubscriptionRefreshAsync(string id,
        Func<SubscriptionEntry, CancellationToken, Task<DownloadedSubscription>>? fetch = null,
        Func<SubscriptionUpdate, bool>? review = null)
    {
        if (subscriptionCancellation != null || busy || client == null) return;
        var previous = Subscriptions.Read().FirstOrDefault(entry => entry.Id == id);
        if (previous == null) return;
        using var cancellation = new CancellationTokenSource();
        subscriptionCancellation = cancellation; subscriptionStatus = "正在下载 " + previous.Name + "…";
        SyncSubscriptionControls();
        subscriptionTask = RunSubscriptionRefreshAsync(previous, cancellation.Token, fetch, review);
        try { await subscriptionTask; }
        finally { subscriptionCancellation = null; subscriptionTask = null; applyingSubscription = false; if (!quitting) SyncSubscriptionControls(); }
    }

    private async Task RunSubscriptionRefreshAsync(SubscriptionEntry previous, CancellationToken token,
        Func<SubscriptionEntry, CancellationToken, Task<DownloadedSubscription>>? fetch, Func<SubscriptionUpdate, bool>? review)
    {
        try
        {
            var download = await (fetch != null ? fetch(previous, token) : Subscriptions.FetchAsync(previous.Url, running ? S(profile, "listen") : null, previous, token));
            token.ThrowIfCancellationRequested();
            if (busy) throw new InvalidOperationException("其他配置操作正在进行，请完成后重试订阅更新。");
            var entries = Subscriptions.Read(); int index = entries.FindIndex(entry => entry.Id == previous.Id);
            if (index < 0 || !SameSubscription(entries[index], previous)) throw new InvalidOperationException("订阅记录已发生变化，请重新更新。");
            var update = SubscriptionUpdate.Prepare(profile, entries[index], download, DateTimeOffset.UtcNow);
            bool saved = false, declined = false;
            await Safe(async () =>
            {
                // The modal review and atomic apply own the configuration lock;
                // the potentially slow download above leaves connection controls usable.
                if (!update.ContentUnchanged && !(review?.Invoke(update) ?? new SubscriptionUpdatePreview(this, update).ShowDialog() == true)) { declined = true; return; }
                token.ThrowIfCancellationRequested();
                applyingSubscription = true; subscriptionStatus = "正在应用订阅更新…"; SyncSubscriptionControls();
                entries[index] = update.Entry;
                if (update.ContentUnchanged) { Subscriptions.Save(entries); RefreshSubscriptionGrid(); }
                else await SaveAsync(update.Profile, entries);
                saved = true;
            });
            subscriptionStatus = saved ? update.ContentUnchanged ? "线路内容未变化，已刷新订阅信息。" : "订阅已更新 · " + update.Summary :
                declined || token.IsCancellationRequested ? "未应用订阅更新，现有配置保留。" : "订阅未能保存，现有配置保留。";
            if (!quitting && saved) ShowNotice(subscriptionStatus);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { subscriptionStatus = "下载已取消，现有线路和订阅信息保留。"; }
        catch (Exception error)
        {
            subscriptionStatus = "订阅更新未完成，现有配置保留。";
            if (!quitting) ShowNotice(subscriptionStatus + " " + error.Message);
        }
    }

    private static bool SameSubscription(SubscriptionEntry left, SubscriptionEntry right) =>
        left.Id == right.Id && left.Name == right.Name && left.Url == right.Url && left.Digest == right.Digest && left.NodeNames.SequenceEqual(right.NodeNames);

    private void CancelSubscriptionRefresh(object sender, RoutedEventArgs e)
    {
        if (applyingSubscription) return;
        subscriptionCancellation?.Cancel(); subscriptionStatus = "正在取消订阅下载…"; SyncSubscriptionControls();
    }

    private async Task CancelSubscriptionRefreshAsync()
    {
        if (!applyingSubscription) subscriptionCancellation?.Cancel();
        if (subscriptionTask is { } task) await task;
    }

    private async void RemoveSubscription(object sender, RoutedEventArgs e)
    {
        if (subscriptionCancellation != null || busy) return;
        await Safe(() =>
        {
            if (SubscriptionGrid.SelectedItem is SubscriptionRow row)
            {
                var entries = Subscriptions.Read(); entries.RemoveAll(entry => entry.Id == row.Id); Subscriptions.Save(entries); RefreshSubscriptionGrid();
                ShowNotice("已移除订阅地址，节点和分流设置保留。");
            }
            return Task.CompletedTask;
        });
    }

    private void SubscriptionSelected(object sender, RoutedEventArgs e) => SyncSubscriptionControls();
    private void SyncSubscriptionControls()
    {
        if (SubscriptionStatus == null || SubscriptionGrid == null || SubscriptionUsageDetail == null) return;
        bool active = subscriptionCancellation != null;
        var selected = SubscriptionGrid.SelectedItem as SubscriptionRow;
        RefreshSubscriptionButton.IsEnabled = !active && !busy && client != null && selected != null;
        AddSubscriptionButton.IsEnabled = RemoveSubscriptionButton.IsEnabled = !active && !busy;
        RemoveSubscriptionButton.IsEnabled &= selected != null;
        CancelSubscriptionButton.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        CancelSubscriptionButton.IsEnabled = active && !applyingSubscription && !subscriptionCancellation!.IsCancellationRequested;
        SubscriptionStatus.Text = subscriptionStatus;
        SubscriptionDownloadProgress.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
        SubscriptionUsageTitle.Text = selected == null ? "服务商统计" : selected.Name + " · 服务商统计";
        SubscriptionUsageTitle.ToolTip = selected == null ? null : selected.Name + "\n" + selected.Address;
        SubscriptionUsageText.Text = selected?.Usage?.Summary ?? "服务商未提供流量信息";
        SubscriptionUsageRemaining.Text = selected?.Usage?.Remaining ?? "这不代表零用量或无限额度。";
        SubscriptionUsageExpiry.Text = selected?.Usage?.Expiry(DateTimeOffset.UtcNow) ?? "未提供到期时间";
        SubscriptionUsageDetail.Text = selected?.Usage?.Detail ?? "服务商提供流量信息后，会在此显示；这些信息与本机流量计数独立。";
        SubscriptionUsageProgress.Visibility = selected?.Usage is { Total: > 0 } ? Visibility.Visible : Visibility.Collapsed;
        SubscriptionUsageProgress.Value = selected?.Usage?.Percent ?? 0;
    }

    private sealed record SubscriptionRow(string Id, string Name, string Address, int Count, int Unsupported, string Updated, string UsageText, string Expiry, SubscriptionUsage? Usage);
}
