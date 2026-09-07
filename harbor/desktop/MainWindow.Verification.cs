using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace Harbor;

public partial class MainWindow
{
    private CancellationTokenSource? verificationCancellation;
    private Task? verificationTask;
    private bool verifying => verificationCancellation != null;
    private VerificationHistory lineChecks = new();
    private string verificationStatus = "按当前列表逐条检查 HTTPS；耗时不代表下载速度。";

    private async void VerifySelected(object sender, RoutedEventArgs e)
    {
        string name = ReferenceEquals(sender, HomeVerify) ? S(profile, "finalPolicy") : (NodeGrid.SelectedItem as NodeRow)?.Name ?? "";
        if (VerificationHistory.Fingerprint(profile, name) == null) { ShowNotice("请先选择一条具体线路。"); return; }
        await BeginVerificationAsync([name]);
    }

    private async void VerifyVisible(object sender, RoutedEventArgs e) =>
        await BeginVerificationAsync(NodeGrid.Items.OfType<NodeRow>().Select(row => row.Name).ToArray());

    private async Task BeginVerificationAsync(string[] names)
    {
        if (verifying || busy || client == null || names.Length == 0) return;
        var testedProfile = profile.DeepClone().AsObject();
        using var cancellation = new CancellationTokenSource();
        verificationCancellation = cancellation;
        verificationTask = RunVerificationAsync(names, testedProfile, cancellation.Token);
        SyncHome();
        try { await verificationTask; }
        finally
        {
            verificationCancellation = null;
            verificationTask = null;
            if (!quitting) { RefreshNodes(); SyncHome(); }
        }
    }

    private async Task RunVerificationAsync(string[] names, JsonObject testedProfile, CancellationToken token)
    {
        string? saveError = null;
        try
        {
            var result = await VerificationBatch.RunAsync(names, async (name, cancellation) =>
            {
                string? fingerprint = VerificationHistory.Fingerprint(testedProfile, name);
                // Imported/edited nodes must never receive an outcome from an older configuration.
                if (fingerprint == null || fingerprint != VerificationHistory.Fingerprint(profile, name)) return VerificationOutcome.Skipped;
                bool success;
                ulong elapsed = 0;
                string failure = "";
                try
                {
                    var response = await client!.CallAsync("verify", new JsonObject { ["config"] = testedProfile.DeepClone(), ["outbound"] = name }, 25, cancellation);
                    elapsed = N(response, "elapsedMs"); success = true;
                }
                catch (Exception error)
                {
                    cancellation.ThrowIfCancellationRequested();
                    if (error.Message.Contains("cancel", StringComparison.OrdinalIgnoreCase)) throw new OperationCanceledException("线路验证已取消。", error);
                    success = false; failure = ConnectionFailure.Describe(error.Message);
                }
                cancellation.ThrowIfCancellationRequested();
                if (quitting || fingerprint != VerificationHistory.Fingerprint(profile, name)) return VerificationOutcome.Skipped;
                string? persistenceError = RememberLineCheck(name, success, elapsed, failure);
                saveError ??= persistenceError;
                return success ? VerificationOutcome.Success : VerificationOutcome.Failure;
            }, progress =>
            {
                verificationStatus = $"已完成 {progress.Completed} / {progress.Total} · 成功 {progress.Successful} · 未通过 {progress.Failed}" + (progress.Skipped > 0 ? $" · 已跳过 {progress.Skipped}" : "");
                BatchProgress.Maximum = Math.Max(1, progress.Total); BatchProgress.Value = progress.Completed;
                SyncVerificationControls();
            }, token);
            verificationStatus = (token.IsCancellationRequested ? "已取消 · " : "验证完成 · ") + $"{result.Completed} / {result.Total} · 成功 {result.Successful} · 未通过 {result.Failed}" + (result.Skipped > 0 ? $" · 设置已变更 {result.Skipped}" : "");
            if (!quitting) ShowNotice(verificationStatus + "。" + (token.IsCancellationRequested ? "已完成的结果保留，未完成的线路不记为失败。" : "目标 www.example.com；结果已更新到线路列表。") + saveError);
        }
        catch (OperationCanceledException) { verificationStatus = "验证已取消，已完成的结果保留。"; }
        catch (Exception error) { verificationStatus = "验证未完成：" + ConnectionFailure.Describe(error.Message); if (!quitting) ShowNotice(verificationStatus); }
    }

    private void CancelVerification(object sender, RoutedEventArgs e)
    {
        verificationCancellation?.Cancel();
        verificationStatus = "正在取消，保留已完成的结果…";
        SyncVerificationControls();
    }

    private async Task CancelVerificationAsync()
    {
        verificationCancellation?.Cancel();
        if (verificationTask is { } task) await task;
    }

    private void SyncVerificationControls()
    {
        if (VerifyVisibleButton == null) return;
        VerifyVisibleButton.IsEnabled = !busy && !verifying && client != null && NodeGrid.Items.Count > 0;
        VerifyNodeButton.IsEnabled = !busy && !verifying && client != null && NodeGrid.SelectedItem != null;
        CancelVerificationButton.Visibility = verifying ? Visibility.Visible : Visibility.Collapsed;
        CancelVerificationButton.IsEnabled = verificationCancellation?.IsCancellationRequested == false;
        ClearLineChecksButton.IsEnabled = !verifying;
        BatchProgress.Visibility = verifying ? Visibility.Visible : Visibility.Collapsed;
        BatchStatus.Text = verificationStatus;
    }

    private string? RememberLineCheck(string name, bool success, ulong elapsed, string failure = "")
    {
        try { lineChecks.Record(profile, name, success, elapsed, DateTimeOffset.UtcNow, failure); return null; }
        catch (Exception error) { return " 验证结果未能保存：" + error.Message; }
        finally { RefreshNodes(); SyncHome(); }
    }

    private void FilterNodes(object sender, RoutedEventArgs e) { if (NodeGrid != null && NodeSearch != null && NodeFilter != null) RefreshNodes(); }
    private void ResetNodeFilter(object sender, RoutedEventArgs e) { NodeSearch.Text = ""; NodeFilter.SelectedIndex = 0; NodeSort.SelectedIndex = 0; }
    private void NodeSelected(object sender, RoutedEventArgs e) => SyncVerificationControls();
    private void ClearLineChecks(object sender, RoutedEventArgs e)
    {
        try { if (verifying) return; lineChecks.Clear(); verificationStatus = "验证记录已清除，可重新检查当前列表。"; RefreshNodes(); SyncHome(); ShowNotice("已清除本机保存的线路验证记录。"); }
        catch (Exception error) { ShowNotice("清除失败：" + error.Message); }
    }
}
