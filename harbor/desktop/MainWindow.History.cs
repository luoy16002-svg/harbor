using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace Harbor;

public partial class MainWindow
{
    private void RefreshWorkspaceHistorySummary()
    {
        try
        {
            var revisions = WorkspaceHistory.Read();
            WorkspaceHistorySummary.Text = revisions.Count == 0 ? "配置变更前自动保存，最多保留 10 个加密版本。" :
                $"已保留 {revisions.Count} 个加密版本 · 最近保存于 {revisions[0].Time}";
        }
        catch (Exception) { WorkspaceHistorySummary.Text = "配置历史无法读取。打开历史可查看提示或清空损坏的记录。"; }
    }

    private async void ShowWorkspaceHistory(object sender, RoutedEventArgs e)
    {
        if (busy || client == null) return;
        try
        {
            var dialog = new WorkspaceHistoryDialog(this, new WorkspaceState(profile, Subscriptions.Read()), !running && !changingConnection);
            if (dialog.ShowDialog() == true && dialog.Request is { } request) await Safe(() => RestoreWorkspaceAsync(request));
        }
        catch (Exception error) { ShowNotice(error.Message); }
        finally { RefreshWorkspaceHistorySummary(); }
    }

    private async Task RestoreWorkspaceAsync(WorkspaceRestoreRequest request)
    {
        if (client == null || running || changingConnection) throw new InvalidOperationException("请先断开连接，再恢复配置历史。");
        var selected = WorkspaceHistory.Read().FirstOrDefault(item => item.Id == request.Id)
            ?? throw new InvalidOperationException("所选历史版本已变化，请重新打开配置历史。");
        var current = Storage.LoadWorkspace() ?? throw new InvalidOperationException("当前配置不存在，无法恢复。");
        if (!WorkspaceHistory.SameConfiguration(current, request.Current) ||
            !System.Text.Json.Nodes.JsonNode.DeepEquals(profile, request.Current.Profile) ||
            !WorkspaceHistory.SameConfiguration(selected.State, request.Selected))
            throw new InvalidOperationException("配置在预览后发生了变化，请重新打开历史并检查差异。");
        var candidate = WorkspaceHistory.PrepareRestore(selected.State);
        await CancelSubscriptionRefreshAsync(); await CancelVerificationAsync();
        await SaveAsync(candidate.Profile, candidate.Subscriptions);
        snapshot = null; RefreshNodes(); SyncHome(); RefreshWorkspaceHistorySummary();
        ShowNotice("历史配置已恢复，保持断开。恢复前的配置已保留；订阅用量需手动刷新。");
    }
}
