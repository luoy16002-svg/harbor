using System.Threading.Tasks;
using System.Windows;

namespace Harbor;

public partial class MainWindow
{
    private async void EditDirectExceptions(object sender, RoutedEventArgs e) => await Safe(async () =>
    {
        var dialog = new DirectExceptionsDialog(this, DirectExceptions.Read(profile));
        if (dialog.ShowDialog() != true || dialog.Result == null) return;
        await ApplyDirectExceptionsAsync(dialog.Result);
    });

    private async Task ApplyDirectExceptionsAsync(DirectExceptionSettings settings)
    {
        var candidate = profile.DeepClone().AsObject(); candidate["directExceptions"] = settings.ToJson();
        await SaveAsync(candidate);
        ExplainResult.Text = "直连例外已改变，可重新检查域名路径。";
        ShowNotice("直连例外已保存。" + (running ? "新连接使用新设置，已有连接保留原出口。" : "连接后生效。"));
    }
}
