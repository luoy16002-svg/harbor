using System;
using System.IO;
using System.Threading;
using System.Windows;

namespace Harbor;
public partial class App : Application
{
    internal static bool Isolated { get; private set; }
    private Mutex? instance;
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        bool known = e.Args.Length switch
        {
            0 => true,
            1 => e.Args[0] == "--recover",
            2 => e.Args[0] is "--isolated" or "--visual-check" or "--guard" or "--data-dir",
            4 => e.Args[0] == "--after-exit",
            _ => false,
        };
        if (!known) { Console.Error.WriteLine("Invalid Harbor arguments. Isolation requires: --isolated DATA_DIRECTORY"); Shutdown(2); return; }
        if (e.Args.Length == 2 && e.Args[0] == "--isolated")
        {
            Isolated = true; NetworkSafety.ProhibitSystemWrites(); Storage.Root = Path.GetFullPath(e.Args[1]);
        }
        if (e.Args.Length == 4 && e.Args[0] == "--after-exit")
        {
            Storage.Root = Path.GetFullPath(e.Args[3]);
            try { using var previous = System.Diagnostics.Process.GetProcessById(int.Parse(e.Args[1])); if (previous.StartTime.ToUniversalTime().Ticks == long.Parse(e.Args[2])) await previous.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
            catch (ArgumentException) { }
            catch (InvalidOperationException) { }
            catch (TimeoutException) { MessageBox.Show("上一个 Harbor 窗口仍在退出，请稍后重试。", "Harbor"); Shutdown(1); return; }
        }
        if (e.Args.Length == 2 && e.Args[0] == "--visual-check")
        {
            Isolated = true;
            NetworkSafety.ProhibitSystemWrites();
            Storage.Root = Path.Combine(Path.GetFullPath(e.Args[1]), "data");
            var check = new MainWindow(); MainWindow = check; check.Show();
            await check.Ready.Task;
            try { await VisualCheck.RunAsync(check, Path.GetFullPath(e.Args[1])); }
            catch (Exception error)
            {
                File.WriteAllText(Path.Combine(Path.GetFullPath(e.Args[1]), "visual-error.txt"), error.ToString());
                check.Close(); Shutdown(1); return;
            }
            check.Close(); return;
        }
        if (e.Args.Length == 2 && e.Args[0] == "--guard") { Shutdown(await Recovery.GuardAsync(e.Args[1])); return; }
        if (e.Args.Length > 0 && e.Args[0] == "--recover")
        {
            try { Console.WriteLine(Recovery.Restore(Storage.JournalPath, true).Message); Shutdown(0); }
            catch (Exception error) { Console.Error.WriteLine(error.Message); Shutdown(1); }
            return;
        }
        if (e.Args.Length == 2 && e.Args[0] == "--data-dir") Storage.Root = Path.GetFullPath(e.Args[1]);
        instance = new Mutex(true, "Local\\Harbor.Desktop." + System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value, out bool created);
        if (!created) { MessageBox.Show("Harbor 已在运行，可从系统托盘打开。", "Harbor"); Shutdown(); return; }
        DispatcherUnhandledException += (_, args) => { MessageBox.Show(args.Exception.Message, "Harbor", MessageBoxButton.OK, MessageBoxImage.Error); args.Handled = true; };
        var window = new MainWindow(); MainWindow = window; window.Show();
    }
    protected override void OnExit(ExitEventArgs e) { instance?.Dispose(); base.OnExit(e); }
}
