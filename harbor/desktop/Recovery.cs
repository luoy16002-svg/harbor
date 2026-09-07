using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Harbor;

internal sealed record ProxySettings(uint Flags, string Server, string Bypass, string AutoConfigUrl)
{
    public static ProxySettings ForHarbor(string listen) => new(3, $"http={listen};https={listen}", "<local>;localhost;127.*;[::1]", "");
}
internal interface IProxyStore { ProxySettings Read(); void Write(ProxySettings settings); }
internal static class NetworkSafety
{
    public static bool SystemWritesProhibited { get; private set; }
    public static void ProhibitSystemWrites() => SystemWritesProhibited = true;
    public static void EnsureSystemWritesAllowed()
    {
        if (SystemWritesProhibited) throw new InvalidOperationException("隔离模式禁止修改系统网络。");
    }
}

internal sealed class WindowsProxyStore : IProxyStore
{
    [StructLayout(LayoutKind.Explicit)] private struct Value { [FieldOffset(0)] public uint Number; [FieldOffset(0)] public IntPtr Text; }
    [StructLayout(LayoutKind.Sequential)] private struct Option { public uint Id; public Value Value; }
    [StructLayout(LayoutKind.Sequential)] private struct OptionList { public uint Size; public IntPtr Connection; public uint Count; public uint Error; public IntPtr Options; }
    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool InternetQueryOptionW(IntPtr handle, uint option, ref OptionList buffer, ref uint length);
    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool InternetSetOptionW(IntPtr handle, uint option, ref OptionList buffer, uint length);
    [DllImport("wininet.dll", SetLastError = true, EntryPoint = "InternetSetOptionW")] private static extern bool Notify(IntPtr handle, uint option, IntPtr buffer, uint length);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr handle);

    public ProxySettings Read()
    {
        int size = Marshal.SizeOf<Option>(); var memory = Marshal.AllocHGlobal(size * 4);
        uint[] ids = [10, 2, 3, 4];
        for (int i = 0; i < 4; i++) Marshal.StructureToPtr(new Option { Id = ids[i] }, memory + size * i, false);
        var list = new OptionList { Size = (uint)Marshal.SizeOf<OptionList>(), Count = 4, Options = memory };
        try
        {
            uint length = list.Size;
            if (!InternetQueryOptionW(IntPtr.Zero, 75, ref list, ref length)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "无法读取 Windows 系统代理。");
            var values = Enumerable.Range(0, 4).Select(i => Marshal.PtrToStructure<Option>(memory + size * i)).ToArray();
            try { return new ProxySettings(values[0].Value.Number, Marshal.PtrToStringUni(values[1].Value.Text) ?? "", Marshal.PtrToStringUni(values[2].Value.Text) ?? "", Marshal.PtrToStringUni(values[3].Value.Text) ?? ""); }
            finally { for (int i = 1; i < 4; i++) if (values[i].Value.Text != IntPtr.Zero) GlobalFree(values[i].Value.Text); }
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
    public void Write(ProxySettings settings)
    {
        NetworkSafety.EnsureSystemWritesAllowed();
        int size = Marshal.SizeOf<Option>(); var memory = Marshal.AllocHGlobal(size * 4);
        IntPtr[] strings = [Marshal.StringToHGlobalUni(settings.Server), Marshal.StringToHGlobalUni(settings.Bypass), Marshal.StringToHGlobalUni(settings.AutoConfigUrl)];
        try
        {
            Marshal.StructureToPtr(new Option { Id = 1, Value = new Value { Number = settings.Flags } }, memory, false);
            uint[] ids = [2, 3, 4];
            for (int i = 0; i < 3; i++) Marshal.StructureToPtr(new Option { Id = ids[i], Value = new Value { Text = strings[i] } }, memory + size * (i + 1), false);
            var list = new OptionList { Size = (uint)Marshal.SizeOf<OptionList>(), Count = 4, Options = memory };
            if (!InternetSetOptionW(IntPtr.Zero, 75, ref list, list.Size)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "无法修改 Windows 系统代理。");
            if (!Notify(IntPtr.Zero, 39, IntPtr.Zero, 0) || !Notify(IntPtr.Zero, 37, IntPtr.Zero, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "代理已写入，但 Windows 刷新通知失败。");
        }
        finally { foreach (var pointer in strings) Marshal.FreeHGlobal(pointer); Marshal.FreeHGlobal(memory); }
    }
}

internal sealed record Lease(ProxySettings Before, ProxySettings Applied, int UiPid, long UiStarted, int EnginePid, long EngineStarted, string Phase, string Listen = "");
internal sealed record RecoveryResult(string State, string Message);
internal static class Recovery
{
    private static readonly string MutexName = "Local\\Harbor.ProxyLease." + System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
    public static RecoveryResult Evaluate(IProxyStore store, Lease lease)
    {
        var current = store.Read();
        if (current == lease.Before) return new("unchanged", "系统网络已处于原始设置。");
        bool owned = current == lease.Applied;
        // The process may have died during a multi-option Windows write.
        if (lease.Phase == "prepared") owned = (current.Flags == lease.Before.Flags || current.Flags == lease.Applied.Flags)
            && (current.Server == lease.Before.Server || current.Server == lease.Applied.Server)
            && (current.Bypass == lease.Before.Bypass || current.Bypass == lease.Applied.Bypass)
            && (current.AutoConfigUrl == lease.Before.AutoConfigUrl || current.AutoConfigUrl == lease.Applied.AutoConfigUrl);
        if (!owned) return new("conflict", "系统代理已被其他程序修改，Harbor 保留了当前设置。");
        store.Write(lease.Before);
        if (store.Read() != lease.Before) throw new IOException("恢复后的系统代理与原始设置不一致。");
        return new("restored", "已恢复启动前的系统代理。");
    }
    private static T Locked<T>(Func<T> action)
    {
        using var mutex = new Mutex(false, MutexName); bool held = false;
        try { try { held = mutex.WaitOne(TimeSpan.FromSeconds(15)); } catch (AbandonedMutexException) { held = true; } if (!held) throw new TimeoutException("网络恢复操作仍在进行。"); return action(); }
        finally { if (held) mutex.ReleaseMutex(); }
    }
    public static RecoveryResult Restore(string path, bool requireOwnerDead = false) => NetworkSafety.SystemWritesProhibited ? new("isolated", "隔离模式：系统网络保持原状。") : Locked(() =>
    {
        var lease = Storage.Read<Lease>(path);
        if (lease == null) return new RecoveryResult("clean", "没有待恢复的网络设置。");
        if (requireOwnerDead && Alive(lease.UiPid, lease.UiStarted) && Alive(lease.EnginePid, lease.EngineStarted)) return new RecoveryResult("active", "当前会话仍在运行。");
        var result = Evaluate(new WindowsProxyStore(), lease);
        Storage.Write(Path.Combine(Path.GetDirectoryName(path)!, "last-recovery.dat"), new { time = DateTimeOffset.UtcNow, result });
        if (result.State == "conflict") File.Move(path, path + ".conflict", true); else File.Delete(path);
        return result;
    });
    public static async Task<Process> ApplyAsync(string listen, Process engine)
    {
        NetworkSafety.EnsureSystemWritesAllowed();
        Restore(Storage.JournalPath, true);
        var ui = Process.GetCurrentProcess();
        Lease lease = Locked(() =>
        {
            if (File.Exists(Storage.JournalPath)) throw new IOException("另一个 Harbor 会话仍持有系统代理。");
            var value = new Lease(new WindowsProxyStore().Read(), ProxySettings.ForHarbor(listen), ui.Id, ui.StartTime.ToUniversalTime().Ticks, engine.Id, engine.StartTime.ToUniversalTime().Ticks, "prepared", listen);
            Storage.Write(Storage.JournalPath, value); return value;
        });
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("--guard"); start.ArgumentList.Add(Storage.JournalPath);
        Process? guardian = null;
        try
        {
            guardian = Process.Start(start) ?? throw new IOException("无法启动网络恢复进程。");
            var ready = await guardian.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(8));
            if (ready != "READY" || guardian.HasExited || engine.HasExited) throw new IOException("网络恢复进程未就绪。");
            Locked(() =>
            {
                if (new WindowsProxyStore().Read() != lease.Before) throw new IOException("系统代理在启动期间发生变化，请重试。");
                new WindowsProxyStore().Write(lease.Applied);
                if (new WindowsProxyStore().Read() != lease.Applied) throw new IOException("系统代理写入验证失败。");
                Storage.Write(Storage.JournalPath, lease with { Phase = "applied" }); return true;
            });
            return guardian;
        }
        catch { Restore(Storage.JournalPath); if (guardian != null && !guardian.HasExited) guardian.Kill(); guardian?.Dispose(); throw; }
    }
    private static bool Alive(int pid, long started)
    {
        try { using var process = Process.GetProcessById(pid); return !process.HasExited && process.StartTime.ToUniversalTime().Ticks == started; }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }
    public static async Task<int> GuardAsync(string path)
    {
        if (NetworkSafety.SystemWritesProhibited) return 1;
        try
        {
            var lease = Storage.Read<Lease>(path) ?? throw new IOException("Missing recovery lease.");
            using var ui = Process.GetProcessById(lease.UiPid); using var engine = Process.GetProcessById(lease.EnginePid);
            if (ui.StartTime.ToUniversalTime().Ticks != lease.UiStarted || engine.StartTime.ToUniversalTime().Ticks != lease.EngineStarted) throw new IOException("Process identity changed.");
            Console.WriteLine("READY"); Console.Out.Flush();
            var ownerExit = Task.WhenAny(ui.WaitForExitAsync(), engine.WaitForExitAsync()); int failures = 0;
            while (true)
            {
                if (await Task.WhenAny(ownerExit, Task.Delay(2000)) == ownerExit) break;
                if (!File.Exists(path)) return 0;
                if (lease.Listen.Length > 0) { failures = await HealthyAsync(lease.Listen) ? 0 : failures + 1; if (failures >= 3) break; }
            }
            for (int i = 0; i < 3; i++)
            {
                try { Restore(path); if (Alive(lease.EnginePid, lease.EngineStarted)) engine.Kill(); return 0; }
                catch when (i < 2) { await Task.Delay(500); }
            }
            return 1;
        }
        catch (Exception error) { Console.Error.WriteLine(error.Message); try { Restore(path, true); } catch (Exception recoveryError) { Console.Error.WriteLine(recoveryError.Message); } return 1; }
    }
    private static async Task<bool> HealthyAsync(string listen)
    {
        if (!System.Net.IPEndPoint.TryParse(listen, out var endpoint) || !System.Net.IPAddress.IsLoopback(endpoint.Address)) return false;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2)); using var socket = new System.Net.Sockets.TcpClient(endpoint.AddressFamily);
        try { await socket.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token); using var stream = socket.GetStream(); await stream.WriteAsync(new byte[] { 5, 1, 0 }, timeout.Token); var reply = new byte[2]; await stream.ReadExactlyAsync(reply, timeout.Token); return reply[0] == 5 && reply[1] == 0; }
        catch (Exception error) when (error is System.Net.Sockets.SocketException or IOException or OperationCanceledException) { return false; }
    }
}
