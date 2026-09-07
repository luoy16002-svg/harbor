using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace Harbor;
internal sealed record WorkspaceState(JsonObject Profile, List<SubscriptionEntry> Subscriptions);
internal sealed record DesktopPreferences(bool SystemProxy = true, bool MinimizeToTray = false, bool ProtectExistingProxy = true);

internal static class Storage
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true, PropertyNameCaseInsensitive = false };
    public static string Root { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Harbor");
    public static string ProfilePath => Path.Combine(Root, "profile.dat");
    public static string JournalPath => Path.Combine(Root, "proxy-lease.dat");
    public static string WorkspacePath => Path.Combine(Root, "workspace.dat");
    public static string PreferencesPath => Path.Combine(Root, "preferences.dat");
    public static WorkspaceState? LoadWorkspace()
    {
        var saved = Read<WorkspaceState>(WorkspacePath); if (saved != null) return saved;
        var profile = Read<JsonObject>(ProfilePath);
        return profile == null ? null : new WorkspaceState(profile, Read<List<SubscriptionEntry>>(Path.Combine(Root, "subscriptions.dat")) ?? []);
    }
    public static void SaveWorkspace(JsonObject profile, List<SubscriptionEntry> subscriptions) => Write(WorkspacePath, new WorkspaceState(profile, subscriptions));

    public static void Write<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        try
        {
            byte[] encrypted = Protect(plain, false);
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { file.Write(encrypted); file.Flush(true); }
                File.Move(temporary, path, true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain); }
    }

    public static T? Read<T>(string path)
    {
        if (!File.Exists(path)) return default;
        var info = new FileInfo(path);
        if (info.Length > 4 * 1024 * 1024) throw new InvalidDataException("配置文件超过大小限制。");
        var plain = Protect(File.ReadAllBytes(path), true);
        try { return JsonSerializer.Deserialize<T>(plain, Json); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref Blob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    private static byte[] Protect(byte[] bytes, bool decrypt)
    {
        var input = new Blob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        Blob output = default;
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            bool ok = decrypt ? CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptProtectData(ref input, "Harbor", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "无法访问当前 Windows 用户的加密配置。");
            var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally
        {
            for (int i = 0; i < input.Size; i++) Marshal.WriteByte(input.Data, i, 0);
            Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero) { for (int i = 0; i < output.Size; i++) Marshal.WriteByte(output.Data, i, 0); LocalFree(output.Data); }
        }
    }
}
