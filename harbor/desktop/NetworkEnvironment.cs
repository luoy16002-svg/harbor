using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace Harbor;
internal sealed record AdapterRow(string Name, string State, string Kind, string Speed, string Addresses, string Dns);
internal sealed record NetworkState(bool ProxyConfigured, bool VirtualAdapterActive, string ProxyMode, IReadOnlyList<AdapterRow> Adapters)
{
    public bool HasCoexistenceRisk => ProxyConfigured || VirtualAdapterActive;
}
internal static class NetworkEnvironment
{
    // Read-only API. Never writes proxy settings, adapter DNS, routes or firewall rules.
    public static NetworkState Read()
    {
        var proxy = new WindowsProxyStore().Read(); var rows = new List<AdapterRow>(); bool virtualActive = false;
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var properties = adapter.GetIPProperties(); bool up = adapter.OperationalStatus == OperationalStatus.Up;
            string description = adapter.Name + " " + adapter.Description;
            bool virtualAdapter = adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel || new[] { "wintun", "wireguard", "clash", "vpn", "tap-windows", "sing-box" }.Any(v => description.Contains(v, StringComparison.OrdinalIgnoreCase));
            virtualActive |= up && virtualAdapter && !adapter.Name.StartsWith("Harbor-", StringComparison.Ordinal);
            string addresses = string.Join(" · ", properties.UnicastAddresses.Where(a => !a.Address.IsIPv6LinkLocal).Select(a => a.Address.ToString()).Take(3));
            string dns = string.Join(" · ", properties.DnsAddresses.Where(a => !a.IsIPv6SiteLocal).Select(a => a.ToString()).Take(3));
            rows.Add(new(adapter.Name, up ? "已连接" : "未连接", virtualAdapter ? "虚拟网络" : adapter.NetworkInterfaceType.ToString(), up && adapter.Speed > 0 ? $"{adapter.Speed / 1_000_000.0:0.#} Mbps" : "—", addresses.Length == 0 ? "—" : addresses, dns.Length == 0 ? "—" : dns));
        }
        bool configured = (proxy.Flags & 6) != 0;
        string mode = (proxy.Flags & 4) != 0 ? "自动代理脚本已启用" : (proxy.Flags & 2) != 0 ? "系统代理已启用" : (proxy.Flags & 8) != 0 ? "自动检测代理" : "系统未配置代理";
        return new(configured, virtualActive, mode, rows.OrderBy(r => r.State != "已连接").ThenBy(r => r.Name).ToList());
    }
    public static void EnsureCanCapture(bool isolated, bool protectExisting, bool systemProxy, bool tun, NetworkState state)
    {
        if (isolated && (systemProxy || tun)) throw new InvalidOperationException("隔离模式仅允许本地监听，不能接管系统代理或 TUN。");
        if (protectExisting && (systemProxy || tun) && state.HasCoexistenceRisk) throw new InvalidOperationException("检测到现有代理或虚拟网络，共存保护已阻止接管。请关闭 Harbor 的系统代理和 TUN 选项，使用本地代理模式。");
    }
}
