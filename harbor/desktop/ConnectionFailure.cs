using System;

namespace Harbor;
internal static class ConnectionFailure
{
    public static string Describe(string error)
    {
        if (string.IsNullOrWhiteSpace(error)) return "—";
        bool Has(string value) => error.Contains(value, StringComparison.OrdinalIgnoreCase);
        bool dns = Has("DNS") || Has("DoH");
        if (Has("physical egress interface")) return "物理网络不可用";
        if (dns && (Has("timeout") || Has("timed out"))) return "DNS 超时";
        if (dns && Has("blocked")) return "域名被规则拦截";
        if (dns && Has("NXDomain")) return "域名不存在";
        if (dns && Has("certificate")) return "DNS 证书验证失败";
        if (dns && Has("NODATA")) return "DNS 没有地址记录";
        if (dns && Has("no address")) return "节点域名解析失败";
        if (dns) return "DNS 查询失败";
        if (Has("certificate")) return "证书验证失败";
        if (Has("authentication") || Has("407")) return "代理认证失败";
        if (Has("timed out") || Has("timeout")) return "连接超时";
        if (Has("Blocked") || Has("Privacy:")) return "被分流或隐私规则拦截";
        return "连接失败";
    }
}
