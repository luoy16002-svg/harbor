using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;

namespace Harbor;
internal sealed record BlockImport(string[] Blocked, string[] Allowed, int Unsupported);
internal static class BlockRules
{
    public static BlockImport Parse(string text)
    {
        if (Encoding.UTF8.GetByteCount(text) > 2 * 1024 * 1024) throw new FormatException("规则文件超过 2 MiB。");
        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase); int unsupported = 0;
        var idn = new IdnMapping();
        foreach (string raw in text.Split('\n'))
        {
            string line = raw.Trim(); if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!') || line.StartsWith('[')) continue;
            if (line.Contains("##", StringComparison.Ordinal) || line.Contains("#@#", StringComparison.Ordinal) || line.Contains("#?#", StringComparison.Ordinal) || line.Contains("#$#", StringComparison.Ordinal)) { unsupported++; continue; }
            bool exception = line.StartsWith("@@||", StringComparison.Ordinal); string domain;
            if (line.StartsWith("||", StringComparison.Ordinal) || exception)
            {
                string rule = line[(exception ? 4 : 2)..]; if (!rule.EndsWith('^') || rule.Contains('$')) { unsupported++; continue; } domain = rule[..^1];
            }
            else
            {
                var parts = line.Split('#')[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;
                if (parts.Length > 1 && IPAddress.TryParse(parts[0], out var hostAddress))
                {
                    if (!IPAddress.IsLoopback(hostAddress) && !hostAddress.Equals(IPAddress.Any) && !hostAddress.Equals(IPAddress.IPv6Any)) { unsupported++; continue; }
                    foreach (string name in parts.Skip(1)) Add(name, false); continue;
                }
                if (parts.Length != 1) { unsupported++; continue; } domain = parts[0];
            }
            Add(domain, exception);
        }
        if (blocked.Count + allowed.Count > 20000 || blocked.Concat(allowed).Sum(v => v.Length) > 512 * 1024) throw new FormatException("最多支持 20,000 个域名，域名文本合计不得超过 512 KiB。");
        return new(blocked.Order().ToArray(), allowed.Order().ToArray(), unsupported);
        void Add(string domain, bool exception)
        {
            try
            {
                domain = idn.GetAscii(domain.TrimEnd('.')).ToLowerInvariant();
                if (domain == "localhost" || IPAddress.TryParse(domain, out _) || domain.Length > 253 || domain.Split('.').Any(label => label.Length == 0 || label.Length > 63 || label.StartsWith('-') || label.EndsWith('-') || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))) { unsupported++; return; }
                (exception ? allowed : blocked).Add(domain);
            }
            catch (ArgumentException) { unsupported++; }
        }
    }
}
