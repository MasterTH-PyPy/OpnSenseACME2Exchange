using System.Text;
using System.Text.RegularExpressions;

namespace OpnSenseACME2Exchange.Core.Haproxy;

public sealed class HaproxyBind
{
    public string Raw { get; init; } = "";
    public string Address { get; init; } = "";
    public bool IsSsl { get; init; }
    public List<string> CrtPaths { get; } = new();
    public List<string> CrtListPaths { get; } = new();
}

public sealed class HaproxySection
{
    public string Type { get; init; } = "";
    public string Name { get; init; } = "";
    public int StartLine { get; init; }
    public List<string> Lines { get; } = new();
    public List<string> LeadingComments { get; } = new();
    public List<HaproxyBind> Binds { get; } = new();

    /// <summary>Hostnamen aus SNI-/Host-ACLs dieses Abschnitts.</summary>
    public SortedSet<string> Hostnames { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Referenzierte ACL- (-f) und Map-Dateien – enthalten oft weitere Hostnamen.</summary>
    public SortedSet<string> ReferencedFiles { get; } = new(StringComparer.Ordinal);

    public string Key => $"{Type} {Name}";
    public bool TerminatesTls => Binds.Any(b => b.IsSsl && (b.CrtPaths.Count > 0 || b.CrtListPaths.Count > 0));
    public bool CanCarryCertificate => Type is "frontend" or "listen";

    public string Text => string.Join(Environment.NewLine, LeadingComments.Concat(Lines));

    public override string ToString() => TerminatesTls ? $"{Key}  [TLS]" : Key;
}

public sealed class HaproxyConfig
{
    private static readonly HashSet<string> SectionKeywords = new(StringComparer.Ordinal)
    {
        "global", "defaults", "frontend", "backend", "listen", "userlist", "peers", "resolvers",
        "mailers", "cache", "program", "http-errors", "ring", "fcgi-app", "crt-store", "traces",
        "log-forward"
    };

    /// <summary>Fetches, deren Werte Hostnamen sind.</summary>
    private static readonly Regex HostFetch = new(
        @"^(req\.ssl_sni|req_ssl_sni|ssl_fc_sni|ssl_c_sni|hdr\(host\)|req\.hdr\(host\)|hdr_(beg|end|dom|reg|sub|str)\(host\)|req\.hdr_(beg|end|dom)\(host\)|base_(beg|dom)|host)(,[a-z_]+(\([^)]*\))?)*$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MapFile = new(@"map(_[a-z]+)?\(([^),]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HostnameLike = new(
        @"^(\*\.|\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\.?$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public List<HaproxySection> Sections { get; } = new();

    public IEnumerable<HaproxySection> CertificateSections => Sections.Where(s => s.CanCarryCertificate);

    public HaproxySection? Find(string? key) =>
        string.IsNullOrWhiteSpace(key)
            ? null
            : Sections.FirstOrDefault(s => string.Equals(s.Key, key.Trim(), StringComparison.Ordinal));

    public static HaproxyConfig Parse(string text)
    {
        var cfg = new HaproxyConfig();
        HaproxySection? current = null;
        var pendingComments = new List<string>();
        var lines = text.Replace("\r\n", "\n").Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                pendingComments.Clear();
                if (current != null) current.Lines.Add(line);
                continue;
            }
            if (trimmed.StartsWith('#'))
            {
                // OPNsense schreibt "# Frontend: name (Beschreibung)" direkt über den Abschnitt.
                pendingComments.Add(line);
                continue;
            }

            var tokens = Tokenize(line);
            if (tokens.Count == 0) continue;

            if (SectionKeywords.Contains(tokens[0]))
            {
                current = new HaproxySection
                {
                    Type = tokens[0],
                    Name = tokens.Count > 1 ? tokens[1] : "",
                    StartLine = i + 1
                };
                current.LeadingComments.AddRange(pendingComments);
                pendingComments.Clear();
                current.Lines.Add(line);
                cfg.Sections.Add(current);
                continue;
            }

            if (current == null) { pendingComments.Clear(); continue; }
            foreach (var c in pendingComments) current.Lines.Add(c);
            pendingComments.Clear();
            current.Lines.Add(line);
            AnalyzeLine(current, tokens);
        }

        // Leerzeilen am Ende abschneiden
        foreach (var s in cfg.Sections)
            while (s.Lines.Count > 0 && string.IsNullOrWhiteSpace(s.Lines[^1])) s.Lines.RemoveAt(s.Lines.Count - 1);

        return cfg;
    }

    private static void AnalyzeLine(HaproxySection section, List<string> tokens)
    {
        if (tokens[0] == "bind")
        {
            section.Binds.Add(ParseBind(tokens));
            return;
        }

        foreach (Match m in MapFile.Matches(string.Join(' ', tokens)))
        {
            var p = m.Groups[2].Value.Trim().Trim('"', '\'');
            if (p.StartsWith('/')) section.ReferencedFiles.Add(p);
        }

        for (int i = 0; i < tokens.Count; i++)
        {
            if (!HostFetch.IsMatch(tokens[i])) continue;
            for (int j = i + 1; j < tokens.Count; j++)
            {
                var t = tokens[j];
                if (t is "}" or "if" or "unless" or "or" or "||" or "!") break;
                if (t == "-f" && j + 1 < tokens.Count) { section.ReferencedFiles.Add(tokens[++j]); continue; }
                if (t is "-m" or "-M" && j + 1 < tokens.Count) { j++; continue; }
                if (t.StartsWith('-')) continue;
                if (IsHostnameLike(t)) section.Hostnames.Add(NormalizeHost(t));
            }
        }
    }

    private static HaproxyBind ParseBind(List<string> tokens)
    {
        var bind = new HaproxyBind
        {
            Raw = string.Join(' ', tokens),
            Address = tokens.Count > 1 ? tokens[1] : "",
            IsSsl = tokens.Contains("ssl")
        };
        for (int i = 2; i < tokens.Count - 1; i++)
        {
            if (tokens[i] == "crt") bind.CrtPaths.Add(tokens[++i]);
            else if (tokens[i] == "crt-list") bind.CrtListPaths.Add(tokens[++i]);
        }
        return bind;
    }

    public static bool IsHostnameLike(string s) => HostnameLike.IsMatch(s.Trim());

    public static string NormalizeHost(string s)
    {
        s = s.Trim().TrimEnd('.').ToLowerInvariant();
        // hdr_dom/map_dom-Muster ".example.de" als Wildcard-Info behalten
        return s;
    }

    /// <summary>Zerlegt eine HAProxy-Zeile in Tokens (Quotes, Escapes, Kommentare).</summary>
    public static List<string> Tokenize(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool inToken = false;
        char quote = '\0';

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quote != '\0')
            {
                if (c == quote) { quote = '\0'; continue; }
                if (c == '\\' && quote == '"' && i + 1 < line.Length) { sb.Append(line[++i]); continue; }
                sb.Append(c);
                continue;
            }
            if (c == '#' && (!inToken)) break;
            if (c is '"' or '\'') { quote = c; inToken = true; continue; }
            if (c == '\\' && i + 1 < line.Length) { sb.Append(line[++i]); inToken = true; continue; }
            if (char.IsWhiteSpace(c))
            {
                if (inToken) { result.Add(sb.ToString()); sb.Clear(); inToken = false; }
                continue;
            }
            sb.Append(c);
            inToken = true;
        }
        if (inToken) result.Add(sb.ToString());
        return result;
    }
}

public sealed record CrtListEntry(string Path, string? Options, IReadOnlyList<string> SniFilters)
{
    /// <summary>Prüft, ob der Eintrag für den Hostnamen gilt (ohne Filter = Default/alle).</summary>
    public bool AppliesTo(string host)
    {
        var positives = SniFilters.Where(f => !f.StartsWith('!')).ToList();
        var negatives = SniFilters.Where(f => f.StartsWith('!')).Select(f => f[1..]).ToList();
        if (negatives.Any(n => Certificates.HostMatcher.Matches(n, host))) return false;
        if (positives.Count == 0) return true;
        return positives.Any(p => Certificates.HostMatcher.Matches(p, host));
    }
}

public static class CrtListParser
{
    public static List<CrtListEntry> Parse(string text)
    {
        var list = new List<CrtListEntry>();
        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            string? options = null;
            var open = line.IndexOf('[');
            var close = open >= 0 ? line.IndexOf(']', open) : -1;
            string rest;
            if (open >= 0 && close > open)
            {
                options = line[(open + 1)..close].Trim();
                rest = (line[..open] + " " + line[(close + 1)..]).Trim();
            }
            else rest = line;

            var tokens = HaproxyConfig.Tokenize(rest);
            if (tokens.Count == 0) continue;
            list.Add(new CrtListEntry(tokens[0], options, tokens.Skip(1).ToList()));
        }
        return list;
    }
}

/// <summary>Liest Hostnamen aus ACL-/Map-Dateien (je Zeile: "host" bzw. "host backend").</summary>
public static class HostListParser
{
    public static IEnumerable<string> Parse(string text)
    {
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var first = HaproxyConfig.Tokenize(line).FirstOrDefault();
            if (first != null && HaproxyConfig.IsHostnameLike(first))
                yield return HaproxyConfig.NormalizeHost(first);
        }
    }
}
