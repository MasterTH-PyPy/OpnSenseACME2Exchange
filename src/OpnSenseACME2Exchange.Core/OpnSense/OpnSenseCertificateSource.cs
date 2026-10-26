using System.Text.RegularExpressions;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Haproxy;
using OpnSenseACME2Exchange.Core.Logging;

namespace OpnSenseACME2Exchange.Core.OpnSense;

public sealed record SshResult(int ExitCode, string StdOut, string StdErr);

public interface ISshSession : IDisposable
{
    SshResult Run(string command, TimeSpan timeout);
}

public interface ISshSessionFactory
{
    /// <summary>Öffnet eine SSH-Sitzung. Wirft bei Verbindungs-, Auth- oder Hostkey-Fehlern.</summary>
    ISshSession Open(OpnSenseNode node);
}

public enum CarpState { Unknown, Master, Backup, NoCarp }

public sealed class NodeStatus
{
    public required OpnSenseNode Node { get; init; }
    public bool Reachable { get; set; }
    public CarpState Carp { get; set; } = CarpState.Unknown;
    public string? Version { get; set; }
    public bool? HaproxyRunning { get; set; }
    public bool? ConfigReadable { get; set; }
    public string? Error { get; set; }

    public string Summary => Reachable
        ? $"erreichbar, CARP {Carp}, {Version ?? "Version ?"}, HAProxy {(HaproxyRunning == true ? "läuft" : HaproxyRunning == false ? "läuft NICHT" : "?")}, Config {(ConfigReadable == true ? "lesbar" : "NICHT lesbar")}"
        : $"NICHT erreichbar: {Error}";
}

public sealed record PemCandidate(string Path, CertificateInfo? Info, bool CoversAll, string? Error, IReadOnlyList<string> SniFilters);

public sealed class CertificateLookupResult : IDisposable
{
    public CertificateBundle? Bundle { get; set; }
    public OpnSenseNode? SourceNode { get; set; }
    public string? SourcePath { get; set; }
    public string? SectionKey { get; set; }
    public List<PemCandidate> Candidates { get; } = new();
    public List<string> Warnings { get; } = new();
    public List<string> Errors { get; } = new();
    public bool Success => Bundle != null;
    public void Dispose() => Bundle?.Dispose();
}

public interface ICertificateSource
{
    CertificateLookupResult Resolve(CertificateSelection selection, CancellationToken ct);
}

/// <summary>
/// Liest Zertifikate per SSH von einem OPNsense-Failovercluster.
/// Selbstheilend: CARP-Master zuerst, bei Fehlern automatisch der nächste Knoten;
/// fehlt der gewählte HAProxy-Abschnitt, werden alle TLS-Frontends durchsucht.
/// </summary>
public sealed class OpnSenseCertificateSource : ICertificateSource
{
    private static readonly Regex SafePath = new(@"^/[A-Za-z0-9._/\-]+$", RegexOptions.Compiled);
    private readonly OpnSenseSettings _settings;
    private readonly ISshSessionFactory _factory;

    public OpnSenseCertificateSource(OpnSenseSettings settings, ISshSessionFactory factory)
    {
        _settings = settings;
        _factory = factory;
    }

    private TimeSpan Timeout => TimeSpan.FromSeconds(Math.Max(5, _settings.TimeoutSeconds));

    public static string Quote(string s) => "'" + s.Replace("'", "'\\''") + "'";

    public static bool IsSafePath(string path) => SafePath.IsMatch(path) && !path.Contains("..");

    private string Cmd(string command) => _settings.UseSudo ? "sudo -n " + command : command;

    private string ReadFile(ISshSession session, string path)
    {
        if (!IsSafePath(path)) throw new InvalidOperationException($"Unzulässiger Pfad: {path}");
        var r = session.Run(Cmd("cat -- " + Quote(path)), Timeout);
        if (r.ExitCode != 0)
            throw new IOException($"'{path}' konnte nicht gelesen werden (Exit {r.ExitCode}): {r.StdErr.Trim()}");
        return r.StdOut;
    }

    private List<string> ListPemFiles(ISshSession session, string dir)
    {
        if (!IsSafePath(dir)) throw new InvalidOperationException($"Unzulässiger Pfad: {dir}");
        var r = session.Run(Cmd($"find {Quote(dir.TrimEnd('/'))} -maxdepth 1 -type f -name '*.pem'"), Timeout);
        return r.ExitCode != 0
            ? new List<string>()
            : r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    public NodeStatus Probe(OpnSenseNode node)
    {
        var st = new NodeStatus { Node = node };
        try
        {
            using var s = _factory.Open(node);
            st.Reachable = true;

            var v = s.Run("opnsense-version 2>/dev/null || uname -sr", Timeout);
            st.Version = v.StdOut.Trim().Split('\n').FirstOrDefault();

            var carp = s.Run("ifconfig -a | grep 'carp:' || true", Timeout);
            st.Carp = ParseCarp(carp.StdOut);

            var hp = s.Run("pgrep -x haproxy >/dev/null 2>&1 && echo RUNNING || echo STOPPED", Timeout);
            st.HaproxyRunning = hp.StdOut.Contains("RUNNING");

            var path = _settings.HaproxyConfigPath;
            if (IsSafePath(path))
            {
                var t = s.Run(Cmd("test -r " + Quote(path)) + " && echo OK || echo NO", Timeout);
                st.ConfigReadable = t.StdOut.Contains("OK");
            }
        }
        catch (Exception ex)
        {
            st.Reachable = false;
            st.Error = Log.Describe(ex);
        }
        return st;
    }

    public static CarpState ParseCarp(string ifconfigOutput)
    {
        var states = Regex.Matches(ifconfigOutput, @"carp:\s+([A-Z]+)")
            .Select(m => m.Groups[1].Value).Distinct().ToList();
        if (states.Count == 0) return CarpState.NoCarp;
        if (states.Contains("MASTER") && !states.Contains("BACKUP")) return CarpState.Master;
        if (states.Contains("BACKUP") && !states.Contains("MASTER")) return CarpState.Backup;
        return CarpState.Unknown; // gemischt (z.B. Split-Brain oder Umschaltung)
    }

    /// <summary>Knoten in sinnvoller Reihenfolge: CARP-Master, dann Rest, nicht erreichbare zuletzt.</summary>
    public List<NodeStatus> OrderedNodes()
    {
        var statuses = _settings.Nodes.Where(n => !string.IsNullOrWhiteSpace(n.Host)).Select(Probe).ToList();
        foreach (var s in statuses) Log.Debug($"OPNsense {s.Node}: {s.Summary}");

        int Rank(NodeStatus s) => !s.Reachable ? 9
            : _settings.PreferCarpMaster && s.Carp == CarpState.Master ? 0
            : s.Carp is CarpState.NoCarp or CarpState.Unknown ? 1
            : 2;

        var masters = statuses.Count(s => s.Carp == CarpState.Master);
        if (masters > 1) Log.Warn("Mehr als ein OPNsense-Knoten meldet CARP MASTER – mögliches Split-Brain!");

        return statuses.OrderBy(Rank).ToList();
    }

    /// <summary>Liest haproxy.conf vom ersten funktionierenden Knoten.</summary>
    public (string Text, OpnSenseNode Node) ReadHaproxyConfig()
    {
        var errors = new List<string>();
        foreach (var st in OrderedNodes())
        {
            if (!st.Reachable) { errors.Add($"{st.Node}: {st.Error}"); continue; }
            try
            {
                using var s = _factory.Open(st.Node);
                var text = ReadFile(s, _settings.HaproxyConfigPath);
                Log.Info($"HAProxy-Konfiguration von {st.Node} gelesen ({text.Length} Zeichen).");
                return (text, st.Node);
            }
            catch (Exception ex)
            {
                errors.Add($"{st.Node}: {Log.Describe(ex)}");
                Log.Warn($"HAProxy-Konfiguration von {st.Node} nicht lesbar – versuche nächsten Knoten. {Log.Describe(ex)}");
            }
        }
        throw new InvalidOperationException("Kein OPNsense-Knoten lieferte die HAProxy-Konfiguration: " + string.Join(" | ", errors));
    }

    /// <summary>Liest zusätzliche Hostnamen aus ACL-/Map-Dateien eines Abschnitts.</summary>
    public SortedSet<string> ReadReferencedHostnames(HaproxySection section, OpnSenseNode node)
    {
        var set = new SortedSet<string>(section.Hostnames, StringComparer.OrdinalIgnoreCase);
        using var s = _factory.Open(node);
        foreach (var file in section.ReferencedFiles)
        {
            try { foreach (var h in HostListParser.Parse(ReadFile(s, file))) set.Add(h); }
            catch (Exception ex) { Log.Debug($"Datei {file} nicht lesbar: {Log.Describe(ex)}"); }
        }
        foreach (var bind in section.Binds)
        foreach (var list in bind.CrtListPaths)
        {
            try
            {
                foreach (var e in CrtListParser.Parse(ReadFile(s, list)))
                foreach (var f in e.SniFilters.Where(f => !f.StartsWith('!')))
                    set.Add(HaproxyConfig.NormalizeHost(f));
            }
            catch (Exception ex) { Log.Debug($"crt-list {list} nicht lesbar: {Log.Describe(ex)}"); }
        }
        return set;
    }

    public CertificateLookupResult Resolve(CertificateSelection selection, CancellationToken ct)
    {
        var result = new CertificateLookupResult();
        var required = RequiredNames(selection);
        if (required.Count == 0)
        {
            result.Errors.Add("Kein Exchange-Hostname konfiguriert.");
            return result;
        }

        var nodes = OrderedNodes();
        // Ausgefallene Cluster-Knoten immer melden – auch wenn ein anderer Knoten liefert.
        foreach (var down in nodes.Where(n => !n.Reachable))
            result.Warnings.Add($"OPNsense-Knoten {down.Node} nicht erreichbar: {down.Error}");

        foreach (var st in nodes.Where(n => n.Reachable))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var s = _factory.Open(st.Node);
                if (TryResolveOnNode(s, st.Node, selection, required, result, ct))
                    return result;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                result.Warnings.Add($"{st.Node}: {Log.Describe(ex)}");
                Log.Warn($"Zertifikat auf {st.Node} nicht ermittelbar – versuche nächsten Knoten. {Log.Describe(ex)}");
            }
        }

        if (result.Errors.Count == 0)
            result.Errors.Add("Auf keinem OPNsense-Knoten wurde ein passendes Zertifikat mit Private Key gefunden.");
        return result;
    }

    public static List<string> RequiredNames(CertificateSelection selection) =>
        new[] { selection.ExchangeHostname }
            .Concat(selection.AdditionalRequiredNames)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => n.Trim().ToLowerInvariant())
            .Distinct()
            .ToList();

    private bool TryResolveOnNode(ISshSession s, OpnSenseNode node, CertificateSelection selection,
        List<string> required, CertificateLookupResult result, CancellationToken ct)
    {
        var cfg = HaproxyConfig.Parse(ReadFile(s, _settings.HaproxyConfigPath));
        var hostname = required[0];

        var sections = new List<HaproxySection>();
        var chosen = cfg.Find(selection.SectionKey);
        if (chosen != null) sections.Add(chosen);
        else
        {
            if (!string.IsNullOrWhiteSpace(selection.SectionKey))
            {
                var w = $"Abschnitt '{selection.SectionKey}' existiert auf {node} nicht mehr – durchsuche alle TLS-Frontends.";
                result.Warnings.Add(w);
                Log.Warn(w);
            }
            sections.AddRange(cfg.CertificateSections.Where(x => x.TerminatesTls));
        }

        // Kandidaten sammeln (Pfad -> SNI-Filter)
        var paths = new List<(string Path, IReadOnlyList<string> Sni, string Section)>();
        foreach (var sec in sections)
        foreach (var bind in sec.Binds)
        {
            foreach (var crt in bind.CrtPaths)
            {
                if (crt.EndsWith('/') || !crt.EndsWith(".pem", StringComparison.OrdinalIgnoreCase))
                {
                    var files = ListPemFiles(s, crt);
                    if (files.Count > 0) { paths.AddRange(files.Select(f => (f, (IReadOnlyList<string>)Array.Empty<string>(), sec.Key))); continue; }
                }
                paths.Add((crt, Array.Empty<string>(), sec.Key));
            }
            foreach (var list in bind.CrtListPaths)
            {
                // Alle Einträge prüfen: maßgeblich ist, was das Zertifikat selbst abdeckt (SNI-Filter können veraltet sein).
                // Passende SNI-Filter zuerst, damit bei Gleichstand der "richtige" Eintrag gewinnt.
                foreach (var e in CrtListParser.Parse(ReadFile(s, list)).OrderByDescending(e => e.AppliesTo(hostname)))
                    paths.Add((e.Path, e.SniFilters, sec.Key));
            }
        }
        if (!string.IsNullOrWhiteSpace(selection.LastKnownPemPath))
            paths.Add((selection.LastKnownPemPath!, Array.Empty<string>(), "zuletzt bekannt"));

        var best = (Bundle: (CertificateBundle?)null, Path: "", Section: "");
        foreach (var p in paths.DistinctBy(p => p.Path))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var bundle = CertificateBundle.Parse(ReadFile(s, p.Path), $"{node.Host}:{p.Path}");
                var covers = bundle.HasPrivateKey && required.All(bundle.Info.Covers);
                result.Candidates.Add(new PemCandidate(p.Path, bundle.Info, covers, null, p.Sni));
                Log.Debug($"Kandidat {p.Path}: {bundle.Info.ShortDescription} | deckt ab: {covers}");

                if (covers && (best.Bundle == null || bundle.Info.NotAfter > best.Bundle.Info.NotAfter))
                {
                    best.Bundle?.Dispose();
                    best = (bundle, p.Path, p.Section);
                }
                else bundle.Dispose();
            }
            catch (Exception ex)
            {
                result.Candidates.Add(new PemCandidate(p.Path, null, false, Log.Describe(ex), p.Sni));
                Log.Debug($"Kandidat {p.Path} unbrauchbar: {Log.Describe(ex)}");
            }
        }

        if (best.Bundle == null)
        {
            result.Warnings.Add($"{node}: kein Zertifikat für {string.Join(", ", required)} unter {paths.Count} Kandidaten.");
            return false;
        }

        result.Bundle = best.Bundle;
        result.SourceNode = node;
        result.SourcePath = best.Path;
        result.SectionKey = best.Section;
        Log.Info($"Zertifikat gefunden auf {node}: {best.Path} → {best.Bundle.Info.ShortDescription}");
        return true;
    }
}
