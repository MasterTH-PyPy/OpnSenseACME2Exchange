using System.Globalization;
using OpnSenseACME2Exchange.Core.Config;

namespace OpnSenseACME2Exchange.Core.Exchange;

public enum ServerGroupKind { Dag, NoDag, Edge }

public sealed class ServerGroup
{
    public required string Key { get; init; }
    public required ServerGroupKind Kind { get; init; }
    public required string Title { get; init; }
    public List<ExchangeServerEntry> Servers { get; } = new();

    public int EnabledCount => Servers.Count(s => s.Enabled);
    public bool AllEnabled => Servers.Count > 0 && Servers.All(s => s.Enabled);
    public bool NoneEnabled => Servers.All(s => !s.Enabled);

    /// <summary>"3 Server, 3 aktiv – alle: bis 24.01.2027"</summary>
    public string Summary
    {
        get
        {
            var parts = new List<string> { $"{Servers.Count} Server, {EnabledCount} aktiv" };
            var missing = Servers.Count(s => s.MissingInAd);
            if (missing > 0) parts.Add($"{missing} nicht mehr im AD");

            var certs = Servers.Select(s => ServerGrouping.ParseCertificate(s.CurrentCertificate)).ToList();
            var known = certs.Where(c => c != null).Select(c => c!.Value).ToList();
            string cert;
            if (known.Count == 0) cert = "Zertifikat noch unbekannt";
            else if (known.Select(c => c.Thumbprint).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1 && known.Count == Servers.Count)
                cert = $"alle gleiches Zertifikat bis {known[0].NotAfter:dd.MM.yyyy}";
            else
            {
                var distinct = known.Select(c => c.Thumbprint).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                cert = $"UNEINHEITLICH: {distinct} verschiedene Zertifikate" +
                       (known.Count < Servers.Count ? $", {Servers.Count - known.Count} unbekannt" : "") +
                       $" (frühester Ablauf {known.Min(c => c.NotAfter):dd.MM.yyyy})";
            }
            return string.Join(", ", parts) + " – " + cert;
        }
    }

    /// <summary>Alle Server der Gruppe haben dasselbe bekannte Zertifikat (für Extended Protection/HAProxy wichtig).</summary>
    public bool CertificatesConsistent
    {
        get
        {
            var known = Servers.Select(s => ServerGrouping.ParseCertificate(s.CurrentCertificate)).ToList();
            return known.All(c => c != null) &&
                   known.Select(c => c!.Value.Thumbprint).Distinct(StringComparer.OrdinalIgnoreCase).Count() <= 1;
        }
    }

    public override string ToString() => $"{Title} – {Summary}";
}

/// <summary>Gruppierung der Exchange-Server: DAGs (alphabetisch), dann Server ohne DAG, dann Edge.</summary>
public static class ServerGrouping
{
    public static string KeyOf(ExchangeServerEntry s) =>
        s.IsEdge ? "~edge" : string.IsNullOrWhiteSpace(s.Dag) ? "~nodag" : "dag:" + s.Dag.Trim().ToUpperInvariant();

    public static List<ServerGroup> Group(IEnumerable<ExchangeServerEntry> servers)
    {
        var groups = new Dictionary<string, ServerGroup>(StringComparer.Ordinal);
        foreach (var s in servers)
        {
            var key = KeyOf(s);
            if (!groups.TryGetValue(key, out var g))
            {
                g = s.IsEdge
                    ? new ServerGroup { Key = key, Kind = ServerGroupKind.Edge, Title = "Edge-Transport" }
                    : string.IsNullOrWhiteSpace(s.Dag)
                        ? new ServerGroup { Key = key, Kind = ServerGroupKind.NoDag, Title = "Ohne DAG" }
                        : new ServerGroup { Key = key, Kind = ServerGroupKind.Dag, Title = DagTitle(s.Dag!) };
                groups[key] = g;
            }
            g.Servers.Add(s);
        }

        foreach (var g in groups.Values)
        {
            var sorted = g.Servers
                .OrderBy(s => s.Site ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            g.Servers.Clear();
            g.Servers.AddRange(sorted);
        }

        return groups.Values
            .OrderBy(g => g.Kind)
            .ThenBy(g => g.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>"DAG01" bleibt "DAG01", "Mail" wird "DAG Mail".</summary>
    public static string DagTitle(string dag)
    {
        var d = dag.Trim();
        return d.StartsWith("DAG", StringComparison.OrdinalIgnoreCase) ? d : "DAG " + d;
    }

    /// <summary>Liest "THUMBPRINT bis dd.MM.yyyy" (Anzeigeformat von CurrentCertificate).</summary>
    public static (string Thumbprint, DateTime NotAfter)? ParseCertificate(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var idx = text.IndexOf(" bis ", StringComparison.Ordinal);
        if (idx <= 0) return null;
        var tp = text[..idx].Trim();
        return DateTime.TryParseExact(text[(idx + 5)..].Trim(), "dd.MM.yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? (tp, d)
            : null;
    }
}
