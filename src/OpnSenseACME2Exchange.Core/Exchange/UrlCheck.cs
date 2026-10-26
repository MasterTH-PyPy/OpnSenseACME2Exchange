using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;

namespace OpnSenseACME2Exchange.Core.Exchange;

/// <summary>Eine in Exchange hinterlegte URL bzw. ein Hostname (gelesen, nie geschrieben).</summary>
/// <param name="Component">OWA, ECP, EWS, OAB, EAS, MAPI, OutlookAnywhere, Autodiscover</param>
/// <param name="Scope">Intern oder Extern</param>
/// <param name="Identity">Exchange-Identity des Objekts (für den Korrekturbefehl)</param>
/// <param name="Value">URL oder (Outlook Anywhere) Hostname; leer = nicht gesetzt</param>
public sealed record ExchangeUrlEntry(string Component, string Scope, string Identity, string? Value);

public enum UrlFindingKind { Ok, NotSet, Accepted, NotCovered, Invalid, DagMismatch }

public sealed record UrlFinding(
    string Server, string Component, string Scope, string Identity, string? Value, string? Host,
    UrlFindingKind Kind, string Message, string? SuggestedCommand)
{
    /// <summary>Verhindert (ohne Option "trotzdem tauschen") den Zertifikatstausch auf diesem Server.</summary>
    public bool Blocking => Kind is UrlFindingKind.NotCovered or UrlFindingKind.Invalid;
}

public sealed class UrlCheckResult
{
    public required string Server { get; init; }
    public string? Fqdn { get; init; }
    public string? Dag { get; init; }
    public List<UrlFinding> Findings { get; set; } = new();
    public string? Error { get; set; }

    public int BlockingCount => Findings.Count(f => f.Blocking);
    public bool Ok => Error == null && BlockingCount == 0;

    public string Summary =>
        Error != null ? "Prüfung fehlgeschlagen: " + Error
        : BlockingCount == 0
            ? $"OK ({Findings.Count(f => f.Kind == UrlFindingKind.Ok)} passend" +
              $"{(Findings.Any(f => f.Kind == UrlFindingKind.Accepted) ? $", {Findings.Count(f => f.Kind == UrlFindingKind.Accepted)} akzeptiert" : "")}" +
              $"{(Findings.Any(f => f.Kind == UrlFindingKind.DagMismatch) ? $", {Findings.Count(f => f.Kind == UrlFindingKind.DagMismatch)} DAG-Abweichung" : "")})"
            : $"{BlockingCount} Abweichung(en) vom Zertifikat";
}

public sealed record UrlCheckReport(List<string> CertificateNames, string CertificateSource, List<UrlCheckResult> Servers, List<string> Warnings);

public sealed record CheckUrlsRequest(List<string> Fqdns);

public static class UrlChecker
{
    /// <summary>Prüft alle URLs eines Servers gegen die Namen des Zertifikats.</summary>
    public static UrlCheckResult Evaluate(ExchangeServerEntry server, IEnumerable<ExchangeUrlEntry> entries,
        IReadOnlyList<string> certNames, IEnumerable<string> acceptedHosts, string exchangeHostname, string? autodiscoverHostname)
    {
        var accepted = acceptedHosts.Where(a => !string.IsNullOrWhiteSpace(a)).Select(a => a.Trim()).ToList();
        var result = new UrlCheckResult { Server = server.Name, Fqdn = server.Fqdn, Dag = server.Dag };

        foreach (var e in entries)
        {
            if (string.IsNullOrWhiteSpace(e.Value))
            {
                result.Findings.Add(new UrlFinding(server.Name, e.Component, e.Scope, e.Identity, null, null,
                    UrlFindingKind.NotSet, "nicht gesetzt", null));
                continue;
            }

            var host = HostOf(e.Value);
            if (host == null)
            {
                result.Findings.Add(new UrlFinding(server.Name, e.Component, e.Scope, e.Identity, e.Value, null,
                    UrlFindingKind.Invalid, "keine gültige URL", Suggest(e, exchangeHostname, autodiscoverHostname)));
                continue;
            }

            if (HostMatcher.Covers(certNames, host))
                result.Findings.Add(new UrlFinding(server.Name, e.Component, e.Scope, e.Identity, e.Value, host,
                    UrlFindingKind.Ok, "im Zertifikat", null));
            else if (accepted.Any(a => HostMatcher.Matches(a, host)))
                result.Findings.Add(new UrlFinding(server.Name, e.Component, e.Scope, e.Identity, e.Value, host,
                    UrlFindingKind.Accepted, "nicht im Zertifikat – bewusst akzeptiert", null));
            else
                result.Findings.Add(new UrlFinding(server.Name, e.Component, e.Scope, e.Identity, e.Value, host,
                    UrlFindingKind.NotCovered, $"'{host}' ist nicht im Zertifikat ({string.Join(", ", certNames)})",
                    Suggest(e, exchangeHostname, autodiscoverHostname)));
        }
        return result;
    }

    /// <summary>
    /// Innerhalb einer DAG sollten die Server dieselben Namen verwenden (Load-Balancing, HAProxy).
    /// Abweichungen sind nur ein Hinweis, kein Blocker.
    /// </summary>
    public static void CompareWithinDag(IEnumerable<UrlCheckResult> results)
    {
        foreach (var dag in results.Where(r => !string.IsNullOrWhiteSpace(r.Dag) && r.Error == null).GroupBy(r => r.Dag!.ToUpperInvariant()))
        {
            var list = dag.ToList();
            if (list.Count < 2) continue;
            // Materialisieren: unten werden den Listen Befunde hinzugefügt
            var keys = list.SelectMany(r => r.Findings).Where(f => f.Host != null && f.Kind != UrlFindingKind.DagMismatch)
                .Select(f => (f.Component, f.Scope)).Distinct().ToList();
            foreach (var (component, scope) in keys)
            {
                var hosts = list
                    .Select(r => (r.Server, Host: r.Findings.FirstOrDefault(f => f.Component == component && f.Scope == scope && f.Kind != UrlFindingKind.DagMismatch)?.Host))
                    .ToList();
                var distinct = hosts.Where(h => h.Host != null).Select(h => h.Host!.ToLowerInvariant()).Distinct().ToList();
                // Interne URLs auf den eigenen Servernamen sind ein typisches, gewolltes Muster – nur gleiche "Fremd"-Namen vergleichen
                if (distinct.Count <= 1 || hosts.All(h => h.Host != null && list.First(r => r.Server == h.Server).Fqdn?.Equals(h.Host, StringComparison.OrdinalIgnoreCase) == true))
                    continue;

                var majority = hosts.Where(h => h.Host != null).GroupBy(h => h.Host!.ToLowerInvariant()).OrderByDescending(g => g.Count()).First().Key;
                foreach (var r in list)
                {
                    var f = r.Findings.FirstOrDefault(x => x.Component == component && x.Scope == scope && x.Kind != UrlFindingKind.DagMismatch);
                    if (f?.Host == null || f.Host.Equals(majority, StringComparison.OrdinalIgnoreCase)) continue;
                    if (r.Findings.Any(x => x.Kind == UrlFindingKind.DagMismatch && x.Component == component && x.Scope == scope)) continue;
                    r.Findings.Add(f with
                    {
                        Kind = UrlFindingKind.DagMismatch,
                        Message = $"weicht in der DAG ab: hier '{f.Host}', bei den anderen '{majority}'",
                        SuggestedCommand = null
                    });
                }
            }
        }
    }

    public static string? HostOf(string value)
    {
        var v = value.Trim();
        if (!v.Contains("://")) // Outlook Anywhere: reiner Hostname
            return HostnameOk(v) ? v.TrimEnd('.').ToLowerInvariant() : null;
        return Uri.TryCreate(v, UriKind.Absolute, out var u) && HostnameOk(u.Host) ? u.Host.ToLowerInvariant() : null;
    }

    private static bool HostnameOk(string h) =>
        h.Length > 0 && h.All(c => char.IsLetterOrDigit(c) || c is '.' or '-') && !h.StartsWith('.') && !h.StartsWith('-');

    /// <summary>Korrekturvorschlag zum Kopieren – wird nie automatisch ausgeführt.</summary>
    public static string? Suggest(ExchangeUrlEntry e, string exchangeHostname, string? autodiscoverHostname)
    {
        if (string.IsNullOrWhiteSpace(exchangeHostname)) return null;
        var id = e.Identity.Replace("'", "''");
        var scopeParam = e.Scope == "Intern" ? "InternalUrl" : "ExternalUrl";

        string NewUrl(string defaultPath)
        {
            var path = defaultPath;
            if (!string.IsNullOrWhiteSpace(e.Value) && Uri.TryCreate(e.Value, UriKind.Absolute, out var u) && u.AbsolutePath.Length > 1)
                path = u.AbsolutePath;
            return $"https://{exchangeHostname}{path}";
        }

        return e.Component switch
        {
            "OWA" => $"Set-OwaVirtualDirectory -Identity '{id}' -{scopeParam} {NewUrl("/owa")}",
            "ECP" => $"Set-EcpVirtualDirectory -Identity '{id}' -{scopeParam} {NewUrl("/ecp")}",
            "EWS" => $"Set-WebServicesVirtualDirectory -Identity '{id}' -{scopeParam} {NewUrl("/EWS/Exchange.asmx")}",
            "OAB" => $"Set-OabVirtualDirectory -Identity '{id}' -{scopeParam} {NewUrl("/OAB")}",
            "EAS" => $"Set-ActiveSyncVirtualDirectory -Identity '{id}' -{scopeParam} {NewUrl("/Microsoft-Server-ActiveSync")}",
            "MAPI" => $"Set-MapiVirtualDirectory -Identity '{id}' -{scopeParam} {NewUrl("/mapi")}",
            "OutlookAnywhere" => e.Scope == "Intern"
                ? $"Set-OutlookAnywhere -Identity '{id}' -InternalHostname {exchangeHostname} -InternalClientsRequireSsl $true"
                : $"Set-OutlookAnywhere -Identity '{id}' -ExternalHostname {exchangeHostname} -ExternalClientsRequireSsl $true",
            "Autodiscover" =>
                $"Set-ClientAccessService -Identity '{id}' -AutoDiscoverServiceInternalUri https://{autodiscoverHostname ?? exchangeHostname}/Autodiscover/Autodiscover.xml",
            _ => null
        };
    }
}
