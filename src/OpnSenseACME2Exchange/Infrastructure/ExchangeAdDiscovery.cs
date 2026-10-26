using System.DirectoryServices;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Logging;

namespace OpnSenseACME2Exchange.Infrastructure;

/// <summary>
/// Ermittelt alle Exchange-Server aus der AD-Konfigurationspartition – braucht keinen "Startserver".
/// </summary>
public static class ExchangeAdDiscovery
{
    private const int EdgeRole = 64;

    public static List<ExchangeServerDiscovery> Discover(string? username = null, string? password = null)
    {
        using var rootDse = Entry("LDAP://RootDSE", username, password);
        var configNc = rootDse.Properties["configurationNamingContext"].Value as string
                       ?? throw new InvalidOperationException("configurationNamingContext nicht lesbar – ist der Rechner Domänenmitglied?");

        using var exRoot = Entry($"LDAP://CN=Microsoft Exchange,CN=Services,{configNc}", username, password);
        using var searcher = new DirectorySearcher(exRoot, "(objectCategory=msExchExchangeServer)",
            new[] { "name", "networkAddress", "serialNumber", "msExchCurrentServerRoles", "msExchServerSite", "msExchMDBAvailabilityGroupLink" })
        {
            PageSize = 500,
            SearchScope = SearchScope.Subtree
        };

        var list = new List<ExchangeServerDiscovery>();
        using var results = searcher.FindAll();
        foreach (SearchResult r in results)
        {
            var name = First(r, "name") ?? "?";
            var fqdn = r.Properties["networkAddress"].OfType<string>()
                .FirstOrDefault(a => a.StartsWith("ncacn_ip_tcp:", StringComparison.OrdinalIgnoreCase))?[13..] ?? name;
            var roles = r.Properties["msExchCurrentServerRoles"].Count > 0 ? Convert.ToInt32(r.Properties["msExchCurrentServerRoles"][0]) : 0;
            var version = First(r, "serialNumber");
            var site = Cn(First(r, "msExchServerSite"));
            var dag = Cn(First(r, "msExchMDBAvailabilityGroupLink"));
            list.Add(new ExchangeServerDiscovery(name, fqdn, version, dag, site, (roles & EdgeRole) != 0));
        }

        Log.Info($"AD-Abfrage: {list.Count} Exchange-Server gefunden ({string.Join(", ", list.Select(s => s.Name))}).");
        return list.OrderBy(s => s.Dag).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static DirectoryEntry Entry(string path, string? user, string? pw) =>
        string.IsNullOrWhiteSpace(user)
            ? new DirectoryEntry(path)
            : new DirectoryEntry(path, user, pw, AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing);

    private static string? First(SearchResult r, string prop) =>
        r.Properties[prop].Count > 0 ? r.Properties[prop][0]?.ToString() : null;

    /// <summary>"CN=DAG01,CN=Database Availability Groups,..." → "DAG01"</summary>
    private static string? Cn(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return null;
        var first = dn.Split(',')[0];
        return first.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ? first[3..] : first;
    }
}
