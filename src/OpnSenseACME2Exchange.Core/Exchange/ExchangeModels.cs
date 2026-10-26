using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;

namespace OpnSenseACME2Exchange.Core.Exchange;

/// <summary>Ein Zertifikat, wie Get-ExchangeCertificate es auf einem Server meldet.</summary>
public sealed record ExchangeCertInfo(
    string Thumbprint,
    string Subject,
    string Issuer,
    string? FriendlyName,
    DateTime NotBefore,
    DateTime NotAfter,
    IReadOnlyList<string> Services,
    IReadOnlyList<string> Domains,
    bool HasPrivateKey)
{
    public bool HasService(string service) =>
        Services.Any(s => string.Equals(s.Trim(), service, StringComparison.OrdinalIgnoreCase));

    public bool Covers(string host) => HostMatcher.Covers(Domains, host);

    public bool IsSelfSigned => string.Equals(Subject, Issuer, StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<string> ParseServices(string? services) =>
        string.IsNullOrWhiteSpace(services)
            ? Array.Empty<string>()
            : services.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(s => !s.Equals("None", StringComparison.OrdinalIgnoreCase))
                .ToList();
}

public sealed record ExchangeServerDiscovery(string Name, string Fqdn, string? Version, string? Dag, string? Site, bool IsEdge);

public sealed record ConnectionStep(string Name, bool Ok, string Detail);

public sealed class ConnectionTestResult
{
    public List<ConnectionStep> Steps { get; } = new();
    public bool Ok => Steps.All(s => s.Ok || s.Name.StartsWith("Ping", StringComparison.Ordinal));
    public string? WorkingPowerShellUri { get; set; }
    public string? ServerVersion { get; set; }
    public ExchangeCertInfo? CurrentIisCertificate { get; set; }

    public string Summary =>
        string.Join("; ", Steps.Select(s => $"{s.Name}: {(s.Ok ? "OK" : "FEHLER")}{(string.IsNullOrEmpty(s.Detail) ? "" : " (" + s.Detail + ")")}"));
}

/// <summary>Zugriff auf Exchange (Implementierung in der App über Remote-PowerShell).</summary>
public interface IExchangeOperations
{
    ConnectionTestResult TestConnection(ExchangeServerEntry server, string externalHostname, CancellationToken ct);
    IReadOnlyList<ExchangeCertInfo> GetCertificates(ExchangeServerEntry server, CancellationToken ct);
    /// <returns>Thumbprint des importierten Zertifikats.</returns>
    string ImportCertificate(ExchangeServerEntry server, byte[] pfx, string password, bool privateKeyExportable, CancellationToken ct);
    void EnableCertificate(ExchangeServerEntry server, string thumbprint, string services, CancellationToken ct);
    void RemoveCertificate(ExchangeServerEntry server, string thumbprint, CancellationToken ct);
    void IisReset(ExchangeServerEntry server, CancellationToken ct);
}

public enum DeployAction { Skip, EnableOnly, Deploy }

public sealed record DeployDecision(DeployAction Action, string Reason, ExchangeCertInfo? ReplacedCertificate);

public static class CertDecision
{
    /// <summary>
    /// Entscheidet, ob das neue Zertifikat auf einen Server muss.
    /// Getauscht wird nur, wenn es wirklich neuer ist – oder das aktive Zertifikat den Hostnamen nicht abdeckt bzw. abgelaufen ist.
    /// </summary>
    public static DeployDecision Decide(CertificateInfo candidate, IReadOnlyList<ExchangeCertInfo> installed,
        IReadOnlyList<string> requestedServices, string hostname, DateTime now)
    {
        if (requestedServices.Count == 0)
            return new DeployDecision(DeployAction.Skip, "Keine Exchange-Dienste ausgewählt.", null);

        var primary = requestedServices.FirstOrDefault(s => s.Equals("IIS", StringComparison.OrdinalIgnoreCase))
                      ?? requestedServices[0];

        var same = installed.FirstOrDefault(c => c.Thumbprint.Equals(candidate.Thumbprint, StringComparison.OrdinalIgnoreCase));
        if (same != null)
        {
            var missing = requestedServices.Where(s => !same.HasService(s)).ToList();
            return missing.Count == 0
                ? new DeployDecision(DeployAction.Skip, "Zertifikat ist bereits installiert und für alle Dienste aktiv.", null)
                : new DeployDecision(DeployAction.EnableOnly,
                    $"Zertifikat ist installiert, aber nicht aktiv für: {string.Join(",", missing)}.",
                    Active(installed, primary, candidate.Thumbprint));
        }

        var active = Active(installed, primary, null);
        if (active == null)
            return new DeployDecision(DeployAction.Deploy, $"Kein aktives Zertifikat für {primary} gefunden.", null);

        if (!active.Covers(hostname))
            return new DeployDecision(DeployAction.Deploy,
                $"Aktives {primary}-Zertifikat ({active.Thumbprint}) deckt '{hostname}' nicht ab.", active);

        if (active.NotAfter < now)
            return new DeployDecision(DeployAction.Deploy,
                $"Aktives {primary}-Zertifikat ist seit {active.NotAfter:dd.MM.yyyy} abgelaufen.", active);

        if (candidate.NotAfter > active.NotAfter ||
            (candidate.NotAfter == active.NotAfter && candidate.NotBefore > active.NotBefore))
            return new DeployDecision(DeployAction.Deploy,
                $"Neues Zertifikat ist neuer (Ablauf {candidate.NotAfter:dd.MM.yyyy} statt {active.NotAfter:dd.MM.yyyy}).", active);

        return new DeployDecision(DeployAction.Skip,
            $"Aktives Zertifikat ist gleich neu oder neuer (Ablauf {active.NotAfter:dd.MM.yyyy}, OPNsense {candidate.NotAfter:dd.MM.yyyy}).", null);
    }

    private static ExchangeCertInfo? Active(IReadOnlyList<ExchangeCertInfo> installed, string service, string? exceptThumbprint) =>
        installed
            .Where(c => c.HasService(service))
            .Where(c => exceptThumbprint == null || !c.Thumbprint.Equals(exceptThumbprint, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(c => c.NotAfter)
            .FirstOrDefault();

    /// <summary>
    /// Ein ersetztes Zertifikat darf nur entfernt werden, wenn es eine ältere Version desselben Zertifikats ist
    /// (deckt den Hostnamen ab, nicht selbstsigniert, älter) und alle seine Dienste vom neuen übernommen wurden.
    /// </summary>
    public static bool MayRemove(ExchangeCertInfo old, CertificateInfo replacement, IReadOnlyList<string> requestedServices, string hostname) =>
        !old.Thumbprint.Equals(replacement.Thumbprint, StringComparison.OrdinalIgnoreCase)
        && old.Covers(hostname)
        && !old.IsSelfSigned
        && old.NotAfter < replacement.NotAfter
        && old.Services.All(s => requestedServices.Any(r => r.Equals(s, StringComparison.OrdinalIgnoreCase)));
}
