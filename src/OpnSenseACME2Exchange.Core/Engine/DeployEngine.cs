using System.Diagnostics;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Net;
using OpnSenseACME2Exchange.Core.OpnSense;

namespace OpnSenseACME2Exchange.Core.Engine;

public enum ServerOutcome { Ok, Skipped, DryRun, Warning, Failed }

public sealed class ServerRunResult
{
    public required string Server { get; init; }
    public string Action { get; set; } = "";
    public ServerOutcome Outcome { get; set; }
    public string Details { get; set; } = "";
}

public sealed class RunResult
{
    public DateTime StartedAt { get; init; } = DateTime.Now;
    public TimeSpan Duration { get; set; }
    public bool DryRun { get; init; }
    public CertificateInfo? Certificate { get; set; }
    public string? CertificateSource { get; set; }
    public List<ServerRunResult> Servers { get; } = new();
    public List<string> Warnings { get; } = new();
    public string? FatalError { get; set; }

    public bool Success => FatalError == null && Servers.All(s => s.Outcome != ServerOutcome.Failed);

    public string Summary
    {
        get
        {
            if (FatalError != null) return "FEHLER: " + FatalError;
            int ok = Servers.Count(s => s.Outcome == ServerOutcome.Ok);
            int skip = Servers.Count(s => s.Outcome == ServerOutcome.Skipped);
            int dry = Servers.Count(s => s.Outcome == ServerOutcome.DryRun);
            int warn = Servers.Count(s => s.Outcome == ServerOutcome.Warning);
            int fail = Servers.Count(s => s.Outcome == ServerOutcome.Failed);
            return $"{(DryRun ? "Dry-Run" : "Lauf")} beendet: {ok} getauscht, {skip} aktuell, {dry} simuliert, {warn} Warnung, {fail} Fehler";
        }
    }
}

/// <summary>Orchestriert: Zertifikat von der OPNsense holen → prüfen → PFX bauen → auf alle Exchange-Server verteilen → verifizieren.</summary>
public sealed class DeployEngine
{
    private static readonly SemaphoreSlim RunLock = new(1, 1);

    private readonly AppConfig _cfg;
    private readonly ICertificateSource _source;
    private readonly IExchangeOperations _exchange;
    private readonly ITlsProbe _probe;
    private readonly Action<TimeSpan, CancellationToken> _delay;
    private readonly Func<DateTime> _clock;

    public DeployEngine(AppConfig cfg, ICertificateSource source, IExchangeOperations exchange, ITlsProbe probe,
        Action<TimeSpan, CancellationToken>? delay = null, Func<DateTime>? clock = null)
    {
        _cfg = cfg;
        _source = source;
        _exchange = exchange;
        _probe = probe;
        _delay = delay ?? ((t, ct) => Task.Delay(t, ct).GetAwaiter().GetResult());
        _clock = clock ?? (() => DateTime.Now);
    }

    public int VerifyAttempts { get; init; } = 3;
    public TimeSpan VerifyDelay { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromSeconds(10);

    public event Action<ServerRunResult>? ServerUpdated;

    public RunResult Run(bool dryRun, CancellationToken ct)
    {
        var result = new RunResult { DryRun = dryRun };
        var sw = Stopwatch.StartNew();
        if (!RunLock.Wait(0))
        {
            result.FatalError = "Es läuft bereits ein Durchlauf.";
            Log.Warn(result.FatalError);
            return result;
        }

        try
        {
            Log.Info($"══ {(dryRun ? "DRY-RUN" : "Durchlauf")} gestartet ══");
            RunCore(result, dryRun, ct);
        }
        catch (OperationCanceledException)
        {
            result.FatalError = "Abgebrochen.";
            Log.Warn("Durchlauf abgebrochen.");
        }
        catch (Exception ex)
        {
            result.FatalError = Log.Describe(ex);
            Log.Error("Durchlauf fehlgeschlagen", ex);
        }
        finally
        {
            sw.Stop();
            result.Duration = sw.Elapsed;
            Log.Info($"══ {result.Summary} (Dauer {result.Duration.TotalSeconds:0.0}s) ══");
            RunLock.Release();
        }
        return result;
    }

    private void RunCore(RunResult result, bool dryRun, CancellationToken ct)
    {
        var hostname = _cfg.Selection.ExchangeHostname.Trim().ToLowerInvariant();
        var servers = _cfg.Exchange.Servers.Where(s => s.Enabled && !string.IsNullOrWhiteSpace(s.Fqdn)).ToList();
        var services = ExchangeCertInfo.ParseServices(_cfg.Exchange.ServicesString());

        if (string.IsNullOrWhiteSpace(hostname)) throw new InvalidOperationException("Kein Exchange-Hostname konfiguriert.");
        if (servers.Count == 0) throw new InvalidOperationException("Keine Exchange-Server aktiviert.");
        if (services.Count == 0) throw new InvalidOperationException("Keine Exchange-Dienste ausgewählt.");

        // 1) Zertifikat von der OPNsense
        using var lookup = _source.Resolve(_cfg.Selection, ct);
        foreach (var w in lookup.Warnings) { result.Warnings.Add(w); Log.Warn(w); }
        if (!lookup.Success)
            throw new InvalidOperationException(string.Join(" ", lookup.Errors));

        var bundle = lookup.Bundle!;
        result.Certificate = bundle.Info;
        result.CertificateSource = $"{lookup.SourceNode}:{lookup.SourcePath}";
        if (!string.Equals(_cfg.Selection.LastKnownPemPath, lookup.SourcePath, StringComparison.Ordinal))
            _cfg.Selection.LastKnownPemPath = lookup.SourcePath;

        // 2) Prüfen
        var validation = CertificateValidator.Validate(bundle.Info, OpnSenseCertificateSource.RequiredNames(_cfg.Selection), _clock());
        foreach (var w in validation.Warnings) { result.Warnings.Add(w); Log.Warn(w); }
        if (!validation.Ok)
            throw new InvalidOperationException("Zertifikat ungültig: " + string.Join(" ", validation.Errors));
        Log.Info($"Zertifikat OK: {bundle.Info.ShortDescription} | {bundle.Info.KeyAlgorithm} | SAN: {string.Join(", ", bundle.Info.DnsNames)}");

        // 3) PFX vorbereiten (nur im Speicher)
        var pfxPassword = CertificateBundle.GeneratePassword();
        byte[]? pfx = dryRun ? null : bundle.ExportPfx(pfxPassword);

        try
        {
            // 4) Pro Server – Fehler auf einem Server stoppen die anderen nicht
            foreach (var server in servers)
            {
                ct.ThrowIfCancellationRequested();
                var sr = new ServerRunResult { Server = server.Name.Length > 0 ? server.Name : server.Fqdn };
                result.Servers.Add(sr);
                try
                {
                    ProcessServer(server, bundle.Info, pfx, pfxPassword, services, hostname, dryRun, sr, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    sr.Outcome = ServerOutcome.Failed;
                    sr.Details = Log.Describe(ex);
                    Log.Error($"[{sr.Server}] fehlgeschlagen", ex);
                }
                server.LastStatus = $"{sr.Outcome}: {sr.Action}";
                ServerUpdated?.Invoke(sr);
            }
        }
        finally
        {
            if (pfx != null) Array.Clear(pfx);
        }
    }

    private void ProcessServer(ExchangeServerEntry server, CertificateInfo cert, byte[]? pfx, string pfxPassword,
        IReadOnlyList<string> services, string hostname, bool dryRun, ServerRunResult sr, CancellationToken ct)
    {
        var name = sr.Server;
        var installed = WithRetry(() => _exchange.GetCertificates(server, ct), $"[{name}] Zertifikate abfragen", ct);
        var current = installed.Where(c => c.HasService("IIS")).OrderByDescending(c => c.NotAfter).FirstOrDefault();
        if (current != null) server.CurrentCertificate = $"{current.Thumbprint} bis {current.NotAfter:dd.MM.yyyy}";

        var decision = CertDecision.Decide(cert, installed, services, hostname, _clock());
        sr.Action = decision.Action switch
        {
            DeployAction.Skip => "Kein Tausch",
            DeployAction.EnableOnly => "Dienste aktivieren",
            _ => "Zertifikat tauschen"
        };
        Log.Info($"[{name}] Entscheidung: {sr.Action} – {decision.Reason}");

        if (dryRun)
        {
            sr.Outcome = decision.Action == DeployAction.Skip ? ServerOutcome.Skipped : ServerOutcome.DryRun;
            sr.Details = decision.Reason + (decision.Action == DeployAction.Skip ? "" : " (simuliert, nichts geändert)");
            if (decision.Action == DeployAction.Skip && NeedsIis(services))
            {
                var presented = SafeProbe(server, hostname);
                if (presented != null && !presented.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    sr.Outcome = ServerOutcome.Warning;
                    sr.Details += $" ACHTUNG: IIS präsentiert {presented} – echter Lauf würde neu binden.";
                }
            }
            return;
        }

        if (decision.Action == DeployAction.Skip)
        {
            sr.Outcome = ServerOutcome.Skipped;
            sr.Details = decision.Reason;
            // Selbstheilung: installiert & "aktiv", aber IIS liefert etwas anderes aus -> neu binden
            if (_cfg.Exchange.VerifyAfterDeploy && NeedsIis(services) && cert.Covers(hostname)
                && installed.Any(c => c.Thumbprint.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
            {
                var presented = SafeProbe(server, hostname);
                if (presented != null && !presented.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    Log.Warn($"[{name}] IIS präsentiert {presented} statt {cert.Thumbprint} – Selbstheilung: Zertifikat neu binden.");
                    _exchange.EnableCertificate(server, cert.Thumbprint, string.Join(",", services), ct);
                    sr.Action = "Neu gebunden (Selbstheilung)";
                    Verify(server, cert, hostname, sr, ct);
                }
            }
            return;
        }

        string thumbprint = cert.Thumbprint;
        if (decision.Action == DeployAction.Deploy)
        {
            if (installed.Any(c => c.Thumbprint.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                Log.Info($"[{name}] Zertifikat bereits im Store – Import übersprungen.");
            else
            {
                Log.Info($"[{name}] Importiere Zertifikat {cert.Thumbprint} …");
                thumbprint = ImportSelfHealing(server, cert, pfx!, pfxPassword, name, ct);
                if (!thumbprint.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"Import lieferte Thumbprint {thumbprint}, erwartet {cert.Thumbprint}.");
            }
        }

        Log.Info($"[{name}] Aktiviere {thumbprint} für {string.Join(",", services)} …");
        WithRetry(() => { _exchange.EnableCertificate(server, thumbprint, string.Join(",", services), ct); return true; },
            $"[{name}] Aktivieren", ct);
        server.CurrentCertificate = $"{thumbprint} bis {cert.NotAfter:dd.MM.yyyy}";

        sr.Outcome = ServerOutcome.Ok;
        sr.Details = decision.Reason;

        if (_cfg.Exchange.VerifyAfterDeploy && NeedsIis(services))
            Verify(server, cert, hostname, sr, ct);

        if (_cfg.Exchange.RemoveReplacedCertificate && decision.ReplacedCertificate is { } old && sr.Outcome == ServerOutcome.Ok)
        {
            if (CertDecision.MayRemove(old, cert, services, hostname))
            {
                try
                {
                    _exchange.RemoveCertificate(server, old.Thumbprint, ct);
                    Log.Info($"[{name}] Altes Zertifikat {old.Thumbprint} entfernt.");
                    sr.Details += $" Altes Zertifikat {old.Thumbprint} entfernt.";
                }
                catch (Exception ex)
                {
                    Log.Warn($"[{name}] Altes Zertifikat {old.Thumbprint} konnte nicht entfernt werden: {Log.Describe(ex)}");
                }
            }
            else Log.Info($"[{name}] Altes Zertifikat {old.Thumbprint} bleibt (nicht eindeutig ersetzbar).");
        }
    }

    /// <summary>Import mit Selbstheilung: schlägt er fehl, wird geprüft, ob das Zertifikat trotzdem angekommen ist, bevor erneut importiert wird.</summary>
    private string ImportSelfHealing(ExchangeServerEntry server, CertificateInfo cert, byte[] pfx, string password, string name, CancellationToken ct)
    {
        try
        {
            return _exchange.ImportCertificate(server, pfx, password, _cfg.Exchange.PrivateKeyExportable, ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Log.Warn($"[{name}] Import fehlgeschlagen ({Log.Describe(ex)}) – prüfe, ob das Zertifikat dennoch im Store liegt.");
            _delay(RetryDelay, ct);
            var now = _exchange.GetCertificates(server, ct);
            if (now.Any(c => c.Thumbprint.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase)))
            {
                Log.Info($"[{name}] Zertifikat ist trotz Fehlermeldung vorhanden – weiter.");
                return cert.Thumbprint;
            }
            Log.Info($"[{name}] Zweiter Importversuch …");
            return _exchange.ImportCertificate(server, pfx, password, _cfg.Exchange.PrivateKeyExportable, ct);
        }
    }

    private static bool NeedsIis(IReadOnlyList<string> services) =>
        services.Any(s => s.Equals("IIS", StringComparison.OrdinalIgnoreCase));

    private void Verify(ExchangeServerEntry server, CertificateInfo cert, string hostname, ServerRunResult sr, CancellationToken ct)
    {
        string? presented = null;
        for (int i = 1; i <= VerifyAttempts; i++)
        {
            ct.ThrowIfCancellationRequested();
            presented = SafeProbe(server, hostname);
            if (presented != null && presented.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                Log.Info($"[{sr.Server}] Verifiziert: IIS präsentiert das neue Zertifikat.");
                sr.Details += " Verifiziert.";
                return;
            }
            if (i < VerifyAttempts) _delay(VerifyDelay, ct);
        }

        if (_cfg.Exchange.IisResetOnMismatch)
        {
            Log.Warn($"[{sr.Server}] IIS präsentiert {presented ?? "nichts"} – führe iisreset /noforce aus.");
            try
            {
                _exchange.IisReset(server, ct);
                _delay(VerifyDelay, ct);
                presented = SafeProbe(server, hostname);
                if (presented != null && presented.Equals(cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    Log.Info($"[{sr.Server}] Nach iisreset verifiziert.");
                    sr.Details += " Verifiziert nach iisreset.";
                    return;
                }
            }
            catch (Exception ex)
            {
                Log.Warn($"[{sr.Server}] iisreset fehlgeschlagen: {Log.Describe(ex)}");
            }
        }

        sr.Outcome = ServerOutcome.Warning;
        sr.Details += $" Verifikation fehlgeschlagen: IIS präsentiert {presented ?? "keine Verbindung"}.";
        Log.Warn($"[{sr.Server}] Verifikation fehlgeschlagen: präsentiert {presented ?? "keine Verbindung"}, erwartet {cert.Thumbprint}.");
    }

    private string? SafeProbe(ExchangeServerEntry server, string hostname)
    {
        try { return _probe.GetPresentedThumbprint(server.Fqdn, 443, hostname, TimeSpan.FromSeconds(10)); }
        catch (Exception ex)
        {
            Log.Debug($"TLS-Probe {server.Fqdn}:443 fehlgeschlagen: {Log.Describe(ex)}");
            return null;
        }
    }

    private T WithRetry<T>(Func<T> action, string what, CancellationToken ct)
    {
        try { return action(); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Log.Warn($"{what} fehlgeschlagen ({Log.Describe(ex)}) – neuer Versuch in {RetryDelay.TotalSeconds:0}s.");
            _delay(RetryDelay, ct);
            return action();
        }
    }
}
