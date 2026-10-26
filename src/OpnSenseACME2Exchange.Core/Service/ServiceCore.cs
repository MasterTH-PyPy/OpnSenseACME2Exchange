using System.Text.Json;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Haproxy;
using OpnSenseACME2Exchange.Core.Ipc;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Net;
using OpnSenseACME2Exchange.Core.OpnSense;

namespace OpnSenseACME2Exchange.Core.Service;

/// <summary>Windows-spezifische Teile, die der Dienst braucht (Implementierung in der App).</summary>
public interface IServiceBackend
{
    string Version { get; }
    string Account { get; }
    string MachineName { get; }
    string DataDirectory { get; }
    string LogDirectory { get; }
    ITlsProbe TlsProbe { get; }
    ISshSessionFactory CreateSshFactory(AppConfig cfg, Func<OpnSenseNode, string, bool> confirmUnknownHostKey);
    IExchangeOperations CreateExchange(AppConfig cfg);
    List<ExchangeServerDiscovery> DiscoverExchangeServers(AppConfig cfg);
    /// <summary>Prozessübergreifende Sperre (z.B. gegen parallelen Kommandozeilen-Lauf).</summary>
    RunResult Guard(Func<RunResult> run, bool dryRun);
    void ApplyLogging(AppConfig cfg);
}

/// <summary>
/// Herz des Dienstes: hält die Konfiguration (einzige schreibende Stelle), beantwortet GUI-Anfragen,
/// führt Tests/Läufe exklusiv aus und plant den täglichen Lauf.
/// </summary>
public sealed class ServiceCore
{
    private readonly ConfigStore _store;
    private readonly StateStore _state;
    private readonly IServiceBackend _backend;
    private readonly Func<DateTime> _clock;
    private readonly object _cfgLock = new();
    private readonly SemaphoreSlim _op = new(1, 1);

    private AppConfig _cfg = new();
    private string _snapshot = "{}";
    private string? _currentOp;
    private DateTime? _opStarted;
    private CancellationTokenSource? _opCts;
    private RunResult? _liveRun;
    private Task? _runTask;
    private DateTime _started;
    private DateTime _lastHeartbeat = DateTime.MinValue;

    public ServiceCore(ConfigStore store, StateStore state, IServiceBackend backend, Func<DateTime>? clock = null)
    {
        _store = store;
        _state = state;
        _backend = backend;
        _clock = clock ?? (() => DateTime.Now);
    }

    /// <summary>Nur für Tests: Wartezeiten der Engine abkürzen.</summary>
    public Action<TimeSpan, CancellationToken>? EngineDelay { get; init; }

    public Task? CurrentRunTask => _runTask;

    // ───────────────────────── Lebenszyklus ─────────────────────────

    public void Start()
    {
        _started = _clock();
        string? configError = null;
        try { _cfg = _store.Load(); }
        catch (Exception ex)
        {
            _cfg = new AppConfig();
            configError = "Konfiguration nicht lesbar: " + Log.Describe(ex);
        }
        _backend.ApplyLogging(_cfg);
        UpdateSnapshot();

        Log.Info($"Dienst gestartet – Version {_backend.Version}, Konto {_backend.Account}, Daten {_backend.DataDirectory}.");
        if (configError != null) Log.Error(configError);

        _state.Update(s =>
        {
            s.Version = _backend.Version;
            s.Account = _backend.Account;
            s.ServiceStarted = _started;
            s.Heartbeat = _started;
            s.Running = false;
            s.RunStarted = null;
            s.ConfigError = configError;
        });
    }

    public void Stop()
    {
        _opCts?.Cancel();
        try { _runTask?.Wait(TimeSpan.FromSeconds(25)); } catch { /* abgebrochen */ }
        _state.Update(s => { s.Running = false; s.Heartbeat = _clock(); });
        Log.Info("Dienst beendet.");
    }

    /// <summary>Vom Dienst regelmäßig aufgerufen (alle ~15 s): Heartbeat und geplanter Lauf.</summary>
    public void SchedulerTick(CancellationToken ct)
    {
        var now = _clock();
        AutoModeSettings auto;
        lock (_cfgLock) auto = _cfg.Auto;
        var st = _state.Load();
        var action = ServiceScheduler.Decide(now, auto, st, out var next);

        if ((now - _lastHeartbeat).TotalSeconds >= 60 || st.NextRun != next)
        {
            _lastHeartbeat = now;
            _state.Update(s => { s.Heartbeat = now; s.NextRun = next; });
        }

        if (action == ServiceTickAction.None) return;
        if (!_op.Wait(0)) return; // GUI-Aktion läuft gerade -> nächster Takt

        var trigger = action == ServiceTickAction.Retry
            ? $"Wiederholung {st.RetryCount}/{ServiceScheduler.MaxRetries}"
            : $"geplant {auto.Time}";
        Log.Info($"Auto-Modus: {trigger}{(auto.DryRun ? " (Dry-Run)" : "")}.");
        try { ExecuteRun(auto.DryRun, trigger, action, ct); }
        finally { _op.Release(); }
    }

    // ───────────────────────── Anfragen der GUI ─────────────────────────

    public async Task<PipeResponse> HandleAsync(PipeRequest req, string client, CancellationToken ct)
    {
        try
        {
            switch (req.Command)
            {
                case Commands.Ping: return PipeResponse.Success(_backend.Version);
                case Commands.GetStatus: return PipeResponse.Success(BuildStatus());
                case Commands.GetConfig: return PipeResponse.Success(BuildConfigDto());
                case Commands.SaveConfig: return SaveConfig(PipeProtocol.FromElement<SaveConfigRequest>(req.Payload), client);
                case Commands.TrustHostKey: return TrustHostKey(PipeProtocol.FromElement<TrustHostKeyRequest>(req.Payload), client);
                case Commands.ResetHostKey: return ResetHostKey(PipeProtocol.FromElement<string>(req.Payload), client);
                case Commands.TestNodes: return await Exclusive("Teste OPNsense-Knoten", client, TestNodes);
                case Commands.ReadHaproxy: return await Exclusive("Lese HAProxy-Konfiguration", client, ReadHaproxy);
                case Commands.ResolveCertificate: return await Exclusive("Ermittle Zertifikat", client, ResolveCertificate);
                case Commands.DiscoverServers: return await Exclusive("Ermittle Exchange-Server (AD)", client, (_, _) => Discover());
                case Commands.TestServers:
                    var fqdns = PipeProtocol.FromElement<TestServersRequest>(req.Payload)?.Fqdns ?? new List<string>();
                    return await Exclusive("Teste Exchange-Server", client, (t, _) => TestServers(fqdns, t));
                case Commands.StartRun: return StartRun(PipeProtocol.FromElement<StartRunRequest>(req.Payload)?.DryRun ?? true, client);
                case Commands.Cancel:
                    var op = _currentOp;
                    _opCts?.Cancel();
                    if (op != null) Log.Warn($"Abbruch von '{op}' angefordert durch {client}.");
                    return PipeResponse.Success(op);
                case Commands.ListLogs: return PipeResponse.Success(LogReader.List(Log.Directory));
                case Commands.ReadLog:
                    var r = PipeProtocol.FromElement<ReadLogRequest>(req.Payload) ?? throw new ArgumentException("ReadLog ohne Angaben.");
                    return PipeResponse.Success(LogReader.Read(Log.Directory, r.Name, r.Offset));
                default:
                    return PipeResponse.Fail($"Unbekannter Befehl '{req.Command}'.");
            }
        }
        catch (Exception ex)
        {
            Log.Error($"Anfrage {req.Command} von {client} fehlgeschlagen", ex);
            return PipeResponse.Fail(Log.Describe(ex));
        }
    }

    private async Task<PipeResponse> Exclusive(string name, string client, Func<CancellationToken, List<UnknownHostKey>, object?> work)
    {
        if (!_op.Wait(0)) return PipeResponse.Fail($"Der Dienst ist beschäftigt: {_currentOp ?? "Lauf"} – bitte warten.");
        var unknown = new List<UnknownHostKey>();
        using var cts = new CancellationTokenSource();
        _opCts = cts;
        _currentOp = name;
        _opStarted = _clock();
        try
        {
            Log.Info($"{name} (angefordert von {client})");
            var result = await Task.Run(() => work(cts.Token, unknown));
            Persist();
            return PipeResponse.Success(result, unknown);
        }
        catch (OperationCanceledException)
        {
            Persist();
            return PipeResponse.Fail("Abgebrochen.", unknown);
        }
        catch (Exception ex)
        {
            Log.Error($"{name} fehlgeschlagen", ex);
            Persist();
            return PipeResponse.Fail(Log.Describe(ex), unknown);
        }
        finally
        {
            _currentOp = null;
            _opStarted = null;
            _opCts = null;
            _op.Release();
        }
    }

    private Func<OpnSenseNode, string, bool> Collect(List<UnknownHostKey> unknown) => (node, fp) =>
    {
        lock (unknown)
            if (!unknown.Any(u => u.Host == node.Host && u.Fingerprint == fp))
                unknown.Add(new UnknownHostKey(node.Host, node.Name, fp));
        return false; // nie ohne Bestätigung durch einen Menschen in der GUI
    };

    private OpnSenseCertificateSource Source(List<UnknownHostKey> unknown) =>
        new(_cfg.OpnSense, _backend.CreateSshFactory(_cfg, Collect(unknown)));

    // ───────────────────────── Konfiguration ─────────────────────────

    private void UpdateSnapshot()
    {
        lock (_cfgLock) _snapshot = JsonSerializer.Serialize(_cfg, ConfigStore.JsonOptions);
    }

    private void Persist()
    {
        try
        {
            lock (_cfgLock) _store.Save(_cfg);
        }
        catch (Exception ex) { Log.Error("Konfiguration konnte nicht gespeichert werden", ex); }
        UpdateSnapshot();
    }

    private ConfigDto BuildConfigDto()
    {
        AppConfig copy;
        lock (_cfgLock) copy = JsonSerializer.Deserialize<AppConfig>(_snapshot, ConfigStore.JsonOptions)!;
        var dto = new ConfigDto
        {
            HasSshPassword = !string.IsNullOrEmpty(copy.OpnSense.PasswordProtected),
            HasKeyPassphrase = !string.IsNullOrEmpty(copy.OpnSense.PrivateKeyPassphraseProtected),
            HasExchangePassword = !string.IsNullOrEmpty(copy.Exchange.PasswordProtected),
            DataDirectory = _backend.DataDirectory,
            ServiceAccount = _backend.Account,
            MachineName = _backend.MachineName
        };
        // Geheimnisse verlassen den Dienst nie – auch nicht verschlüsselt
        copy.OpnSense.PasswordProtected = null;
        copy.OpnSense.PrivateKeyPassphraseProtected = null;
        copy.Exchange.PasswordProtected = null;
        dto.Config = copy;
        return dto;
    }

    private PipeResponse SaveConfig(SaveConfigRequest? req, string client)
    {
        if (req?.Config == null) return PipeResponse.Fail("Keine Konfiguration übergeben.");
        if (!_op.Wait(0)) return PipeResponse.Fail($"Der Dienst ist beschäftigt: {_currentOp ?? "Lauf"} – Speichern danach erneut versuchen.");
        try
        {
            var incoming = req.Config;
            lock (_cfgLock)
            {
                var old = _cfg;
                incoming.OpnSense.PasswordProtected = Merge(old.OpnSense.PasswordProtected, req.SshPassword);
                incoming.OpnSense.PrivateKeyPassphraseProtected = Merge(old.OpnSense.PrivateKeyPassphraseProtected, req.KeyPassphrase);
                incoming.Exchange.PasswordProtected = Merge(old.Exchange.PasswordProtected, req.ExchangePassword);

                // Sicherheitsrelevantes nie blind von der GUI übernehmen: Hostkeys nur über TrustHostKey
                foreach (var n in incoming.OpnSense.Nodes)
                {
                    var known = old.OpnSense.Nodes.FirstOrDefault(o => o.Host.Equals(n.Host, StringComparison.OrdinalIgnoreCase));
                    n.HostKeyFingerprint = known?.HostKeyFingerprint;
                }
                // Gelerntes behalten, wenn die GUI es nicht kennt
                foreach (var s in incoming.Exchange.Servers)
                {
                    var known = old.Exchange.Servers.FirstOrDefault(o => o.Fqdn.Equals(s.Fqdn, StringComparison.OrdinalIgnoreCase));
                    if (known == null) continue;
                    // AD-Daten gehören dem Dienst (aus der Ermittlung), nicht der GUI
                    s.IsEdge = known.IsEdge;
                    s.MissingInAd = known.MissingInAd;
                    s.Dag = known.Dag ?? s.Dag;
                    s.Site = known.Site ?? s.Site;
                    s.Version = known.Version ?? s.Version;
                    s.PowerShellUri ??= known.PowerShellUri;
                    s.CurrentCertificate ??= known.CurrentCertificate;
                    s.LastStatus ??= known.LastStatus;
                }
                incoming.Selection.LastKnownPemPath ??= old.Selection.LastKnownPemPath;
                _cfg = incoming;
            }
            Persist();
            _backend.ApplyLogging(_cfg);
            _state.Update(s => s.ConfigError = null);
            Log.Info($"Konfiguration gespeichert von {client}.");
            return PipeResponse.Success(BuildConfigDto());
        }
        finally { _op.Release(); }
    }

    private string? Merge(string? existingProtected, string? newPlain) =>
        string.IsNullOrEmpty(newPlain) ? existingProtected : _store.Hide(newPlain);

    private PipeResponse TrustHostKey(TrustHostKeyRequest? req, string client)
    {
        if (req == null) return PipeResponse.Fail("Keine Angaben.");
        OpnSenseNode? node;
        lock (_cfgLock)
        {
            node = _cfg.OpnSense.Nodes.FirstOrDefault(n => n.Host.Equals(req.Host, StringComparison.OrdinalIgnoreCase));
            if (node == null) return PipeResponse.Fail($"Knoten {req.Host} ist nicht konfiguriert.");
            if (!string.IsNullOrEmpty(node.HostKeyFingerprint) && node.HostKeyFingerprint != req.Fingerprint)
                return PipeResponse.Fail($"Für {req.Host} ist bereits ein anderer Hostkey hinterlegt – erst zurücksetzen.");
            node.HostKeyFingerprint = req.Fingerprint;
        }
        Persist();
        Log.Info($"SSH-Hostkey für {node} bestätigt durch {client}: {req.Fingerprint}");
        return PipeResponse.Success();
    }

    private PipeResponse ResetHostKey(string? host, string client)
    {
        OpnSenseNode? node;
        lock (_cfgLock) node = _cfg.OpnSense.Nodes.FirstOrDefault(n => n.Host.Equals(host, StringComparison.OrdinalIgnoreCase));
        if (node == null) return PipeResponse.Fail($"Knoten {host} ist nicht konfiguriert.");
        Log.Warn($"SSH-Hostkey für {node} zurückgesetzt durch {client} (war {node.HostKeyFingerprint}).");
        node.HostKeyFingerprint = null;
        Persist();
        return PipeResponse.Success();
    }

    // ───────────────────────── Operationen ─────────────────────────

    private object TestNodes(CancellationToken ct, List<UnknownHostKey> unknown)
    {
        var src = Source(unknown);
        var list = new List<NodeStatusDto>();
        foreach (var n in _cfg.OpnSense.Nodes)
        {
            ct.ThrowIfCancellationRequested();
            var st = src.Probe(n);
            Log.Info($"OPNsense {n}: {st.Summary}");
            list.Add(new NodeStatusDto(n.Host, n.Name, st.Reachable, st.Carp, st.Version, st.HaproxyRunning, st.ConfigReadable,
                st.Error, st.Summary, n.HostKeyFingerprint));
        }
        return list;
    }

    private object ReadHaproxy(CancellationToken ct, List<UnknownHostKey> unknown)
    {
        var src = Source(unknown);
        var (text, node) = src.ReadHaproxyConfig();
        var parsed = HaproxyConfig.Parse(text);
        var sections = new List<HaproxySectionDto>();
        foreach (var sec in parsed.Sections)
        {
            ct.ThrowIfCancellationRequested();
            var hosts = new SortedSet<string>(sec.Hostnames, StringComparer.OrdinalIgnoreCase);
            if (sec.CanCarryCertificate)
            {
                try { hosts = src.ReadReferencedHostnames(sec, node); }
                catch (Exception ex) { Log.Debug($"Hostnamen für {sec.Key} nicht vollständig lesbar: {Log.Describe(ex)}"); }
            }
            sections.Add(new HaproxySectionDto(sec.Key, sec.Type, sec.Name, sec.Text, sec.TerminatesTls, sec.CanCarryCertificate, hosts.ToList()));
        }
        return new HaproxyReadResult(node.ToString(), sections);
    }

    private object ResolveCertificate(CancellationToken ct, List<UnknownHostKey> unknown)
    {
        using var r = Source(unknown).Resolve(_cfg.Selection, ct);
        CertificateValidator.Result? v = r.Bundle != null
            ? CertificateValidator.Validate(r.Bundle.Info, OpnSenseCertificateSource.RequiredNames(_cfg.Selection), _clock())
            : null;
        if (r.SourcePath != null) _cfg.Selection.LastKnownPemPath = r.SourcePath;
        return new ResolveResultDto(r.Bundle?.Info, r.SourceNode?.ToString(), r.SourcePath, r.SectionKey,
            r.Candidates.ToList(), r.Warnings.ToList(), r.Errors.ToList(),
            v?.Errors ?? new List<string>(), v?.Warnings ?? new List<string>());
    }

    private object Discover()
    {
        var found = _backend.DiscoverExchangeServers(_cfg);
        var (added, missing) = MergeDiscovery(found);
        Log.Info($"{found.Count} Exchange-Server im AD, {added} neu, {missing} nicht mehr vorhanden.");
        return new DiscoveryResultDto(found, added);
    }

    /// <summary>Gleicht die Serverliste mit dem AD ab: neue hinzufügen (Edge deaktiviert), verschwundene markieren.</summary>
    private (int Added, int Missing) MergeDiscovery(List<ExchangeServerDiscovery> found)
    {
        int added = 0, missing = 0;
        lock (_cfgLock)
        {
            foreach (var d in found)
            {
                var existing = _cfg.Exchange.Servers.FirstOrDefault(s =>
                    s.Fqdn.Equals(d.Fqdn, StringComparison.OrdinalIgnoreCase) || s.Name.Equals(d.Name, StringComparison.OrdinalIgnoreCase));
                if (existing == null)
                {
                    existing = new ExchangeServerEntry
                    {
                        Enabled = !d.IsEdge,
                        LastStatus = d.IsEdge ? "Edge-Transport – deaktiviert" : "neu im AD ermittelt"
                    };
                    _cfg.Exchange.Servers.Add(existing);
                    added++;
                    Log.Info($"Neuer Exchange-Server: {d.Name} ({d.Fqdn}, DAG {d.Dag ?? "–"}){(d.IsEdge ? " – Edge, deaktiviert" : "")}.");
                }
                else if (existing.MissingInAd)
                {
                    Log.Info($"{existing.Name} ist wieder im AD vorhanden.");
                    if (existing.LastStatus?.StartsWith("nicht (mehr)", StringComparison.Ordinal) == true) existing.LastStatus = null;
                }
                existing.Name = d.Name;
                existing.Fqdn = d.Fqdn;
                existing.Version = d.Version;
                existing.Dag = d.Dag;
                existing.Site = d.Site;
                existing.IsEdge = d.IsEdge;
                existing.MissingInAd = false;
            }
            foreach (var s in _cfg.Exchange.Servers.Where(s => !found.Any(d => d.Fqdn.Equals(s.Fqdn, StringComparison.OrdinalIgnoreCase))))
            {
                if (!s.MissingInAd) Log.Warn($"{s.Name} ({s.Fqdn}) ist nicht mehr im AD – wird bei Läufen übersprungen.");
                s.MissingInAd = true;
                s.LastStatus = "nicht (mehr) im AD gefunden";
                missing++;
            }
        }
        return (added, missing);
    }

    /// <summary>Vor einem Lauf: Serverliste aktualisieren. Scheitert das AD, wird mit der bekannten Liste weitergemacht.</summary>
    private List<string> RefreshServersBeforeRun()
    {
        var warnings = new List<string>();
        if (!_cfg.Exchange.AutoDiscoverBeforeRun) return warnings;
        try
        {
            var found = _backend.DiscoverExchangeServers(_cfg);
            if (found.Count == 0)
            {
                warnings.Add("AD-Abfrage lieferte keine Exchange-Server – bekannte Serverliste wird verwendet.");
                return warnings;
            }
            var (added, missing) = MergeDiscovery(found);
            if (added > 0) warnings.Add($"{added} neue(r) Exchange-Server aus dem AD übernommen.");
            if (missing > 0) warnings.Add($"{missing} Exchange-Server nicht mehr im AD – übersprungen.");
            Log.Info($"AD-Abgleich vor dem Lauf: {found.Count} Server, {added} neu, {missing} fehlen.");
        }
        catch (Exception ex)
        {
            var msg = "AD-Abgleich vor dem Lauf fehlgeschlagen – bekannte Serverliste wird verwendet: " + Log.Describe(ex);
            warnings.Add(msg);
            Log.Warn(msg);
        }
        return warnings;
    }

    private object TestServers(List<string> fqdns, CancellationToken ct)
    {
        var ops = _backend.CreateExchange(_cfg);
        var host = _cfg.Selection.ExchangeHostname;
        var targets = _cfg.Exchange.Servers
            .Where(s => fqdns.Count == 0 || fqdns.Contains(s.Fqdn, StringComparer.OrdinalIgnoreCase))
            .ToList();
        var results = new List<ServerTestDto>();
        foreach (var s in targets)
        {
            ct.ThrowIfCancellationRequested();
            var r = ops.TestConnection(s, string.IsNullOrWhiteSpace(host) ? s.Fqdn : host, ct);
            s.LastStatus = (r.Ok ? "OK – " : "FEHLER – ") + r.Summary;
            results.Add(new ServerTestDto(s.Fqdn, r.Ok, r.Summary, r.Steps.ToList()));
        }
        return results;
    }

    // ───────────────────────── Läufe ─────────────────────────

    private PipeResponse StartRun(bool dryRun, string client)
    {
        if (!_op.Wait(0)) return PipeResponse.Fail($"Der Dienst ist beschäftigt: {_currentOp ?? "Lauf"}.");
        _runTask = Task.Run(() =>
        {
            try { ExecuteRun(dryRun, $"manuell von {client}", null, CancellationToken.None); }
            catch (Exception ex) { Log.Error("Lauf fehlgeschlagen", ex); }
            finally { _op.Release(); }
        });
        return PipeResponse.Success();
    }

    /// <summary>Führt einen Lauf aus. Aufrufer hält die Operationssperre.</summary>
    private void ExecuteRun(bool dryRun, string trigger, ServiceTickAction? scheduled, CancellationToken outer)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
        _opCts = cts;
        _currentOp = dryRun ? "Dry-Run" : "Zertifikatsaustausch";
        _opStarted = _clock();
        var live = new RunResult { DryRun = dryRun, StartedAt = _clock() };
        _liveRun = live;
        _state.Update(s => { s.Running = true; s.RunStarted = live.StartedAt; });

        RunResult result;
        try
        {
            var preWarnings = RefreshServersBeforeRun();
            var unknown = new List<UnknownHostKey>();
            var engine = new DeployEngine(_cfg, Source(unknown), _backend.CreateExchange(_cfg), _backend.TlsProbe, EngineDelay);
            engine.ServerUpdated += sr => { lock (live) live.Servers.Add(sr); };
            Log.Info($"Lauf ausgelöst: {trigger}");
            result = _backend.Guard(() => engine.Run(dryRun, cts.Token), dryRun);
            result.Warnings.InsertRange(0, preWarnings);
            foreach (var u in unknown)
                result.Warnings.Add($"Unbekannter SSH-Hostkey für {u.Host} ({u.Fingerprint}) – in der GUI unter OPNsense bestätigen.");
        }
        catch (Exception ex)
        {
            result = new RunResult { DryRun = dryRun, StartedAt = live.StartedAt, FatalError = Log.Describe(ex) };
            Log.Error("Lauf fehlgeschlagen", ex);
        }
        finally
        {
            _liveRun = null;
            _currentOp = null;
            _opStarted = null;
            _opCts = null;
        }

        var now = _clock();
        _state.Update(s =>
        {
            s.Running = false;
            s.RunStarted = null;
            s.LastRun = now;
            s.LastResult = result.Summary;
            s.LastSuccess = result.Success;
            s.LastTrigger = trigger;
            s.LastRunDetails = result;
            if (scheduled is { } a && a != ServiceTickAction.None)
            {
                ServiceScheduler.AfterScheduledRun(s, a, result.Success, now);
                if (s.RetryAt is { } r) Log.Warn($"Geplanter Lauf nicht erfolgreich – nächster Versuch um {r:HH:mm}.");
            }
        });
        Persist();
    }

    private StatusDto BuildStatus()
    {
        var st = _state.Load();
        AutoModeSettings auto;
        lock (_cfgLock) auto = _cfg.Auto;
        ServiceScheduler.Decide(_clock(), auto, st, out var next);
        st.NextRun = next;
        var lastDetails = st.LastRunDetails;
        st.LastRunDetails = null; // nicht doppelt übertragen

        RunResult? live = null;
        var lr = _liveRun;
        if (lr != null)
        {
            live = new RunResult { DryRun = lr.DryRun, StartedAt = lr.StartedAt };
            lock (lr) live.Servers.AddRange(lr.Servers);
        }

        return new StatusDto
        {
            Version = _backend.Version,
            Account = _backend.Account,
            MachineName = _backend.MachineName,
            ServiceStarted = _started,
            CurrentOperation = _currentOp,
            OperationStarted = _opStarted,
            RunInProgress = lr != null,
            CurrentRun = live,
            LastRunResult = lastDetails,
            State = st,
            Auto = auto
        };
    }
}
