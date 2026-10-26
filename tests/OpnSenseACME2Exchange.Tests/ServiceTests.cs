using System.IO.Pipes;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Ipc;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Net;
using OpnSenseACME2Exchange.Core.OpnSense;
using OpnSenseACME2Exchange.Core.Service;

namespace OpnSenseACME2Exchange.Tests;

/// <summary>Simuliert SSH.NET-Hostkey-Prüfung: unbekannter Key nur nach Bestätigung, abweichender Key = Abbruch.</summary>
public sealed class HostKeyCheckingFactory(FakeOpnSense inner, Func<OpnSenseNode, string, bool> confirm) : ISshSessionFactory
{
    public static string KeyOf(string host) => "SHA256:FAKE-" + host;

    public ISshSession Open(OpnSenseNode node)
    {
        var fp = KeyOf(node.Host);
        if (string.IsNullOrEmpty(node.HostKeyFingerprint))
        {
            if (!confirm(node, fp)) throw new InvalidOperationException($"Unbekannter SSH-Hostkey für {node.Host}");
            node.HostKeyFingerprint = fp;
        }
        else if (node.HostKeyFingerprint != fp) throw new InvalidOperationException("HOSTKEY GEÄNDERT");
        return inner.Open(node);
    }
}

public sealed class FakeBackend(FakeOpnSense opn, FakeExchange ex, string dir) : IServiceBackend
{
    public string Version => "9.9.9";
    public string Account => @"CORP\svc-acme$";
    public string MachineName => "MGMT01";
    public string DataDirectory => dir;
    public string LogDirectory => Path.Combine(dir, "Logs");
    public ITlsProbe TlsProbe => ex;
    public int GuardCalls;
    public List<ExchangeServerDiscovery> Discovered { get; } = new();

    public ISshSessionFactory CreateSshFactory(AppConfig cfg, Func<OpnSenseNode, string, bool> confirm) => new HostKeyCheckingFactory(opn, confirm);
    public IExchangeOperations CreateExchange(AppConfig cfg) => ex;
    public List<ExchangeServerDiscovery> DiscoverExchangeServers(AppConfig cfg) => Discovered.ToList();
    public RunResult Guard(Func<RunResult> run, bool dryRun) { GuardCalls++; return run(); }
    public void ApplyLogging(AppConfig cfg) { }
}

public static class ServiceTests
{
    public static void Register(Action<string, Action> test,
        Func<(AppConfig Cfg, FakeOpnSense Opn, FakeExchange Ex, string NewThumb, string OldThumb)> scenario)
    {
        (ServiceCore Core, FakeBackend Backend, ConfigStore Store, StateStore State, FakeExchange Ex, string NewThumb, string Dir)
            Setup(Action<AppConfig>? tweak = null, Func<DateTime>? clock = null)
        {
            var (cfg, opn, ex, newThumb, _) = scenario();
            tweak?.Invoke(cfg);
            var dir = Path.Combine(Path.GetTempPath(), "o2e-svc-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var store = new ConfigStore(Path.Combine(dir, "config.dat"), new ReverseProtector());
            store.Save(cfg);
            var state = new StateStore(Path.Combine(dir, "state.json"));
            var backend = new FakeBackend(opn, ex, dir);
            var core = new ServiceCore(store, state, backend, clock) { EngineDelay = (_, _) => { } };
            core.Start();
            return (core, backend, store, state, ex, newThumb, dir);
        }

        PipeResponse Call(ServiceCore core, string cmd, object? payload = null) =>
            core.HandleAsync(new PipeRequest { Command = cmd, Payload = payload == null ? null : PipeProtocol.ToElement(payload) },
                @"CORP\admin", CancellationToken.None).GetAwaiter().GetResult();

        T Payload<T>(PipeResponse r) => PipeProtocol.FromElement<T>(r.Payload)!;

        void TrustAll(ServiceCore core)
        {
            foreach (var host in new[] { "fw1", "fw2" })
                Assert.True(Call(core, Commands.TrustHostKey, new TrustHostKeyRequest(host, HostKeyCheckingFactory.KeyOf(host))).Ok, "Trust " + host);
        }

        test("Dienst: Geheimnisse verlassen den Dienst nie, leer = unverändert", () =>
        {
            var (core, _, store, _, _, _, _) = Setup();
            var dto = Payload<ConfigDto>(Call(core, Commands.GetConfig));
            Assert.False(dto.HasSshPassword, "noch kein Passwort");

            var save = new SaveConfigRequest { Config = dto.Config, SshPassword = "geheim1", ExchangePassword = "geheim2" };
            Assert.True(Call(core, Commands.SaveConfig, save).Ok, "speichern");
            var raw = Call(core, Commands.GetConfig);
            var dto2 = Payload<ConfigDto>(raw);
            Assert.True(dto2.HasSshPassword && dto2.HasExchangePassword, "Flags gesetzt");
            Assert.True(dto2.Config.OpnSense.PasswordProtected == null && dto2.Config.Exchange.PasswordProtected == null, "nichts übertragen");
            Assert.False(raw.Payload!.Value.GetRawText().Contains("geheim"), "kein Klartext in der Antwort");

            dto2.Config.Selection.ExchangeHostname = "mail.example.de";
            Assert.True(Call(core, Commands.SaveConfig, new SaveConfigRequest { Config = dto2.Config }).Ok, "speichern ohne Passwort");
            Assert.Equal("geheim1", store.Reveal(store.Load().OpnSense.PasswordProtected), "Passwort behalten");
            Assert.Equal(@"CORP\svc-acme$", dto2.ServiceAccount, "Dienstkonto gemeldet");
        });

        test("Dienst: GUI kann Hostkeys nicht per SaveConfig unterschieben", () =>
        {
            var (core, _, store, _, _, _, _) = Setup();
            var dto = Payload<ConfigDto>(Call(core, Commands.GetConfig));
            dto.Config.OpnSense.Nodes[0].HostKeyFingerprint = "SHA256:ANGREIFER";
            Call(core, Commands.SaveConfig, new SaveConfigRequest { Config = dto.Config });
            Assert.True(store.Load().OpnSense.Nodes[0].HostKeyFingerprint == null, "Fingerprint ignoriert");
        });

        test("Dienst: unbekannter Hostkey → Rückfrage an GUI → bestätigen → OK", () =>
        {
            var (core, _, _, _, _, _, _) = Setup();
            var r1 = Call(core, Commands.TestNodes);
            Assert.True(r1.Ok, "Antwort");
            Assert.Equal(2, r1.UnknownHostKeys.Count, "zwei unbekannte Keys");
            Assert.True(Payload<List<NodeStatusDto>>(r1).All(n => !n.Reachable), "ohne Bestätigung keine Verbindung");

            TrustAll(core);
            var r2 = Call(core, Commands.TestNodes);
            var nodes = Payload<List<NodeStatusDto>>(r2);
            Assert.Equal(0, r2.UnknownHostKeys.Count, "keine Rückfrage mehr");
            Assert.True(nodes.All(n => n.Reachable), "erreichbar");
            Assert.True(nodes.Any(n => n.Carp == CarpState.Master), "CARP erkannt");
            Assert.False(Call(core, Commands.TrustHostKey, new TrustHostKeyRequest("fw1", "SHA256:ANDERER")).Ok, "Überschreiben verweigert");
            Assert.True(Call(core, Commands.ResetHostKey, "fw1").Ok, "Reset");
            Assert.Equal(1, Call(core, Commands.TestNodes).UnknownHostKeys.Count, "nach Reset wieder Rückfrage");
        });

        test("Dienst: HAProxy einlesen + Zertifikat ermitteln", () =>
        {
            var (core, _, _, _, _, newThumb, _) = Setup();
            TrustAll(core);
            var hp = Payload<HaproxyReadResult>(Call(core, Commands.ReadHaproxy));
            Assert.True(hp.Node.StartsWith("FW2"), "vom Master");
            var fe = hp.Sections.Single(s => s.Key == "frontend 1_HTTPS_frontend");
            Assert.True(fe.TerminatesTls && fe.Hostnames.Contains("owa.example.de") && fe.Hostnames.Contains("mail.example.de"),
                "Hostnamen inkl. Map-Datei");

            var res = Payload<ResolveResultDto>(Call(core, Commands.ResolveCertificate));
            Assert.Equal(newThumb, res.Info!.Thumbprint, "richtiges Zertifikat");
            Assert.Equal(0, res.ValidationErrors.Count, "gültig");
        });

        test("Dienst: AD-Discovery wird zusammengeführt und gespeichert", () =>
        {
            var (core, backend, store, _, _, _, _) = Setup();
            backend.Discovered.Add(new ExchangeServerDiscovery("EXCH1", "exch1.corp.local", "Version 15.2", "DAG01", "HQ", false));
            backend.Discovered.Add(new ExchangeServerDiscovery("EXCH3", "exch3.corp.local", "Version 15.2", "DAG01", "HQ", false));
            backend.Discovered.Add(new ExchangeServerDiscovery("EDGE1", "edge1.dmz.local", "Version 15.2", null, null, true));
            var d = Payload<DiscoveryResultDto>(Call(core, Commands.DiscoverServers));
            Assert.Equal(2, d.Added, "zwei neu");
            var servers = store.Load().Exchange.Servers;
            Assert.Equal("DAG01", servers.Single(s => s.Name == "EXCH1").Dag, "DAG ergänzt");
            Assert.False(servers.Single(s => s.Name == "EDGE1").Enabled, "Edge deaktiviert");
            Assert.True(servers.Single(s => s.Name == "EXCH2").LastStatus!.Contains("nicht (mehr)"), "verschwundener Server markiert");
        });

        test("Dienst: Lauf über GUI, Live-Status, Sperre gegen Doppelstart", () =>
        {
            var (core, backend, _, state, ex, newThumb, _) = Setup();
            TrustAll(core);
            Assert.True(Call(core, Commands.StartRun, new StartRunRequest(false)).Ok, "gestartet");
            var second = Call(core, Commands.StartRun, new StartRunRequest(false));
            core.CurrentRunTask!.Wait(TimeSpan.FromSeconds(30));
            var st = Payload<StatusDto>(Call(core, Commands.GetStatus));
            Assert.False(st.RunInProgress, "fertig");
            Assert.True(st.LastRunResult!.Success, "Erfolg: " + st.LastRunResult.Summary);
            Assert.Equal(2, st.LastRunResult.Servers.Count, "Server-Ergebnisse übertragen");
            Assert.Equal(newThumb, st.LastRunResult.Certificate!.Thumbprint, "Zertifikat im Ergebnis");
            Assert.True(st.State.LastTrigger!.Contains(@"CORP\admin"), "Auslöser protokolliert");
            Assert.Equal(1, backend.GuardCalls, "prozessübergreifende Sperre benutzt");
            Assert.True(second.Ok || second.Error!.Contains("beschäftigt"), "zweiter Start abgewiesen oder nach Ende");
            Assert.True(ex.Stores["exch1.corp.local"].Any(c => c.Thumbprint == newThumb && c.HasService("IIS")), "getauscht");
            Assert.True(state.Load().LastRunDetails != null, "Ergebnis überlebt Neustart (state.json)");
        });

        test("Dienst: während eines Laufs kein Speichern", () =>
        {
            var (core, _, _, _, ex, _, _) = Setup();
            TrustAll(core);
            var gate = new ManualResetEventSlim(false);
            ex.BeforeGet = () => gate.Wait(TimeSpan.FromSeconds(10));
            Call(core, Commands.StartRun, new StartRunRequest(true));
            Thread.Sleep(200);
            var st = Payload<StatusDto>(Call(core, Commands.GetStatus));
            var dto = Payload<ConfigDto>(Call(core, Commands.GetConfig));
            var save = Call(core, Commands.SaveConfig, new SaveConfigRequest { Config = dto.Config });
            gate.Set();
            core.CurrentRunTask!.Wait(TimeSpan.FromSeconds(30));
            ex.BeforeGet = null;
            Assert.True(st.RunInProgress && st.CurrentOperation == "Dry-Run", "Live-Status während des Laufs");
            Assert.False(save.Ok, "Speichern abgewiesen");
        });

        test("Dienst: geplanter Lauf, Fehlschlag → Wiederholung nach 1 h, danach Erfolg", () =>
        {
            var now = new DateTime(2026, 10, 27, 3, 31, 0);
            var (core, _, _, state, ex, _, _) = Setup(c => { c.Auto.Enabled = true; c.Auto.Time = "03:30"; }, () => now);
            TrustAll(core);
            state.Update(s => s.LastAutoRun = now.AddDays(-1));
            ex.Broken.Add("exch1.corp.local");

            core.SchedulerTick(CancellationToken.None);
            var s1 = state.Load();
            Assert.Equal(now, s1.LastAutoRun, "geplanter Lauf ausgeführt");
            Assert.False(s1.LastSuccess, "fehlgeschlagen");
            Assert.Equal(now.AddHours(1), s1.RetryAt, "Wiederholung geplant");

            now = now.AddMinutes(30);
            core.SchedulerTick(CancellationToken.None);
            Assert.Equal(1, state.Load().RetryCount, "noch nicht wiederholt");

            ex.Broken.Clear();
            now = now.AddMinutes(31);
            core.SchedulerTick(CancellationToken.None);
            var s3 = state.Load();
            Assert.True(s3.LastSuccess, "Wiederholung erfolgreich");
            Assert.True(s3.RetryAt == null && s3.RetryCount == 0, "Wiederholung erledigt");
            Assert.True(s3.LastTrigger!.StartsWith("Wiederholung"), "Auslöser");

            now = now.AddHours(2);
            core.SchedulerTick(CancellationToken.None);
            Assert.Equal(s3.LastRun, state.Load().LastRun, "kein weiterer Lauf am selben Tag");
        });

        test("Dienst: max. 3 Wiederholungen", () =>
        {
            var st = new ServiceState();
            var t = new DateTime(2026, 10, 27, 3, 30, 0);
            ServiceScheduler.AfterScheduledRun(st, ServiceTickAction.ScheduledRun, false, t);
            for (int i = 0; i < 3; i++) ServiceScheduler.AfterScheduledRun(st, ServiceTickAction.Retry, false, t.AddHours(i + 1));
            Assert.True(st.RetryAt == null, "nach 3 Wiederholungen Schluss");
        });

        test("Pipe: echte Named Pipe, Anfrage → Dienst → Antwort", () =>
        {
            var (core, _, _, _, _, _, _) = Setup();
            var name = "o2e-test-" + Guid.NewGuid().ToString("N")[..8];
            using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var serverTask = Task.Run(async () =>
            {
                await server.WaitForConnectionAsync();
                var req = await PipeProtocol.ReadAsync<PipeRequest>(server, CancellationToken.None);
                var resp = await core.HandleAsync(req, "pipe-client", CancellationToken.None);
                await PipeProtocol.WriteAsync(server, resp, CancellationToken.None);
            });
            using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            client.Connect(5000);
            PipeProtocol.WriteAsync(client, new PipeRequest { Command = Commands.GetStatus }, CancellationToken.None).GetAwaiter().GetResult();
            var resp = PipeProtocol.ReadAsync<PipeResponse>(client, CancellationToken.None).GetAwaiter().GetResult();
            serverTask.Wait(5000);
            Assert.True(resp.Ok, "Antwort OK");
            Assert.Equal("9.9.9", PipeProtocol.FromElement<StatusDto>(resp.Payload)!.Version, "Status über Pipe");
        });

        test("Pipe: Müll und Übergrößen werden abgewiesen", () =>
        {
            var ms = new MemoryStream(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F, 1, 2, 3 });
            Assert.Throws<InvalidDataException>(() => PipeProtocol.ReadAsync<PipeRequest>(ms, CancellationToken.None).GetAwaiter().GetResult(), "Länge");
            var ms2 = new MemoryStream(new byte[] { 10, 0, 0, 0, 1, 2 });
            Assert.Throws<EndOfStreamException>(() => PipeProtocol.ReadAsync<PipeRequest>(ms2, CancellationToken.None).GetAwaiter().GetResult(), "abgerissen");
        });

        test("Dienst: Logs stückweise, keine fremden Dateien", () =>
        {
            var (core, _, _, _, _, _, dir) = Setup();
            Log.Info("Testzeile für den Log-Reader");
            var list = Payload<LogListDto>(Call(core, Commands.ListLogs));
            Assert.True(list.Files.Any(f => f.Name == list.Current), "aktuelle Datei gelistet");
            var chunk = Payload<LogChunkDto>(Call(core, Commands.ReadLog, new ReadLogRequest(list.Current, 0)));
            Assert.True(chunk.Text.Contains("Testzeile für den Log-Reader"), "Inhalt");
            var again = Payload<LogChunkDto>(Call(core, Commands.ReadLog, new ReadLogRequest(list.Current, chunk.NewOffset)));
            Assert.True(again.Text.Length == 0 || !again.Text.Contains("Testzeile für den Log-Reader"), "nur Neues");
            Assert.False(Call(core, Commands.ReadLog, new ReadLogRequest("../config.dat", 0)).Ok, "Traversal blockiert");
            Assert.False(Call(core, Commands.ReadLog, new ReadLogRequest("C:\\Windows\\win.ini", 0)).Ok, "fremde Datei blockiert");
        });
    }
}
