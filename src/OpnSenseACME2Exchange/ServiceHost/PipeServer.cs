using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using OpnSenseACME2Exchange.Core.Ipc;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Service;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.ServiceHost;

/// <summary>
/// Named-Pipe-Server des Dienstes. Zugriff per ACL nur für SYSTEM, (erhöhte) Administratoren, das Dienstkonto
/// und die Einträge aus access.json. Funktioniert lokal und über das Netzwerk (\\server\pipe\…).
/// </summary>
public sealed class PipeServer
{
    private readonly ServiceCore _core;

    public PipeServer(ServiceCore core) => _core = core;

    public async Task RunAsync(CancellationToken ct)
    {
        Log.Info($"GUI-Schnittstelle bereit: \\\\{Environment.MachineName}\\pipe\\{PipeProtocol.PipeName} " +
                 $"(Zugriff: {string.Join(", ", AccessList.Load().Entries.Select(e => e.Name).DefaultIfEmpty("nur Administratoren"))}).");
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = Create();
                await pipe.WaitForConnectionAsync(ct);
                var connected = pipe;
                pipe = null;
                _ = Task.Run(() => HandleAsync(connected, ct), CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                pipe?.Dispose();
                Log.Error("Pipe-Server", ex);
                try { await Task.Delay(2000, ct); } catch (OperationCanceledException) { break; }
            }
        }
    }

    private static NamedPipeServerStream Create()
    {
        const PipeAccessRights clientRights = PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize;
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), clientRights, AccessControlType.Allow));
        var me = WindowsIdentity.GetCurrent().User;
        if (me != null) sec.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (var sid in AccessList.Load().Sids())
            sec.AddAccessRule(new PipeAccessRule(sid, clientRights, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(PipeProtocol.PipeName, PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            1 << 16, 1 << 16, sec);
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using (pipe)
        {
            string client = "?";
            try
            {
                try { client = pipe.GetImpersonationUserName(); } catch { /* Client ohne Identifikation */ }

                PipeRequest req;
                using (var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    readTimeout.CancelAfter(TimeSpan.FromSeconds(30));
                    req = await PipeProtocol.ReadAsync<PipeRequest>(pipe, readTimeout.Token);
                }
                if (req.Command is not (Commands.GetStatus or Commands.ReadLog or Commands.ListLogs or Commands.Ping))
                    Log.Debug($"Anfrage {req.Command} von {client}");

                var resp = await _core.HandleAsync(req, client, ct);
                await PipeProtocol.WriteAsync(pipe, resp, ct);
            }
            catch (OperationCanceledException) { /* Dienst stoppt oder Client zu langsam */ }
            catch (IOException) { /* Client hat aufgelegt */ }
            catch (Exception ex) { Log.Warn($"Pipe-Anfrage von {client} fehlgeschlagen: {Log.Describe(ex)}"); }
        }
    }
}
