using System.IO.Pipes;
using System.Security.Principal;
using OpnSenseACME2Exchange.Core.Ipc;

namespace OpnSenseACME2Exchange.Client;

public sealed class ServiceCallException : Exception
{
    public ServiceCallException(string message) : base(message) { }
}

/// <summary>GUI-Seite der Pipe: eine Verbindung pro Anfrage, lokal (".") oder auf einem anderen Server.</summary>
public sealed class ServiceClient
{
    public string Server { get; set; } = ".";

    public string Display => Server is "." or "" ? "diesem Rechner" : Server;

    public async Task<PipeResponse> SendAsync(string command, object? payload, CancellationToken ct, int connectTimeoutMs = 5000)
    {
        using var pipe = new NamedPipeClientStream(string.IsNullOrWhiteSpace(Server) ? "." : Server.Trim(),
            PipeProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(connectTimeoutMs, ct);
        }
        catch (TimeoutException)
        {
            throw new ServiceCallException($"Dienst auf {Display} nicht erreichbar (nicht installiert, gestoppt oder Port 445 gesperrt).");
        }
        catch (UnauthorizedAccessException)
        {
            throw new ServiceCallException($"Kein Zugriff auf den Dienst auf {Display} – Benutzer im Reiter 'Dienst' unter 'Zugriff' freigeben lassen.");
        }

        await PipeProtocol.WriteAsync(pipe, new PipeRequest
        {
            Command = command,
            Payload = payload == null ? null : PipeProtocol.ToElement(payload),
            ClientVersion = Program.Version
        }, ct);
        return await PipeProtocol.ReadAsync<PipeResponse>(pipe, ct);
    }

    /// <summary>Anfrage, die bei Fehler eine Exception wirft (ohne Hostkey-Behandlung).</summary>
    public async Task<T?> CallAsync<T>(string command, object? payload, CancellationToken ct)
    {
        var resp = await SendAsync(command, payload, ct);
        if (!resp.Ok) throw new ServiceCallException(resp.Error ?? "Unbekannter Fehler im Dienst.");
        return PipeProtocol.FromElement<T>(resp.Payload);
    }
}
