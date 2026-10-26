using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.OpnSense;
using Renci.SshNet;

namespace OpnSenseACME2Exchange.Infrastructure;

public sealed record SshCredentials(string Username, SshAuthMode Mode, string? Password, string? PrivateKeyPath, string? Passphrase);

/// <summary>
/// SSH.NET-Implementierung mit strikter Hostkey-Prüfung:
/// bekannter Key muss passen, unbekannter Key nur nach Bestätigung (GUI) – im Auto-Modus wird abgelehnt.
/// </summary>
public sealed class SshNetSessionFactory : ISshSessionFactory
{
    private readonly SshCredentials _cred;
    private readonly int _timeoutSeconds;
    private readonly Func<OpnSenseNode, string, bool>? _confirmUnknownHostKey;

    public SshNetSessionFactory(SshCredentials cred, int timeoutSeconds, Func<OpnSenseNode, string, bool>? confirmUnknownHostKey)
    {
        _cred = cred;
        _timeoutSeconds = Math.Max(5, timeoutSeconds);
        _confirmUnknownHostKey = confirmUnknownHostKey;
    }

    /// <summary>Wird ausgelöst, wenn ein neuer Hostkey akzeptiert wurde (Konfiguration speichern!).</summary>
    public event Action<OpnSenseNode>? HostKeyLearned;

    public ISshSession Open(OpnSenseNode node)
    {
        var methods = new List<AuthenticationMethod>();
        if (_cred.Mode == SshAuthMode.PrivateKey)
        {
            if (string.IsNullOrWhiteSpace(_cred.PrivateKeyPath) || !File.Exists(_cred.PrivateKeyPath))
                throw new FileNotFoundException("SSH-Private-Key nicht gefunden.", _cred.PrivateKeyPath);
            var keyFile = string.IsNullOrEmpty(_cred.Passphrase)
                ? new PrivateKeyFile(_cred.PrivateKeyPath)
                : new PrivateKeyFile(_cred.PrivateKeyPath, _cred.Passphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(_cred.Username, keyFile));
        }
        else
        {
            var pw = _cred.Password ?? "";
            methods.Add(new PasswordAuthenticationMethod(_cred.Username, pw));
            var kbd = new KeyboardInteractiveAuthenticationMethod(_cred.Username);
            kbd.AuthenticationPrompt += (_, e) =>
            {
                foreach (var p in e.Prompts)
                    if (p.Request.Contains("assword", StringComparison.OrdinalIgnoreCase)) p.Response = pw;
            };
            methods.Add(kbd);
        }

        var info = new ConnectionInfo(node.Host, node.Port <= 0 ? 22 : node.Port, _cred.Username, methods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(_timeoutSeconds)
        };

        var client = new SshClient(info);
        string? rejectReason = null;
        client.HostKeyReceived += (_, e) =>
        {
            var fp = "SHA256:" + e.FingerPrintSHA256;
            if (!string.IsNullOrWhiteSpace(node.HostKeyFingerprint))
            {
                e.CanTrust = string.Equals(node.HostKeyFingerprint, fp, StringComparison.Ordinal);
                if (!e.CanTrust)
                    rejectReason = $"HOSTKEY GEÄNDERT für {node.Host}! Erwartet {node.HostKeyFingerprint}, erhalten {fp}. " +
                                   "Wenn die Firewall neu installiert wurde: Fingerprint im Reiter OPNsense zurücksetzen.";
                return;
            }

            bool accept = _confirmUnknownHostKey?.Invoke(node, fp) ?? false;
            e.CanTrust = accept;
            if (accept)
            {
                node.HostKeyFingerprint = fp;
                Log.Info($"SSH-Hostkey für {node.Host} gespeichert: {fp}");
                HostKeyLearned?.Invoke(node);
            }
            else rejectReason = $"Unbekannter SSH-Hostkey für {node.Host} ({fp}) – im Reiter OPNsense per 'Verbindung testen' bestätigen.";
        };

        try
        {
            client.Connect();
        }
        catch (Exception ex)
        {
            client.Dispose();
            if (rejectReason != null) throw new InvalidOperationException(rejectReason, ex);
            throw;
        }
        return new Session(client);
    }

    private sealed class Session(SshClient client) : ISshSession
    {
        public SshResult Run(string command, TimeSpan timeout)
        {
            using var cmd = client.CreateCommand(command);
            cmd.CommandTimeout = timeout;
            var stdout = cmd.Execute();
            // ExitStatus ist je nach SSH.NET-Version int oder int?
            object? status = cmd.ExitStatus;
            int exit = status is null ? -1 : Convert.ToInt32(status);
            return new SshResult(exit, stdout ?? "", cmd.Error ?? "");
        }

        public void Dispose()
        {
            try { if (client.IsConnected) client.Disconnect(); } catch { /* egal */ }
            client.Dispose();
        }
    }
}
