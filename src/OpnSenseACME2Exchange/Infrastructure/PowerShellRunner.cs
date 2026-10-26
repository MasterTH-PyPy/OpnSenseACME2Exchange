using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OpnSenseACME2Exchange.Infrastructure;

public sealed class PowerShellException : Exception
{
    public PowerShellException(string message, bool isConnectError) : base(message) => IsConnectError = isConnectError;
    /// <summary>Fehler beim Aufbau der Remote-Session (→ andere URI probieren).</summary>
    public bool IsConnectError { get; }
}

/// <summary>
/// Führt Skripte in Windows PowerShell 5.1 aus (Exchange-Remoting braucht die klassische PowerShell).
/// Skript und Eingabedaten (inkl. Passwörter/PFX) gehen Base64-kodiert über stdin –
/// nichts davon landet auf der Kommandozeile oder auf der Platte.
/// </summary>
public static class PowerShellRunner
{
    private const string ResultMarker = "##RESULT##";
    private const string ErrorMarker = "##ERROR##";

    // Kleiner Bootstrap: liest {Script, Input} von stdin und führt das Skript mit $in aus.
    private const string Bootstrap = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $raw = [Console]::In.ReadToEnd()
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw.Trim()))
        $payload = $json | ConvertFrom-Json
        $in = $payload.Input
        $sb = [scriptblock]::Create($payload.Script)
        try {
            $res = & $sb $in
            Write-Output ('##RESULT##' + (ConvertTo-Json -InputObject $res -Depth 6 -Compress))
            exit 0
        } catch {
            $m = $_.Exception.Message
            if ($_.FullyQualifiedErrorId) { $m = $m + ' [' + $_.FullyQualifiedErrorId + ']' }
            Write-Output ('##ERROR##' + $m)
            exit 1
        }
        """;

    private static string PowerShellExe =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    public static JsonNode? Run(string script, object input, TimeSpan timeout, CancellationToken ct)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Bootstrap));
        var psi = new ProcessStartInfo(PowerShellExe)
        {
            ArgumentList = { "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded },
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data != null) lock (stdout) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (stderr) stderr.AppendLine(e.Data); };

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        var payload = JsonSerializer.Serialize(new { Script = script, Input = input });
        var bytes = Encoding.UTF8.GetBytes(payload);
        proc.StandardInput.Write(Convert.ToBase64String(bytes));
        Array.Clear(bytes);
        proc.StandardInput.Close();

        var deadline = DateTime.UtcNow + timeout;
        while (!proc.WaitForExit(250))
        {
            if (ct.IsCancellationRequested || DateTime.UtcNow > deadline)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* schon weg */ }
                ct.ThrowIfCancellationRequested();
                throw new TimeoutException($"PowerShell-Aufruf nach {timeout.TotalSeconds:0}s abgebrochen.");
            }
        }
        proc.WaitForExit(); // Restliche Ausgabe abholen

        string output;
        lock (stdout) output = stdout.ToString();
        foreach (var line in output.Split('\n'))
        {
            var l = line.TrimEnd('\r');
            if (l.StartsWith(ResultMarker, StringComparison.Ordinal))
            {
                var json = l[ResultMarker.Length..];
                return string.IsNullOrWhiteSpace(json) || json == "null" ? null : JsonNode.Parse(json);
            }
            if (l.StartsWith(ErrorMarker, StringComparison.Ordinal))
            {
                var msg = l[ErrorMarker.Length..];
                var isConnect = msg.StartsWith("CONNECT:", StringComparison.Ordinal);
                throw new PowerShellException(isConnect ? msg[8..].Trim() : msg, isConnect);
            }
        }

        string err;
        lock (stderr) err = stderr.ToString().Trim();
        throw new PowerShellException(
            $"PowerShell lieferte kein Ergebnis (Exit {proc.ExitCode}). {(err.Length > 600 ? err[..600] : err)}", false);
    }
}
