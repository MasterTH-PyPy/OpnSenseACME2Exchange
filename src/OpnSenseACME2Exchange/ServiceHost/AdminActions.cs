using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.ServiceHost;

public enum AdminAction { Install, Update, Uninstall, Start, Stop, Access }

public sealed class AdminRequest
{
    public AdminAction Action { get; set; }
    /// <summary>DOMÄNE\konto, DOMÄNE\gmsa$ oder LocalSystem.</summary>
    public string? Account { get; set; }
    public string? Password { get; set; }
    public string? GuiUserSid { get; set; }
    /// <summary>Zusätzliche Benutzer/Gruppen für den GUI-Zugriff (DOMÄNE\name).</summary>
    public List<string> ExtraPrincipals { get; set; } = new();
    public string? SourceExe { get; set; }
}

public sealed class AdminResult
{
    public bool Ok { get; set; }
    public string Message { get; set; } = "";
    public List<string> Steps { get; set; } = new();
}

/// <summary>Installierter Zustand des Dienstes (lesbar ohne Adminrechte).</summary>
public sealed record InstalledServiceInfo(bool Installed, ServiceControllerStatus? Status, string? Account, string? ImagePath);

/// <summary>
/// Aktionen, die Administratorrechte brauchen. Die GUI startet dafür sich selbst erhöht mit "--admin &lt;Datei&gt;".
/// Die Anfrage (mit Dienstkonto-Passwort) liegt DPAPI-geschützt im TEMP-Ordner des Benutzers und wird sofort gelöscht.
/// </summary>
public static class AdminActions
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("OpnSenseACME2Exchange/AdminRequest/v1");

    // ───────────────────────── GUI-Seite ─────────────────────────

    public static InstalledServiceInfo QueryInstalled()
    {
        try
        {
            using var sc = new ServiceController(AppPaths.ServiceName);
            var status = sc.Status; // wirft, wenn nicht installiert
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AppPaths.ServiceName}");
            return new InstalledServiceInfo(true, status, key?.GetValue("ObjectName") as string, key?.GetValue("ImagePath") as string);
        }
        catch (InvalidOperationException)
        {
            return new InstalledServiceInfo(false, null, null, null);
        }
    }

    /// <summary>Startet die EXE erhöht (UAC) und wartet auf das Ergebnis.</summary>
    public static async Task<AdminResult> RunElevatedAsync(AdminRequest request)
    {
        request.SourceExe ??= Environment.ProcessPath;
        request.GuiUserSid ??= WindowsIdentity.GetCurrent().User?.Value;

        var file = Path.Combine(Path.GetTempPath(), $"o2e-admin-{Guid.NewGuid():N}.req");
        var resultFile = file + ".result";
        var json = JsonSerializer.SerializeToUtf8Bytes(request);
        // LocalMachine-Scope: auch ein anderer Admin (UAC mit fremden Anmeldedaten) kann lesen; die Datei-ACL des TEMP-Ordners
        // beschränkt den Zugriff auf diesen Benutzer, SYSTEM und Administratoren.
        File.WriteAllBytes(file, ProtectedData.Protect(json, Entropy, DataProtectionScope.LocalMachine));
        CryptographicOperations.ZeroMemory(json);

        try
        {
            var psi = new ProcessStartInfo(Environment.ProcessPath!, $"--admin \"{file}\"")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process? p;
            try { p = Process.Start(psi); }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return new AdminResult { Ok = false, Message = "Abgebrochen (keine Administratorrechte erteilt)." };
            }
            if (p == null) return new AdminResult { Ok = false, Message = "Erhöhter Prozess konnte nicht gestartet werden." };
            using (p) await p.WaitForExitAsync();

            if (!File.Exists(resultFile))
                return new AdminResult { Ok = false, Message = $"Kein Ergebnis vom erhöhten Prozess (Exit {p.ExitCode})." };
            return JsonSerializer.Deserialize<AdminResult>(await File.ReadAllTextAsync(resultFile))
                   ?? new AdminResult { Ok = false, Message = "Ergebnis unlesbar." };
        }
        finally
        {
            try { File.Delete(file); } catch { /* schon weg */ }
            try { File.Delete(resultFile); } catch { /* egal */ }
        }
    }

    // ───────────────────────── Erhöhte Seite ─────────────────────────

    public static int Execute(string requestFile)
    {
        var result = new AdminResult();
        try
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(requestFile), Entropy, DataProtectionScope.LocalMachine);
            File.Delete(requestFile);
            var req = JsonSerializer.Deserialize<AdminRequest>(bytes) ?? throw new InvalidDataException("Leere Anfrage.");
            CryptographicOperations.ZeroMemory(bytes);

            switch (req.Action)
            {
                case AdminAction.Install: Install(req, result); break;
                case AdminAction.Update: Update(req, result); break;
                case AdminAction.Uninstall: Uninstall(result); break;
                case AdminAction.Start: StartService(result); break;
                case AdminAction.Stop: StopService(result); break;
                case AdminAction.Access: UpdateAccess(req, result, replaceExtras: true); break;
            }
            result.Ok = true;
            if (result.Message.Length == 0) result.Message = "Erledigt.";
        }
        catch (Exception ex)
        {
            result.Ok = false;
            result.Message = ex.InnerException != null ? $"{ex.Message} ({ex.InnerException.Message})" : ex.Message;
        }

        try { File.WriteAllText(requestFile + ".result", JsonSerializer.Serialize(result)); } catch { /* GUI meldet fehlendes Ergebnis */ }
        return result.Ok ? 0 : 1;
    }

    private static (string? Account, string? Password, SecurityIdentifier? Sid) ResolveAccount(AdminRequest req)
    {
        var account = (req.Account ?? "").Trim();
        if (account.Length == 0 || account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) || account.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase))
            return (null, null, null);

        if (!account.Contains('\\') && !account.Contains('@')) account = Environment.UserDomainName + "\\" + account;
        SecurityIdentifier sid;
        try { sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier)); }
        catch (IdentityNotMappedException) { throw new InvalidOperationException($"Konto '{account}' wurde nicht gefunden."); }

        bool gmsa = account.EndsWith('$');
        var password = gmsa ? null : req.Password;
        if (!gmsa && string.IsNullOrEmpty(password)) throw new InvalidOperationException("Für ein normales Dienstkonto wird das Passwort benötigt (bei gMSA leer lassen).");
        return (account, password, sid);
    }

    private static void Install(AdminRequest req, AdminResult r)
    {
        var (account, password, sid) = ResolveAccount(req);
        r.Steps.Add(account == null ? "Konto: LocalSystem (Achtung: Exchange-Zugriff dann als Computerkonto!)" : $"Konto: {account} ({sid})");

        StopIfRunning(r);
        CopyExecutable(req.SourceExe, r);
        MigrateOldConfig(req.SourceExe, r);

        DataDirectorySecurity.Apply(AppPaths.DataDirectory, sid);
        r.Steps.Add($"Datenverzeichnis {AppPaths.DataDirectory} geschützt (SYSTEM, Administratoren{(sid != null ? ", Dienstkonto" : "")}).");

        UpdateAccess(req, r, replaceExtras: false);

        if (sid != null)
        {
            NativeServiceApi.GrantServiceLogonRight(sid);
            r.Steps.Add("Recht 'Als Dienst anmelden' erteilt.");
        }

        var created = NativeServiceApi.CreateOrUpdate(AppPaths.ServiceName, AppPaths.ServiceDisplayName,
            "Holt das ACME-Zertifikat aus dem HAProxy der OPNsense und verteilt es auf die Exchange-Server. Bedienung über die GUI (OpnSenseACME2Exchange.exe).",
            $"\"{AppPaths.InstalledExe}\" --service", account, password);
        r.Steps.Add(created ? "Dienst angelegt (automatisch, verzögert; Neustart bei Fehlern)." : "Vorhandener Dienst aktualisiert.");

        StartService(r);
        r.Message = "Dienst installiert und gestartet.";
    }

    private static void Update(AdminRequest req, AdminResult r)
    {
        StopIfRunning(r);
        CopyExecutable(req.SourceExe, r);
        StartService(r);
        r.Message = "Dienst aktualisiert.";
    }

    private static void Uninstall(AdminResult r)
    {
        StopIfRunning(r);
        r.Steps.Add(NativeServiceApi.Delete(AppPaths.ServiceName) ? "Dienst entfernt." : "Dienst war nicht installiert.");
        r.Message = $"Dienst entfernt. Konfiguration und Logs bleiben in {AppPaths.DataDirectory}.";
    }

    private static void UpdateAccess(AdminRequest req, AdminResult r, bool replaceExtras)
    {
        var list = replaceExtras ? new AccessList() : AccessList.Load();
        if (!string.IsNullOrWhiteSpace(req.GuiUserSid)) list.Add(new SecurityIdentifier(req.GuiUserSid));
        foreach (var p in req.ExtraPrincipals.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            try { list.Add((SecurityIdentifier)new NTAccount(p.Trim()).Translate(typeof(SecurityIdentifier))); }
            catch (IdentityNotMappedException) { throw new InvalidOperationException($"Benutzer/Gruppe '{p}' wurde nicht gefunden."); }
        }
        list.Save();
        DataDirectorySecurity.EnsureProtected(AppPaths.DataDirectory);
        r.Steps.Add("GUI-Zugriff: " + string.Join(", ", list.Entries.Select(e => e.Name)) + " (+ Administratoren erhöht).");
        if (replaceExtras) r.Message = "Zugriff aktualisiert – gilt ab der nächsten Verbindung.";
    }

    private static void CopyExecutable(string? source, AdminResult r)
    {
        if (string.IsNullOrWhiteSpace(source) || !File.Exists(source)) throw new FileNotFoundException("Programmdatei nicht gefunden.", source);
        Directory.CreateDirectory(AppPaths.InstallDirectory);
        if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(AppPaths.InstalledExe), StringComparison.OrdinalIgnoreCase))
        {
            r.Steps.Add($"Programm liegt bereits in {AppPaths.InstallDirectory}.");
            return;
        }
        // Kurz warten, falls der gerade gestoppte Dienst die Datei noch hält
        for (int i = 0; ; i++)
        {
            try { File.Copy(source, AppPaths.InstalledExe, overwrite: true); break; }
            catch (IOException) when (i < 10) { Thread.Sleep(1000); }
        }
        r.Steps.Add($"Programm nach {AppPaths.InstalledExe} kopiert.");
    }

    /// <summary>Übernimmt config.dat/key.bin aus Version 1.0.x (lagen neben der EXE).</summary>
    private static void MigrateOldConfig(string? sourceExe, AdminResult r)
    {
        if (File.Exists(AppPaths.ConfigFile) || string.IsNullOrWhiteSpace(sourceExe)) return;
        var dir = Path.GetDirectoryName(sourceExe)!;
        var oldCfg = Path.Combine(dir, "config.dat");
        var oldKey = Path.Combine(dir, "key.bin");
        if (!File.Exists(oldCfg) || !File.Exists(oldKey)) return;
        Directory.CreateDirectory(AppPaths.DataDirectory);
        File.Copy(oldCfg, AppPaths.ConfigFile, false);
        File.Copy(oldKey, AppPaths.KeyFile, false);
        r.Steps.Add($"Bestehende Konfiguration aus {dir} übernommen.");
    }

    private static void StopIfRunning(AdminResult r)
    {
        try
        {
            using var sc = new ServiceController(AppPaths.ServiceName);
            if (sc.Status is ServiceControllerStatus.Stopped) return;
            if (sc.Status != ServiceControllerStatus.StopPending) sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
            r.Steps.Add("Dienst gestoppt.");
        }
        catch (InvalidOperationException) { /* nicht installiert */ }
    }

    private static void StopService(AdminResult r)
    {
        StopIfRunning(r);
        r.Message = "Dienst gestoppt.";
    }

    private static void StartService(AdminResult r)
    {
        using var sc = new ServiceController(AppPaths.ServiceName);
        if (sc.Status != ServiceControllerStatus.Running)
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
        }
        r.Steps.Add("Dienst läuft.");
        if (r.Message.Length == 0) r.Message = "Dienst gestartet.";
    }
}
