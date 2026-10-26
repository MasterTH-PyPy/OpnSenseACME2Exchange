using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace OpnSenseACME2Exchange.Infrastructure;

public static class AppPaths
{
    public const string ServiceName = "OpnSenseACME2Exchange";
    public const string ServiceDisplayName = "OpnSenseACME2Exchange – ACME-Zertifikat für Exchange";
    public const string ExeName = "OpnSenseACME2Exchange.exe";

    /// <summary>Daten des Dienstes: Konfiguration, Schlüssel, Status, Logs (nur SYSTEM, Administratoren, Dienstkonto).</summary>
    public static string DataDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OpnSenseACME2Exchange");

    public static string ConfigFile => Path.Combine(DataDirectory, "config.dat");
    public static string KeyFile => Path.Combine(DataDirectory, "key.bin");
    public static string StateFile => Path.Combine(DataDirectory, "state.json");
    public static string AccessFile => Path.Combine(DataDirectory, "access.json");
    public static string LogDirectory => Path.Combine(DataDirectory, "Logs");

    /// <summary>Hierhin installiert sich der Dienst (das Dienstkonto muss die EXE lesen können).</summary>
    public static string InstallDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpnSenseACME2Exchange");

    public static string InstalledExe => Path.Combine(InstallDirectory, ExeName);

    /// <summary>Eigene Diagnose-Logs der GUI (pro Benutzer).</summary>
    public static string GuiLogDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpnSenseACME2Exchange", "Logs");
}

/// <summary>Geschützte ACL für das Datenverzeichnis: kein Zugriff für normale Benutzer (key.bin ist maschinengebunden!).</summary>
public static class DataDirectorySecurity
{
    private const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    public static void EnsureProtected(string dir, SecurityIdentifier? extraModify = null)
    {
        var exists = Directory.Exists(dir);
        Directory.CreateDirectory(dir);
        var di = new DirectoryInfo(dir);
        var current = di.GetAccessControl();
        if (exists && current.AreAccessRulesProtected && extraModify == null) return;
        Apply(dir, extraModify ?? WindowsIdentity.GetCurrent().User);
    }

    public static void Apply(string dir, params SecurityIdentifier?[] modifySids)
    {
        Directory.CreateDirectory(dir);
        var di = new DirectoryInfo(dir);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));

        // Bestehende Zusatzrechte (z.B. Dienstkonto) behalten
        foreach (FileSystemAccessRule r in di.GetAccessControl().GetAccessRules(true, false, typeof(SecurityIdentifier)))
        {
            var sid = (SecurityIdentifier)r.IdentityReference;
            if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) continue;
            if (r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify
                && !IsBroadGroup(sid))
                sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.Modify, Inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        foreach (var sid in modifySids.Where(s => s != null))
            sec.AddAccessRule(new FileSystemAccessRule(sid!, FileSystemRights.Modify, Inherit, PropagationFlags.None, AccessControlType.Allow));

        di.SetAccessControl(sec);

        // Dateien (auch alte mit eigener ACL) auf Vererbung zurücksetzen
        foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        {
            try
            {
                var fi = new FileInfo(f);
                var fs = fi.GetAccessControl();
                fs.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                foreach (FileSystemAccessRule r in fs.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                    fs.RemoveAccessRuleSpecific(r);
                fi.SetAccessControl(fs);
            }
            catch { /* einzelne Datei gesperrt – nicht kritisch */ }
        }
    }

    private static bool IsBroadGroup(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) || sid.IsWellKnown(WellKnownSidType.WorldSid)
        || sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) || sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid);
}

public sealed class AccessEntry
{
    public string Sid { get; set; } = "";
    public string Name { get; set; } = "";
}

/// <summary>Wer die GUI-Pipe des Dienstes benutzen darf (zusätzlich zu SYSTEM und erhöhten Administratoren).</summary>
public sealed class AccessList
{
    public List<AccessEntry> Entries { get; set; } = new();

    public static AccessList Load()
    {
        try
        {
            return File.Exists(AppPaths.AccessFile)
                ? JsonSerializer.Deserialize<AccessList>(File.ReadAllText(AppPaths.AccessFile)) ?? new AccessList()
                : new AccessList();
        }
        catch { return new AccessList(); }
    }

    public void Save()
    {
        Directory.CreateDirectory(AppPaths.DataDirectory);
        File.WriteAllText(AppPaths.AccessFile, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }

    public void Add(SecurityIdentifier sid)
    {
        if (Entries.Any(e => e.Sid == sid.Value)) return;
        string name;
        try { name = sid.Translate(typeof(NTAccount)).Value; } catch { name = sid.Value; }
        Entries.Add(new AccessEntry { Sid = sid.Value, Name = name });
    }

    public IEnumerable<SecurityIdentifier> Sids()
    {
        foreach (var e in Entries)
        {
            SecurityIdentifier? sid = null;
            try { sid = new SecurityIdentifier(e.Sid); } catch { /* defekter Eintrag */ }
            if (sid != null) yield return sid;
        }
    }
}
