namespace OpnSenseACME2Exchange.Core.Config;

public sealed class AppConfig
{
    public int SchemaVersion { get; set; } = 1;
    public OpnSenseSettings OpnSense { get; set; } = new();
    public CertificateSelection Selection { get; set; } = new();
    public ExchangeSettings Exchange { get; set; } = new();
    public AutoModeSettings Auto { get; set; } = new();
    public LoggingSettings Logging { get; set; } = new();
}

public enum SshAuthMode { Password, PrivateKey }

public sealed class OpnSenseNode
{
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;

    /// <summary>SHA256-Fingerprint des SSH-Hostkeys (Trust-on-first-use, danach strikt).</summary>
    public string? HostKeyFingerprint { get; set; }

    public override string ToString() => string.IsNullOrWhiteSpace(Name) ? Host : $"{Name} ({Host})";
}

public sealed class OpnSenseSettings
{
    public List<OpnSenseNode> Nodes { get; set; } = new();
    public string Username { get; set; } = "root";
    public SshAuthMode AuthMode { get; set; } = SshAuthMode.Password;

    /// <summary>Verschlüsselt (siehe ISecretProtector).</summary>
    public string? PasswordProtected { get; set; }
    public string? PrivateKeyPath { get; set; }
    /// <summary>Verschlüsselt (siehe ISecretProtector).</summary>
    public string? PrivateKeyPassphraseProtected { get; set; }

    /// <summary>Befehle mit "sudo -n" ausführen (wenn nicht als root angemeldet).</summary>
    public bool UseSudo { get; set; }

    /// <summary>Den aktuellen CARP-Master zuerst verwenden.</summary>
    public bool PreferCarpMaster { get; set; } = true;

    public string HaproxyConfigPath { get; set; } = "/usr/local/etc/haproxy.conf";
    public int TimeoutSeconds { get; set; } = 20;
}

public sealed class CertificateSelection
{
    /// <summary>Gewählter Abschnitt aus der HAProxy-Konfiguration, z.B. "frontend 1_HTTPS".</summary>
    public string? SectionKey { get; set; }

    /// <summary>Externer Exchange-Hostname, den das Zertifikat abdecken muss (z.B. mail.example.de).</summary>
    public string ExchangeHostname { get; set; } = "";

    /// <summary>Weitere Namen, die das Zertifikat zusätzlich abdecken muss (z.B. autodiscover.example.de).</summary>
    public List<string> AdditionalRequiredNames { get; set; } = new();

    /// <summary>Zuletzt gefundener Pfad auf der OPNsense (nur Info / Schnellweg).</summary>
    public string? LastKnownPemPath { get; set; }
}

public sealed class ExchangeServerEntry
{
    public bool Enabled { get; set; } = true;
    public string Name { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public string? Version { get; set; }
    public string? Dag { get; set; }
    public string? Site { get; set; }
    public bool IsEdge { get; set; }

    /// <summary>Beim letzten AD-Abgleich nicht mehr gefunden → wird bei Läufen übersprungen.</summary>
    public bool MissingInAd { get; set; }

    /// <summary>Zuletzt funktionierende Remote-PowerShell-URI (wird selbstheilend gelernt).</summary>
    public string? PowerShellUri { get; set; }

    /// <summary>Letzter Status (Test/Lauf) – nur Anzeige.</summary>
    public string? LastStatus { get; set; }
    public string? CurrentCertificate { get; set; }
}

public sealed class ExchangeSettings
{
    public List<ExchangeServerEntry> Servers { get; set; } = new();

    public bool UseCurrentUser { get; set; } = true;
    public string? Username { get; set; }
    /// <summary>Verschlüsselt (siehe ISecretProtector).</summary>
    public string? PasswordProtected { get; set; }

    /// <summary>Kerberos, Negotiate oder Default.</summary>
    public string Authentication { get; set; } = "Kerberos";

    public bool ServiceIis { get; set; } = true;
    public bool ServiceSmtp { get; set; }
    public bool ServiceImap { get; set; }
    public bool ServicePop { get; set; }

    public bool PrivateKeyExportable { get; set; }
    public bool VerifyAfterDeploy { get; set; } = true;
    public bool IisResetOnMismatch { get; set; }
    public bool RemoveReplacedCertificate { get; set; }

    /// <summary>Vor jedem Lauf die Server neu aus dem AD ermitteln (neue mitnehmen, entfernte überspringen).</summary>
    public bool AutoDiscoverBeforeRun { get; set; } = true;

    public string ServicesString()
    {
        var list = new List<string>();
        if (ServiceIis) list.Add("IIS");
        if (ServiceSmtp) list.Add("SMTP");
        if (ServiceImap) list.Add("IMAP");
        if (ServicePop) list.Add("POP");
        return string.Join(",", list);
    }
}

public sealed class AutoModeSettings
{
    public bool Enabled { get; set; }
    /// <summary>Uhrzeit HH:mm (lokal).</summary>
    public string Time { get; set; } = "03:30";
    public bool DryRun { get; set; }
    // Letzter Lauf/Ergebnis stehen in state.json (schreibt nur der Dienst).
}

public sealed class LoggingSettings
{
    public string? Directory { get; set; }
    public int RetainDays { get; set; } = 30;
    public bool Debug { get; set; }
}
