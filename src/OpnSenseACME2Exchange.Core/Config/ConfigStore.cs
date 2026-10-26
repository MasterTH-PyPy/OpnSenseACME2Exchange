using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpnSenseACME2Exchange.Core.Config;

/// <summary>Verschlüsselt/entschlüsselt Geheimnisse (Implementierung: AES-256-GCM mit DPAPI-geschütztem Schlüssel).</summary>
public interface ISecretProtector
{
    string Protect(string plain);
    string Unprotect(string protectedValue);
}

/// <summary>
/// Lädt und speichert die Konfiguration als AES-256-verschlüsselte Datei (config.dat).
/// Einzelne Passwörter sind zusätzlich feldweise geschützt.
/// </summary>
public sealed class ConfigStore
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private readonly ISecretProtector _protector;

    public ConfigStore(string path, ISecretProtector protector)
    {
        FilePath = path;
        _protector = protector;
    }

    public string FilePath { get; }

    public AppConfig Load()
    {
        if (!File.Exists(FilePath)) return new AppConfig();
        var raw = File.ReadAllText(FilePath, Encoding.UTF8).Trim();
        var json = raw.StartsWith('{') ? raw : _protector.Unprotect(raw); // Klartext nur als Import-Fallback
        return JsonSerializer.Deserialize<AppConfig>(json, JsonOptions) ?? new AppConfig();
    }

    public void Save(AppConfig config)
    {
        var json = JsonSerializer.Serialize(config, JsonOptions);
        var payload = _protector.Protect(json);
        var dir = Path.GetDirectoryName(Path.GetFullPath(FilePath))!;
        Directory.CreateDirectory(dir);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, payload, Encoding.UTF8);
        File.Move(tmp, FilePath, overwrite: true);
    }

    public string? Reveal(string? protectedValue)
    {
        if (string.IsNullOrEmpty(protectedValue)) return null;
        return _protector.Unprotect(protectedValue);
    }

    public string? Hide(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return null;
        return _protector.Protect(plain);
    }

    public static AppConfig Clone(AppConfig c) =>
        JsonSerializer.Deserialize<AppConfig>(JsonSerializer.Serialize(c, JsonOptions), JsonOptions)!;
}
