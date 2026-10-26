using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpnSenseACME2Exchange.Core.Certificates;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.OpnSense;
using OpnSenseACME2Exchange.Core.Service;

namespace OpnSenseACME2Exchange.Core.Ipc;

/// <summary>
/// GUI ⇄ Dienst über eine Named Pipe. Jede Nachricht: 4 Byte Länge (Little Endian) + UTF-8-JSON.
/// Pro Verbindung genau eine Anfrage und eine Antwort.
/// </summary>
public static class PipeProtocol
{
    public const string PipeName = "OpnSenseACME2Exchange";
    public const int MaxMessageBytes = 32 * 1024 * 1024;

    public static readonly JsonSerializerOptions Json = new()
    {
        Converters = { new JsonStringEnumConverter() },
        PropertyNameCaseInsensitive = true
    };

    public static async Task WriteAsync<T>(Stream stream, T message, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, Json);
        if (body.Length > MaxMessageBytes) throw new InvalidOperationException("Nachricht zu groß.");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        await stream.WriteAsync(header, ct);
        await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await ReadExactAsync(stream, header, ct);
        var len = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (len <= 0 || len > MaxMessageBytes) throw new InvalidDataException($"Ungültige Nachrichtenlänge {len}.");
        var body = new byte[len];
        await ReadExactAsync(stream, body, ct);
        return JsonSerializer.Deserialize<T>(body, Json) ?? throw new InvalidDataException("Leere Nachricht.");
    }

    private static async Task ReadExactAsync(Stream s, byte[] buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            var n = await s.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) throw new EndOfStreamException("Verbindung zum Gegenüber unterbrochen.");
            read += n;
        }
    }

    public static JsonElement ToElement<T>(T value) => JsonSerializer.SerializeToElement(value, Json);

    public static T? FromElement<T>(JsonElement? element) =>
        element is { ValueKind: not JsonValueKind.Undefined and not JsonValueKind.Null } e ? e.Deserialize<T>(Json) : default;
}

public static class Commands
{
    public const string Ping = "Ping";
    public const string GetStatus = "GetStatus";
    public const string GetConfig = "GetConfig";
    public const string SaveConfig = "SaveConfig";
    public const string TrustHostKey = "TrustHostKey";
    public const string ResetHostKey = "ResetHostKey";
    public const string TestNodes = "TestNodes";
    public const string ReadHaproxy = "ReadHaproxy";
    public const string ResolveCertificate = "ResolveCertificate";
    public const string DiscoverServers = "DiscoverServers";
    public const string TestServers = "TestServers";
    public const string CheckUrls = "CheckUrls";
    public const string StartRun = "StartRun";
    public const string Cancel = "Cancel";
    public const string ListLogs = "ListLogs";
    public const string ReadLog = "ReadLog";
}

public sealed class PipeRequest
{
    public string Command { get; set; } = "";
    public JsonElement? Payload { get; set; }
    public string? ClientVersion { get; set; }
}

public sealed class PipeResponse
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public JsonElement? Payload { get; set; }
    /// <summary>Unbekannte SSH-Hostkeys, die die GUI dem Benutzer zur Bestätigung vorlegen soll.</summary>
    public List<UnknownHostKey> UnknownHostKeys { get; set; } = new();

    public static PipeResponse Success(object? payload = null, List<UnknownHostKey>? unknown = null) => new()
    {
        Ok = true,
        Payload = payload == null ? null : PipeProtocol.ToElement(payload),
        UnknownHostKeys = unknown ?? new()
    };

    public static PipeResponse Fail(string error, List<UnknownHostKey>? unknown = null) => new()
    {
        Ok = false,
        Error = error,
        UnknownHostKeys = unknown ?? new()
    };
}

// ───────────────────────── DTOs ─────────────────────────

public sealed record UnknownHostKey(string Host, string Name, string Fingerprint);

public sealed record TrustHostKeyRequest(string Host, string Fingerprint);

/// <summary>Konfiguration ohne Geheimnisse (die verlassen den Dienst nie).</summary>
public sealed class ConfigDto
{
    public AppConfig Config { get; set; } = new();
    public bool HasSshPassword { get; set; }
    public bool HasKeyPassphrase { get; set; }
    public bool HasExchangePassword { get; set; }
    public string DataDirectory { get; set; } = "";
    public string ServiceAccount { get; set; } = "";
    public string MachineName { get; set; } = "";
}

/// <summary>Speichern: null/leer = Geheimnis unverändert lassen.</summary>
public sealed class SaveConfigRequest
{
    public AppConfig Config { get; set; } = new();
    public string? SshPassword { get; set; }
    public string? KeyPassphrase { get; set; }
    public string? ExchangePassword { get; set; }
}

public sealed record NodeStatusDto(string Host, string Name, bool Reachable, CarpState Carp, string? Version,
    bool? HaproxyRunning, bool? ConfigReadable, string? Error, string Summary, string? HostKeyFingerprint);

public sealed record HaproxySectionDto(string Key, string Type, string Name, string Text, bool TerminatesTls, bool CanCarryCertificate, List<string> Hostnames)
{
    public override string ToString() => TerminatesTls ? $"{Key}  [TLS]" : Key;
}

public sealed record HaproxyReadResult(string Node, List<HaproxySectionDto> Sections);

public sealed record ResolveResultDto(
    CertificateInfo? Info, string? Node, string? Path, string? Section,
    List<PemCandidate> Candidates, List<string> Warnings, List<string> Errors,
    List<string> ValidationErrors, List<string> ValidationWarnings);

public sealed record DiscoveryResultDto(List<ExchangeServerDiscovery> Found, int Added);

public sealed record TestServersRequest(List<string> Fqdns);

public sealed record ServerTestDto(string Fqdn, bool Ok, string Summary, List<ConnectionStep> Steps);

public sealed record StartRunRequest(bool DryRun);

public sealed class StatusDto
{
    public string Version { get; set; } = "";
    public string Account { get; set; } = "";
    public string MachineName { get; set; } = "";
    public DateTime ServiceStarted { get; set; }
    public string? CurrentOperation { get; set; }
    public DateTime? OperationStarted { get; set; }
    public bool RunInProgress { get; set; }
    public RunResult? CurrentRun { get; set; }
    public RunResult? LastRunResult { get; set; }
    public ServiceState State { get; set; } = new();
    public AutoModeSettings Auto { get; set; } = new();
}

public sealed record LogFileDto(string Name, long Size, DateTime Modified);

public sealed record LogListDto(List<LogFileDto> Files, string Current);

public sealed record ReadLogRequest(string Name, long Offset);

public sealed record LogChunkDto(string Name, string Text, long NewOffset, long Length, bool Reset);
