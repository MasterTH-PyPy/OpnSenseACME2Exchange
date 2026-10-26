using System.Text;

namespace OpnSenseACME2Exchange.Core.Logging;

public enum LogLevel { Debug, Info, Warn, Error }

public sealed record LogEntry(DateTime Timestamp, LogLevel Level, string Message)
{
    public override string ToString() =>
        $"[{Timestamp:yyyy-MM-dd HH:mm:ss}] {LevelTag(Level)} {Message}";

    private static string LevelTag(LogLevel l) => l switch
    {
        LogLevel.Debug => "DEBUG",
        LogLevel.Info  => "INFO ",
        LogLevel.Warn  => "WARN ",
        _              => "ERROR"
    };
}

/// <summary>
/// Thread-sicheres Tageslog: &lt;Verzeichnis&gt;\OpnSenseACME2Exchange_yyyy-MM-dd.log.
/// Passwörter, Private Keys und PFX-Inhalte werden nie geloggt – Aufrufer übergeben nur Metadaten.
/// </summary>
public static class Log
{
    public const string FilePrefix = "OpnSenseACME2Exchange_";
    private static readonly object Sync = new();
    private static string _directory = Path.Combine(AppContext.BaseDirectory, "Logs");
    private static int _retainDays = 30;
    private static DateTime _lastCleanup = DateTime.MinValue;

    public static bool DebugEnabled { get; set; }

    /// <summary>Wird für jede geschriebene Zeile ausgelöst (z.B. für die GUI).</summary>
    public static event Action<LogEntry>? EntryWritten;

    public static string Directory
    {
        get { lock (Sync) return _directory; }
    }

    public static void Configure(string? directory, int retainDays, bool debug)
    {
        lock (Sync)
        {
            _directory = string.IsNullOrWhiteSpace(directory)
                ? Path.Combine(AppContext.BaseDirectory, "Logs")
                : Environment.ExpandEnvironmentVariables(directory.Trim());
            _retainDays = Math.Clamp(retainDays, 1, 3650);
            _lastCleanup = DateTime.MinValue;
        }
        DebugEnabled = debug;
    }

    public static string CurrentFile => FileFor(DateTime.Now);

    public static string FileFor(DateTime day) =>
        Path.Combine(Directory, $"{FilePrefix}{day:yyyy-MM-dd}.log");

    public static void Debug(string msg) { if (DebugEnabled) Write(LogLevel.Debug, msg); }
    public static void Info(string msg)  => Write(LogLevel.Info, msg);
    public static void Warn(string msg)  => Write(LogLevel.Warn, msg);
    public static void Error(string msg) => Write(LogLevel.Error, msg);

    public static void Error(string msg, Exception ex)
    {
        Write(LogLevel.Error, $"{msg}: {Describe(ex)}");
        if (DebugEnabled) Write(LogLevel.Debug, ex.ToString());
    }

    public static string Describe(Exception ex)
    {
        var sb = new StringBuilder(ex.GetType().Name).Append(": ").Append(ex.Message);
        var inner = ex.InnerException;
        int depth = 0;
        while (inner != null && depth++ < 3)
        {
            sb.Append(" -> ").Append(inner.GetType().Name).Append(": ").Append(inner.Message);
            inner = inner.InnerException;
        }
        return sb.ToString();
    }

    public static void Write(LogLevel level, string message)
    {
        var entry = new LogEntry(DateTime.Now, level, Sanitize(message));
        lock (Sync)
        {
            try
            {
                System.IO.Directory.CreateDirectory(_directory);
                File.AppendAllText(FileFor(entry.Timestamp), entry + Environment.NewLine, Encoding.UTF8);
                CleanupIfDue(entry.Timestamp);
            }
            catch
            {
                // Logging darf den eigentlichen Ablauf nie abbrechen.
            }
        }
        try { EntryWritten?.Invoke(entry); } catch { /* GUI-Handler-Fehler ignorieren */ }
    }

    /// <summary>Verhindert Log-Injection: Zeilenumbrüche und Steuerzeichen werden entschärft.</summary>
    public static string Sanitize(string message)
    {
        if (string.IsNullOrEmpty(message)) return string.Empty;
        var sb = new StringBuilder(message.Length);
        foreach (var c in message)
        {
            if (c == '\r') continue;
            if (c == '\n') { sb.Append(" | "); continue; }
            if (char.IsControl(c) && c != '\t') { sb.Append('?'); continue; }
            sb.Append(c);
        }
        return sb.ToString();
    }

    private static void CleanupIfDue(DateTime now)
    {
        if ((now - _lastCleanup).TotalHours < 6) return;
        _lastCleanup = now;
        var limit = now.Date.AddDays(-_retainDays);
        foreach (var file in System.IO.Directory.EnumerateFiles(_directory, FilePrefix + "*.log"))
        {
            var stamp = Path.GetFileNameWithoutExtension(file)[FilePrefix.Length..];
            if (DateTime.TryParseExact(stamp, "yyyy-MM-dd", null,
                    System.Globalization.DateTimeStyles.None, out var day) && day < limit)
            {
                try { File.Delete(file); } catch { /* gesperrt -> nächstes Mal */ }
            }
        }
    }

    /// <summary>Alle vorhandenen Logdateien, neueste zuerst.</summary>
    public static IReadOnlyList<string> ListFiles()
    {
        var dir = Directory;
        if (!System.IO.Directory.Exists(dir)) return Array.Empty<string>();
        return System.IO.Directory.EnumerateFiles(dir, FilePrefix + "*.log")
            .OrderByDescending(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
