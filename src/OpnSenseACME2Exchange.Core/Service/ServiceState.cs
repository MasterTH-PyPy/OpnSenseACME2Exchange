using System.Text;
using System.Text.Json;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Scheduling;

namespace OpnSenseACME2Exchange.Core.Service;

/// <summary>
/// Laufzeitstatus des Dienstes (state.json, keine Geheimnisse). Schreibt nur der Dienst bzw. der Kommandozeilen-Lauf,
/// die GUI liest – so überschreiben sich GUI-Konfiguration und Dienststatus nie gegenseitig.
/// </summary>
public sealed class ServiceState
{
    public string? Version { get; set; }
    public string? Account { get; set; }
    public DateTime? ServiceStarted { get; set; }
    public DateTime? Heartbeat { get; set; }
    public bool Running { get; set; }
    public DateTime? RunStarted { get; set; }

    /// <summary>Letzter geplanter (automatischer) Lauf – Grundlage für "heute schon gelaufen?".</summary>
    public DateTime? LastAutoRun { get; set; }
    /// <summary>Letzter Lauf überhaupt (auch manuell ausgelöst).</summary>
    public DateTime? LastRun { get; set; }
    public string? LastResult { get; set; }
    public bool LastSuccess { get; set; }
    public string? LastTrigger { get; set; }
    public DateTime? NextRun { get; set; }
    public string? ConfigError { get; set; }

    /// <summary>Selbstheilung: fehlgeschlagener geplanter Lauf wird bis zu 3× stündlich wiederholt.</summary>
    public DateTime? RetryAt { get; set; }
    public int RetryCount { get; set; }

    /// <summary>Vollständiges Ergebnis des letzten Laufs (für die GUI, auch nach Dienst-Neustart).</summary>
    public Engine.RunResult? LastRunDetails { get; set; }
}

public sealed class StateStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    private readonly object _sync = new();

    public StateStore(string path) => FilePath = path;

    public string FilePath { get; }

    public ServiceState Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new ServiceState();
            using var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<ServiceState>(fs, Options) ?? new ServiceState();
        }
        catch
        {
            return new ServiceState(); // halb geschriebene/beschädigte Datei -> leer statt Absturz
        }
    }

    public void Save(ServiceState state)
    {
        lock (_sync)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(FilePath))!);
            var tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(state, Options), Encoding.UTF8);
            File.Move(tmp, FilePath, overwrite: true);
        }
    }

    public void Update(Action<ServiceState> change)
    {
        lock (_sync)
        {
            var s = Load();
            change(s);
            Save(s);
        }
    }
}

/// <summary>Sofort-Lauf anfordern: die GUI legt eine Datei ab, der Dienst holt sie ab (keine Dienst-Steuerrechte nötig).</summary>
public static class RunTrigger
{
    public const string FileName = "run.trigger";

    public static void Request(string dataDirectory, bool dryRun, string requestedBy)
    {
        Directory.CreateDirectory(dataDirectory);
        File.WriteAllText(Path.Combine(dataDirectory, FileName), $"{(dryRun ? "dryrun" : "run")}\n{requestedBy}\n{DateTime.Now:o}");
    }

    public static bool IsPending(string dataDirectory) => File.Exists(Path.Combine(dataDirectory, FileName));

    /// <summary>Holt eine Anforderung ab (und löscht sie). null = keine.</summary>
    public static (bool DryRun, string RequestedBy)? TryConsume(string dataDirectory)
    {
        var path = Path.Combine(dataDirectory, FileName);
        if (!File.Exists(path)) return null;
        try
        {
            var lines = File.ReadAllLines(path);
            File.Delete(path);
            var dry = lines.Length == 0 || !lines[0].Trim().Equals("run", StringComparison.OrdinalIgnoreCase); // im Zweifel Dry-Run
            return (dry, lines.Length > 1 ? lines[1].Trim() : "?");
        }
        catch (IOException) { return null; } // wird gerade geschrieben -> nächster Tick
    }
}

public enum ServiceTickAction { None, ScheduledRun, Retry }

public static class ServiceScheduler
{
    public const int MaxRetries = 3;
    public static readonly TimeSpan RetryInterval = TimeSpan.FromHours(1);

    /// <summary>Entscheidet für einen Takt, ob der geplante Lauf (oder eine Wiederholung) fällig ist.</summary>
    public static ServiceTickAction Decide(DateTime now, AutoModeSettings auto, ServiceState state, out DateTime? nextRun)
    {
        nextRun = null;
        if (!auto.Enabled || !DailySchedule.TryParseTime(auto.Time, out var t)) return ServiceTickAction.None;
        nextRun = DailySchedule.NextRun(now, t, state.LastAutoRun);
        if (nextRun <= now) return ServiceTickAction.ScheduledRun;
        if (state.RetryAt is { } retry)
        {
            if (retry < nextRun) nextRun = retry;
            if (retry <= now) return ServiceTickAction.Retry;
        }
        return ServiceTickAction.None;
    }

    /// <summary>Status nach einem geplanten Lauf/einer Wiederholung fortschreiben.</summary>
    public static void AfterScheduledRun(ServiceState state, ServiceTickAction action, bool success, DateTime now)
    {
        if (action == ServiceTickAction.ScheduledRun)
        {
            state.LastAutoRun = now;
            state.RetryCount = 0;
        }
        if (success)
        {
            state.RetryAt = null;
            state.RetryCount = 0;
            return;
        }
        state.RetryCount++;
        state.RetryAt = state.RetryCount <= MaxRetries ? now + RetryInterval : null;
    }
}
