using System.Reflection;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Infrastructure;
using OpnSenseACME2Exchange.UI;

namespace OpnSenseACME2Exchange;

internal static class Program
{
    public static string Version =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "?";

    /// <summary>
    /// Ohne Parameter: GUI.
    /// --run [--dry-run]: ein Durchlauf ohne Oberfläche (für die Windows-Aufgabenplanung), Exitcode 0 = OK, 1 = Fehler, 2 = Warnung.
    /// </summary>
    [STAThread]
    private static int Main(string[] args)
    {
        var services = new AppServices();
        bool headless = args.Any(a => a.Equals("--run", StringComparison.OrdinalIgnoreCase) || a.Equals("/run", StringComparison.OrdinalIgnoreCase));
        bool dryRun = args.Any(a => a.Equals("--dry-run", StringComparison.OrdinalIgnoreCase) || a.Equals("/dryrun", StringComparison.OrdinalIgnoreCase));

        if (headless) return RunHeadless(services, dryRun);

        using var single = new Mutex(true, @"Local\OpnSenseACME2Exchange_GUI", out bool first);
        if (!first)
        {
            MessageBox.Show("OpnSenseACME2Exchange läuft bereits (ggf. im Infobereich neben der Uhr).",
                "OpnSenseACME2Exchange", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            Log.Error("Unbehandelter Fehler", e.Exception);
            MessageBox.Show(e.Exception.Message, "Fehler", MessageBoxButtons.OK, MessageBoxIcon.Error);
        };
        Application.Run(new MainForm(services));
        return 0;
    }

    private static int RunHeadless(AppServices services, bool dryRun)
    {
        try
        {
            var cfg = services.Store.Load();
            services.ApplyLogging(cfg);
            Log.Info($"OpnSenseACME2Exchange {Version} – Aufruf per Kommandozeile ({Environment.UserDomainName}\\{Environment.UserName}).");

            bool learned = false;
            // Ohne GUI werden unbekannte Hostkeys nie automatisch akzeptiert.
            var engine = services.CreateEngine(cfg, confirmHostKey: null, onLearned: () => learned = true);
            var result = RunGuard.Execute(() => engine.Run(dryRun, CancellationToken.None), dryRun);

            cfg.Auto.LastRun = DateTime.Now;
            cfg.Auto.LastResult = result.Summary + " (Kommandozeile)";
            try { services.Store.Save(cfg); }
            catch (Exception ex) { Log.Warn("Konfiguration konnte nach dem Lauf nicht gespeichert werden: " + Log.Describe(ex)); }
            if (learned) Log.Debug("Gelernte Einstellungen (URIs) gespeichert.");

            if (!result.Success) return 1;
            return result.Servers.Any(s => s.Outcome == Core.Engine.ServerOutcome.Warning) ? 2 : 0;
        }
        catch (Exception ex)
        {
            Log.Error("Kommandozeilen-Lauf fehlgeschlagen", ex);
            return 1;
        }
    }
}
