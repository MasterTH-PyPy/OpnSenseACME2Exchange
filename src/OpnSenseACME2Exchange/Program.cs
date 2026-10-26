using System.Reflection;
using System.ServiceProcess;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Service;
using OpnSenseACME2Exchange.Infrastructure;
using OpnSenseACME2Exchange.ServiceHost;
using OpnSenseACME2Exchange.UI;

namespace OpnSenseACME2Exchange;

internal static class Program
{
    public static string Version =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "?";

    /// <summary>
    /// Eine EXE, mehrere Rollen:
    ///   (ohne)                 GUI – bedient den Dienst über die Named Pipe
    ///   --service              Windows-Dienst (wird vom Dienststeuerungs-Manager gestartet)
    ///   --admin &lt;datei&gt;       erhöhte Admin-Aktion (Installieren/Starten/…; startet die GUI selbst)
    ///   --run [--dry-run]      ein Lauf ohne Dienst/GUI (Diagnose), Exitcode 0 = OK, 1 = Fehler, 2 = Warnung
    ///   --screenshots &lt;ordner&gt;  GUI mit Demodaten als PNGs rendern (Doku/CI)
    /// </summary>
    [STAThread]
    private static int Main(string[] args)
    {
        bool Has(string a) => args.Any(x => x.Equals(a, StringComparison.OrdinalIgnoreCase));

        if (Has("--service"))
        {
            ServiceBase.Run(new CertWindowsService());
            return 0;
        }

        var adminIdx = Array.FindIndex(args, a => a.Equals("--admin", StringComparison.OrdinalIgnoreCase));
        if (adminIdx >= 0 && adminIdx + 1 < args.Length)
            return AdminActions.Execute(args[adminIdx + 1]);

        if (Has("--run")) return RunHeadless(Has("--dry-run"));

        var shotIdx = Array.FindIndex(args, a => a.Equals("--screenshots", StringComparison.OrdinalIgnoreCase));
        if (shotIdx >= 0)
        {
            // Doku: GUI mit Demodaten rendern (kein Dienst, kein Netzwerk)
            Log.Configure(Path.Combine(Path.GetTempPath(), "o2e-screenshots"), 1, false);
            ApplicationConfiguration.Initialize();
            var dir = shotIdx + 1 < args.Length ? args[shotIdx + 1] : "screenshots";
            try
            {
                MainForm.RenderScreenshots(dir);
                return 0;
            }
            catch (Exception ex)
            {
                // Für die CI lesbar machen (WinExe hat keine Konsole)
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "screenshot-error.txt"), ex.ToString());
                return 3;
            }
        }

        Log.Configure(AppPaths.GuiLogDirectory, 14, false);
        using var single = new Mutex(true, @"Local\OpnSenseACME2Exchange_GUI", out bool first);
        if (!first)
        {
            MessageBox.Show("OpnSenseACME2Exchange ist bereits geöffnet.", "OpnSenseACME2Exchange",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            Log.Error("Unbehandelter Fehler", e.Exception);
            MessageBox.Show(e.Exception.Message, "Fehler", MessageBoxButtons.OK, MessageBoxIcon.Error);
        };
        Application.Run(new MainForm());
        return 0;
    }

    /// <summary>Diagnose-Lauf ohne Dienst: nutzt dieselbe Konfiguration (braucht Zugriff auf das Datenverzeichnis).</summary>
    private static int RunHeadless(bool dryRun)
    {
        try
        {
            var services = new AppServices();
            var cfg = services.Store.Load();
            services.ApplyLogging(cfg);
            Log.Info($"OpnSenseACME2Exchange {Version} – Kommandozeilen-Lauf ({Environment.UserDomainName}\\{Environment.UserName}).");

            // Ohne GUI werden unbekannte Hostkeys nie akzeptiert.
            var engine = services.CreateEngine(cfg, confirmHostKey: null);
            var result = RunGuard.Execute(() => engine.Run(dryRun, CancellationToken.None), dryRun);

            new StateStore(AppPaths.StateFile).Update(s =>
            {
                s.LastRun = DateTime.Now;
                s.LastResult = result.Summary;
                s.LastSuccess = result.Success;
                s.LastTrigger = $"Kommandozeile ({Environment.UserName})";
                s.LastRunDetails = result;
            });
            try { services.Store.Save(cfg); }
            catch (Exception ex) { Log.Warn("Konfiguration konnte nach dem Lauf nicht gespeichert werden: " + Log.Describe(ex)); }

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
