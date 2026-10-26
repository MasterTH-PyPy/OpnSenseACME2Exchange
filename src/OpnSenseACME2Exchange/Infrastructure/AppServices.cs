using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Net;
using OpnSenseACME2Exchange.Core.OpnSense;

namespace OpnSenseACME2Exchange.Infrastructure;

/// <summary>Baut die Komponenten aus der Konfiguration (Geheimnisse werden erst hier entschlüsselt).</summary>
public sealed class AppServices
{
    public AppServices()
    {
        Protector = new DpapiAesSecretProtector(AppPaths.KeyFile);
        Store = new ConfigStore(AppPaths.ConfigFile, Protector);
    }

    public DpapiAesSecretProtector Protector { get; }
    public ConfigStore Store { get; }

    public SshNetSessionFactory CreateSshFactory(AppConfig cfg, Func<OpnSenseNode, string, bool>? confirmHostKey)
    {
        var o = cfg.OpnSense;
        var cred = new SshCredentials(o.Username, o.AuthMode, Store.Reveal(o.PasswordProtected),
            o.PrivateKeyPath, Store.Reveal(o.PrivateKeyPassphraseProtected));
        return new SshNetSessionFactory(cred, o.TimeoutSeconds, confirmHostKey);
    }

    public OpnSenseCertificateSource CreateCertificateSource(AppConfig cfg, Func<OpnSenseNode, string, bool>? confirmHostKey, Action? onLearned = null)
    {
        var f = CreateSshFactory(cfg, confirmHostKey);
        if (onLearned != null) f.HostKeyLearned += _ => onLearned();
        return new OpnSenseCertificateSource(cfg.OpnSense, f);
    }

    public ExchangePowerShellOperations CreateExchange(AppConfig cfg, Action? onLearned = null)
    {
        var e = cfg.Exchange;
        var cred = new ExchangeCredentials(e.UseCurrentUser, e.Username, Store.Reveal(e.PasswordProtected),
            string.IsNullOrWhiteSpace(e.Authentication) ? "Kerberos" : e.Authentication);
        var ops = new ExchangePowerShellOperations(cred, new TlsProbe());
        if (onLearned != null) ops.UriLearned += _ => onLearned();
        return ops;
    }

    public DeployEngine CreateEngine(AppConfig cfg, Func<OpnSenseNode, string, bool>? confirmHostKey, Action? onLearned = null) =>
        new(cfg, CreateCertificateSource(cfg, confirmHostKey, onLearned), CreateExchange(cfg, onLearned), new TlsProbe());

    public void ApplyLogging(AppConfig cfg) =>
        Log.Configure(cfg.Logging.Directory, cfg.Logging.RetainDays, cfg.Logging.Debug, AppPaths.LogDirectory);
}

/// <summary>Prozessübergreifende Sperre, damit GUI und geplante Aufgabe nie gleichzeitig tauschen.</summary>
public static class RunGuard
{
    private const string MutexName = @"Global\OpnSenseACME2Exchange_Run";

    public static RunResult Execute(Func<RunResult> run, bool dryRun)
    {
        using var mutex = new Mutex(false, MutexName);
        bool owned;
        try { owned = mutex.WaitOne(TimeSpan.Zero); }
        catch (AbandonedMutexException) { owned = true; }

        if (!owned)
        {
            var r = new RunResult { DryRun = dryRun, FatalError = "Ein anderer Prozess (GUI oder geplante Aufgabe) führt gerade einen Lauf aus." };
            Log.Warn(r.FatalError);
            return r;
        }
        try { return run(); }
        finally { mutex.ReleaseMutex(); }
    }
}
