using System.Security.Principal;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Engine;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Net;
using OpnSenseACME2Exchange.Core.OpnSense;
using OpnSenseACME2Exchange.Core.Service;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.ServiceHost;

/// <summary>Die echten Windows-Bausteine für den Dienstkern.</summary>
public sealed class WindowsServiceBackend : IServiceBackend
{
    private readonly AppServices _services;

    public WindowsServiceBackend(AppServices services) => _services = services;

    public string Version => Program.Version;
    public string Account => WindowsIdentity.GetCurrent().Name;
    public string MachineName => Environment.MachineName;
    public string DataDirectory => AppPaths.DataDirectory;
    public string LogDirectory => Log.Directory;
    public ITlsProbe TlsProbe { get; } = new TlsProbe();

    public ISshSessionFactory CreateSshFactory(AppConfig cfg, Func<OpnSenseNode, string, bool> confirmUnknownHostKey) =>
        _services.CreateSshFactory(cfg, confirmUnknownHostKey);

    public IExchangeOperations CreateExchange(AppConfig cfg) => _services.CreateExchange(cfg);

    public List<ExchangeServerDiscovery> DiscoverExchangeServers(AppConfig cfg)
    {
        var e = cfg.Exchange;
        return e.UseCurrentUser
            ? ExchangeAdDiscovery.Discover()
            : ExchangeAdDiscovery.Discover(e.Username, _services.Store.Reveal(e.PasswordProtected));
    }

    public RunResult Guard(Func<RunResult> run, bool dryRun) => RunGuard.Execute(run, dryRun);

    public void ApplyLogging(AppConfig cfg) => _services.ApplyLogging(cfg);
}
