using System.ServiceProcess;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Service;
using OpnSenseACME2Exchange.Infrastructure;

namespace OpnSenseACME2Exchange.ServiceHost;

/// <summary>Der Windows-Dienst: Dienstkern + GUI-Pipe + Zeitplan-Takt.</summary>
public sealed class CertWindowsService : ServiceBase
{
    private readonly CancellationTokenSource _cts = new();
    private ServiceCore? _core;
    private Task? _pipeTask, _schedulerTask;

    public CertWindowsService()
    {
        ServiceName = AppPaths.ServiceName;
        CanStop = true;
        CanShutdown = true;
        CanPauseAndContinue = false;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        DataDirectorySecurity.EnsureProtected(AppPaths.DataDirectory);
        var services = new AppServices();
        _core = new ServiceCore(services.Store, new StateStore(AppPaths.StateFile), new WindowsServiceBackend(services));
        _core.Start();

        _pipeTask = new PipeServer(_core).RunAsync(_cts.Token);
        _schedulerTask = Task.Run(() => SchedulerLoopAsync(_core, _cts.Token));
    }

    private static async Task SchedulerLoopAsync(ServiceCore core, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { core.SchedulerTick(ct); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Log.Error("Zeitplan", ex); }
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    protected override void OnStop()
    {
        RequestAdditionalTime(35_000);
        _cts.Cancel();
        _core?.Stop();
        try { Task.WaitAll(new[] { _pipeTask, _schedulerTask }.OfType<Task>().ToArray(), TimeSpan.FromSeconds(5)); }
        catch { /* beim Beenden egal */ }
    }

    protected override void OnShutdown() => OnStop();
}
