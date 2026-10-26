using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Logging;
using OpnSenseACME2Exchange.Core.Net;

namespace OpnSenseACME2Exchange.Infrastructure;

public sealed record ExchangeCredentials(bool UseCurrentUser, string? Username, string? Password, string Authentication);

/// <summary>
/// Exchange-Zugriff über Remote-PowerShell (Microsoft.Exchange-Endpunkt, Implicit Remoting).
/// Selbstheilend: probiert die zuletzt funktionierende URI, dann http und https, und merkt sich die funktionierende.
/// </summary>
public sealed class ExchangePowerShellOperations : IExchangeOperations
{
    private static readonly string[] CertCommands =
        { "Get-ExchangeServer", "Get-ExchangeCertificate", "Import-ExchangeCertificate", "Enable-ExchangeCertificate", "Remove-ExchangeCertificate" };

    private const string ConnectBlock = """
        param($in)
        try {
            $opt = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 600000 -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            $p = @{ ConfigurationName = 'Microsoft.Exchange'; ConnectionUri = $in.Uri; Authentication = $in.Auth; SessionOption = $opt; ErrorAction = 'Stop' }
            if ($in.User) {
                $p.Credential = New-Object System.Management.Automation.PSCredential($in.User, (ConvertTo-SecureString $in.Password -AsPlainText -Force))
            }
            $s = New-PSSession @p
            Import-PSSession $s -CommandName @($in.Commands) -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
        } catch {
            throw ('CONNECT: ' + $_.Exception.Message)
        }
        try {
        """;

    private const string CloseBlock = """
        } finally {
            Remove-PSSession $s -ErrorAction SilentlyContinue
        }
        """;

    private const string CertProjection = """
        function ConvertTo-CertDto($c) {
            [pscustomobject]@{
                Thumbprint    = "$($c.Thumbprint)"
                Subject       = "$($c.Subject)"
                Issuer        = "$($c.Issuer)"
                FriendlyName  = "$($c.FriendlyName)"
                NotBefore     = ([datetime]$c.NotBefore).ToUniversalTime().ToString('o')
                NotAfter      = ([datetime]$c.NotAfter).ToUniversalTime().ToString('o')
                Services      = "$($c.Services)"
                Domains       = @($c.CertificateDomains | ForEach-Object { "$_" })
                HasPrivateKey = [bool]$c.HasPrivateKey
            }
        }
        """;

    private readonly ExchangeCredentials _cred;
    private readonly ITlsProbe _probe;

    public ExchangePowerShellOperations(ExchangeCredentials cred, ITlsProbe probe)
    {
        _cred = cred;
        _probe = probe;
    }

    /// <summary>Wird ausgelöst, wenn eine (neue) funktionierende Remote-PowerShell-URI gelernt wurde.</summary>
    public event Action<ExchangeServerEntry>? UriLearned;

    private static string Identity(ExchangeServerEntry s) =>
        !string.IsNullOrWhiteSpace(s.Name) ? s.Name : s.Fqdn.Split('.')[0];

    private static IEnumerable<string> CandidateUris(ExchangeServerEntry s)
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(s.PowerShellUri)) list.Add(s.PowerShellUri!);
        list.Add($"http://{s.Fqdn}/PowerShell/");
        list.Add($"https://{s.Fqdn}/PowerShell/");
        return list.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private JsonNode? Exec(ExchangeServerEntry server, string body, Dictionary<string, object?> extra, TimeSpan timeout, CancellationToken ct)
    {
        var script = ConnectBlock + "\n" + CertProjection + "\n" + body + "\n" + CloseBlock;
        var errors = new List<string>();
        foreach (var uri in CandidateUris(server))
        {
            ct.ThrowIfCancellationRequested();
            var input = new Dictionary<string, object?>(extra)
            {
                ["Uri"] = uri,
                ["Auth"] = _cred.Authentication,
                ["User"] = _cred.UseCurrentUser ? null : _cred.Username,
                ["Password"] = _cred.UseCurrentUser ? null : _cred.Password,
                ["Server"] = Identity(server),
                ["Commands"] = CertCommands
            };
            try
            {
                var sw = Stopwatch.StartNew();
                var res = PowerShellRunner.Run(script, input, timeout, ct);
                Log.Debug($"[{Identity(server)}] Remote-PowerShell {uri} OK ({sw.ElapsedMilliseconds} ms)");
                if (!string.Equals(server.PowerShellUri, uri, StringComparison.OrdinalIgnoreCase))
                {
                    if (server.PowerShellUri != null)
                        Log.Info($"[{Identity(server)}] Remote-PowerShell-URI gewechselt: {server.PowerShellUri} → {uri}");
                    server.PowerShellUri = uri;
                    UriLearned?.Invoke(server);
                }
                return res;
            }
            catch (PowerShellException ex) when (ex.IsConnectError)
            {
                errors.Add($"{uri}: {ex.Message}");
                Log.Debug($"[{Identity(server)}] Verbindung über {uri} fehlgeschlagen: {ex.Message}");
            }
        }
        throw new InvalidOperationException("Keine Remote-PowerShell-Verbindung möglich – " + string.Join(" | ", errors));
    }

    public IReadOnlyList<ExchangeCertInfo> GetCertificates(ExchangeServerEntry server, CancellationToken ct)
    {
        const string body = """
            $list = @(Get-ExchangeCertificate -Server $in.Server | ForEach-Object { ConvertTo-CertDto $_ })
            [pscustomobject]@{ Certs = $list }
            """;
        var res = Exec(server, body, new(), TimeSpan.FromMinutes(3), ct);
        return ParseCerts(res?["Certs"]);
    }

    public string ImportCertificate(ExchangeServerEntry server, byte[] pfx, string password, bool privateKeyExportable, CancellationToken ct)
    {
        const string body = """
            $bytes = [Convert]::FromBase64String($in.Pfx)
            $sec = ConvertTo-SecureString $in.PfxPassword -AsPlainText -Force
            $imported = @(Import-ExchangeCertificate -Server $in.Server -FileData $bytes -Password $sec -PrivateKeyExportable:([bool]$in.Exportable))
            $leaf = @($imported | Where-Object { $_.HasPrivateKey })
            if ($leaf.Count -eq 0) { $leaf = $imported }
            [pscustomobject]@{ Thumbprint = "$($leaf[0].Thumbprint)" }
            """;
        var res = Exec(server, body, new()
        {
            ["Pfx"] = Convert.ToBase64String(pfx),
            ["PfxPassword"] = password,
            ["Exportable"] = privateKeyExportable
        }, TimeSpan.FromMinutes(5), ct);
        var tp = res?["Thumbprint"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(tp)) throw new InvalidOperationException("Import-ExchangeCertificate lieferte keinen Thumbprint.");
        return tp.Trim().ToUpperInvariant();
    }

    public void EnableCertificate(ExchangeServerEntry server, string thumbprint, string services, CancellationToken ct)
    {
        const string body = """
            Enable-ExchangeCertificate -Server $in.Server -Thumbprint $in.Thumbprint -Services $in.Services -Force -Confirm:$false | Out-Null
            [pscustomobject]@{ Ok = $true }
            """;
        Exec(server, body, new() { ["Thumbprint"] = thumbprint, ["Services"] = services }, TimeSpan.FromMinutes(5), ct);
    }

    public void RemoveCertificate(ExchangeServerEntry server, string thumbprint, CancellationToken ct)
    {
        const string body = """
            Remove-ExchangeCertificate -Server $in.Server -Thumbprint $in.Thumbprint -Confirm:$false | Out-Null
            [pscustomobject]@{ Ok = $true }
            """;
        Exec(server, body, new() { ["Thumbprint"] = thumbprint }, TimeSpan.FromMinutes(3), ct);
    }

    public void IisReset(ExchangeServerEntry server, CancellationToken ct)
    {
        const string script = """
            param($in)
            $p = @{ ComputerName = $in.Fqdn; ScriptBlock = { iisreset /noforce 2>&1 | Out-String }; ErrorAction = 'Stop' }
            if ($in.User) {
                $p.Credential = New-Object System.Management.Automation.PSCredential($in.User, (ConvertTo-SecureString $in.Password -AsPlainText -Force))
            }
            $o = Invoke-Command @p
            [pscustomobject]@{ Output = "$o" }
            """;
        var res = PowerShellRunner.Run(script, new Dictionary<string, object?>
        {
            ["Fqdn"] = server.Fqdn,
            ["User"] = _cred.UseCurrentUser ? null : _cred.Username,
            ["Password"] = _cred.UseCurrentUser ? null : _cred.Password
        }, TimeSpan.FromMinutes(5), ct);
        Log.Info($"[{Identity(server)}] iisreset: {res?["Output"]?.GetValue<string>()?.Trim()}");
    }

    public ConnectionTestResult TestConnection(ExchangeServerEntry server, string externalHostname, CancellationToken ct)
    {
        var r = new ConnectionTestResult();
        var name = Identity(server);

        // 1) DNS
        try
        {
            var addrs = Dns.GetHostAddresses(server.Fqdn);
            r.Steps.Add(new ConnectionStep("DNS", addrs.Length > 0, string.Join(", ", addrs.Select(a => a.ToString()))));
        }
        catch (Exception ex)
        {
            r.Steps.Add(new ConnectionStep("DNS", false, ex.Message));
            return r;
        }

        // 2) Ping (nur Info – ICMP ist oft gesperrt)
        try
        {
            using var ping = new Ping();
            var reply = ping.Send(server.Fqdn, 2000);
            r.Steps.Add(new ConnectionStep("Ping", reply.Status == IPStatus.Success,
                reply.Status == IPStatus.Success ? $"{reply.RoundtripTime} ms" : reply.Status.ToString()));
        }
        catch (Exception ex) { r.Steps.Add(new ConnectionStep("Ping", false, ex.Message)); }

        // 3) Ports
        foreach (var port in new[] { 80, 443 })
            r.Steps.Add(new ConnectionStep($"TCP {port}", TcpOpen(server.Fqdn, port, 3000, out var err), err));

        // 4) Remote-PowerShell + Zertifikate
        try
        {
            const string body = """
                $srv = Get-ExchangeServer -Identity $in.Server
                $list = @(Get-ExchangeCertificate -Server $in.Server | ForEach-Object { ConvertTo-CertDto $_ })
                [pscustomobject]@{ Version = "$($srv.AdminDisplayVersion)"; Site = "$($srv.Site)"; Certs = $list }
                """;
            var res = Exec(server, body, new(), TimeSpan.FromMinutes(2), ct);
            r.WorkingPowerShellUri = server.PowerShellUri;
            r.ServerVersion = res?["Version"]?.GetValue<string>();
            var certs = ParseCerts(res?["Certs"]);
            r.CurrentIisCertificate = certs.Where(c => c.HasService("IIS")).OrderByDescending(c => c.NotAfter).FirstOrDefault();
            if (r.ServerVersion != null) server.Version = r.ServerVersion;
            r.Steps.Add(new ConnectionStep("Remote-PowerShell", true, $"{server.PowerShellUri} – {r.ServerVersion}"));
            r.Steps.Add(new ConnectionStep("Zertifikate", true, r.CurrentIisCertificate == null
                ? $"{certs.Count} im Store, keins für IIS aktiv"
                : $"{certs.Count} im Store, IIS: {r.CurrentIisCertificate.Thumbprint} bis {r.CurrentIisCertificate.NotAfter:dd.MM.yyyy}"));
            if (r.CurrentIisCertificate != null)
                server.CurrentCertificate = $"{r.CurrentIisCertificate.Thumbprint} bis {r.CurrentIisCertificate.NotAfter:dd.MM.yyyy}";
        }
        catch (Exception ex)
        {
            r.Steps.Add(new ConnectionStep("Remote-PowerShell", false, Log.Describe(ex)));
        }

        // 5) Was liefert IIS tatsächlich aus?
        try
        {
            var presented = _probe.GetPresentedThumbprint(server.Fqdn, 443, externalHostname, TimeSpan.FromSeconds(8));
            var match = r.CurrentIisCertificate == null || string.Equals(presented, r.CurrentIisCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
            r.Steps.Add(new ConnectionStep("TLS 443", match, match ? presented ?? "" : $"präsentiert {presented}, gebunden {r.CurrentIisCertificate!.Thumbprint}"));
        }
        catch (Exception ex) { r.Steps.Add(new ConnectionStep("TLS 443", false, ex.Message)); }

        Log.Info($"[{name}] Verbindungstest: {r.Summary}");
        return r;
    }

    private static bool TcpOpen(string host, int port, int timeoutMs, out string detail)
    {
        try
        {
            using var c = new TcpClient();
            var ok = c.ConnectAsync(host, port).Wait(timeoutMs) && c.Connected;
            detail = ok ? "offen" : "Timeout";
            return ok;
        }
        catch (Exception ex)
        {
            detail = (ex.InnerException ?? ex).Message;
            return false;
        }
    }

    private static List<ExchangeCertInfo> ParseCerts(JsonNode? node)
    {
        var list = new List<ExchangeCertInfo>();
        if (node is not JsonArray arr)
        {
            // Ein einzelnes Objekt wird von PowerShell 5.1 manchmal nicht als Array serialisiert
            if (node is JsonObject single) arr = new JsonArray(single.DeepClone());
            else return list;
        }
        foreach (var item in arr.OfType<JsonObject>())
        {
            string S(string k) => item[k]?.GetValue<string>() ?? "";
            DateTime D(string k) => DateTime.TryParse(S(k), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d)
                ? d.ToLocalTime() : DateTime.MinValue;

            var domains = item["Domains"] switch
            {
                JsonArray a => a.Select(x => x?.GetValue<string>() ?? "").Where(x => x.Length > 0).ToList(),
                JsonValue v => new List<string> { v.GetValue<string>() },
                _ => new List<string>()
            };
            list.Add(new ExchangeCertInfo(
                S("Thumbprint").ToUpperInvariant(), S("Subject"), S("Issuer"), S("FriendlyName"),
                D("NotBefore"), D("NotAfter"),
                ExchangeCertInfo.ParseServices(S("Services")),
                domains,
                item["HasPrivateKey"]?.GetValue<bool>() ?? false));
        }
        return list;
    }
}
