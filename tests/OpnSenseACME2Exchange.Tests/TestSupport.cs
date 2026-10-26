using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using OpnSenseACME2Exchange.Core.Config;
using OpnSenseACME2Exchange.Core.Exchange;
using OpnSenseACME2Exchange.Core.Net;
using OpnSenseACME2Exchange.Core.OpnSense;

namespace OpnSenseACME2Exchange.Tests;

public static class Assert
{
    public static void True(bool cond, string msg) { if (!cond) throw new Exception("Erwartet true: " + msg); }
    public static void False(bool cond, string msg) { if (cond) throw new Exception("Erwartet false: " + msg); }
    public static void Equal<T>(T expected, T actual, string msg)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"{msg}: erwartet '{expected}', war '{actual}'");
    }
    public static void Throws<TEx>(Action a, string msg) where TEx : Exception
    {
        try { a(); }
        catch (TEx) { return; }
        catch (Exception ex) { throw new Exception($"{msg}: falsche Exception {ex.GetType().Name}"); }
        throw new Exception($"{msg}: keine Exception");
    }
}

/// <summary>Erzeugt eine realistische Kette: Root → Intermediate → Leaf.</summary>
public sealed class TestPki
{
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _intermediate;
    private readonly RSA _intKey;

    public TestPki()
    {
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _root = rootReq.CreateSelfSigned(DateTimeOffset.Now.AddYears(-1), DateTimeOffset.Now.AddYears(5));

        var intKey = _intKey = RSA.Create(2048);
        var intReq = new CertificateRequest("CN=Test Intermediate R1", intKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intPub = intReq.Create(_root, DateTimeOffset.Now.AddMonths(-6), DateTimeOffset.Now.AddYears(3), Serial());
        _intermediate = intPub.CopyWithPrivateKey(intKey);
    }

    public string IntermediatePem => _intermediate.ExportCertificatePem();

    private static byte[] Serial() => RandomNumberGenerator.GetBytes(12);

    public (string Pem, string Thumbprint) Leaf(string[] dnsNames, DateTimeOffset notBefore, DateTimeOffset notAfter,
        bool ecdsa = false, bool includeKey = true, bool keyFirst = false)
    {
        AsymmetricAlgorithm key = ecdsa ? ECDsa.Create(ECCurve.NamedCurves.nistP384) : RSA.Create(2048);
        CertificateRequest req = key is RSA r
            ? new CertificateRequest("CN=" + dnsNames[0], r, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new CertificateRequest("CN=" + dnsNames[0], (ECDsa)key, HashAlgorithmName.SHA256);

        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in dnsNames) san.AddDnsName(n);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

        // EC-Leaf mit RSA-Issuer braucht einen expliziten Signaturgenerator
        using var cert = key is RSA
            ? req.Create(_intermediate, notBefore, notAfter, Serial())
            : req.Create(_intermediate.SubjectName, X509SignatureGenerator.CreateForRSA(_intKey, RSASignaturePadding.Pkcs1), notBefore, notAfter, Serial());
        var keyPem = key is RSA rsa ? rsa.ExportPkcs8PrivateKeyPem() : ((ECDsa)key).ExportPkcs8PrivateKeyPem();
        key.Dispose();

        var sb = new StringBuilder();
        if (includeKey && keyFirst) sb.AppendLine(keyPem);
        sb.AppendLine(cert.ExportCertificatePem());
        sb.AppendLine(IntermediatePem);
        if (includeKey && !keyFirst) sb.AppendLine(keyPem);
        return (sb.ToString(), cert.Thumbprint.ToUpperInvariant());
    }
}

/// <summary>Simuliert OPNsense-Knoten (Dateisystem + ein paar Befehle).</summary>
public sealed class FakeOpnSense : ISshSessionFactory
{
    public Dictionary<string, Dictionary<string, string>> Files { get; } = new();
    public Dictionary<string, string> CarpOutput { get; } = new();
    public HashSet<string> Down { get; } = new();
    public List<string> Commands { get; } = new();

    public ISshSession Open(OpnSenseNode node)
    {
        if (Down.Contains(node.Host)) throw new IOException($"Connection refused {node.Host}");
        return new Session(this, node.Host);
    }

    private sealed class Session(FakeOpnSense owner, string host) : ISshSession
    {
        public SshResult Run(string command, TimeSpan timeout)
        {
            owner.Commands.Add($"{host}: {command}");
            var cmd = command.StartsWith("sudo -n ") ? command[8..] : command;
            var files = owner.Files.TryGetValue(host, out var f) ? f : new Dictionary<string, string>();

            if (cmd.StartsWith("cat -- '"))
            {
                var path = cmd[8..^1];
                return files.TryGetValue(path, out var c) ? new SshResult(0, c, "") : new SshResult(1, "", "No such file");
            }
            if (cmd.StartsWith("find '"))
            {
                var dir = cmd[6..cmd.IndexOf('\'', 6)];
                var list = files.Keys.Where(k => k.StartsWith(dir + "/") && k.EndsWith(".pem"));
                return new SshResult(0, string.Join("\n", list), "");
            }
            if (cmd.StartsWith("opnsense-version")) return new SshResult(0, "OPNsense 26.7.4", "");
            if (cmd.StartsWith("ifconfig")) return new SshResult(0, owner.CarpOutput.GetValueOrDefault(host, ""), "");
            if (cmd.StartsWith("pgrep")) return new SshResult(0, "RUNNING", "");
            if (cmd.StartsWith("test -r")) return new SshResult(0, "OK", "");
            return new SshResult(127, "", "unknown command");
        }

        public void Dispose() { }
    }
}

/// <summary>Simuliert Exchange-Server: Zertifikatsspeicher + Dienstbindungen (IIS kann nur an einem Zertifikat hängen).</summary>
public sealed class FakeExchange : IExchangeOperations, ITlsProbe
{
    public Dictionary<string, List<ExchangeCertInfo>> Stores { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Broken { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> StaleIis { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ImportThrowsButSucceeds { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Calls { get; } = new();

    private List<ExchangeCertInfo> Store(ExchangeServerEntry s)
    {
        if (Broken.Contains(s.Fqdn)) throw new InvalidOperationException("WinRM nicht erreichbar");
        if (!Stores.TryGetValue(s.Fqdn, out var list)) Stores[s.Fqdn] = list = new List<ExchangeCertInfo>();
        return list;
    }

    public ConnectionTestResult TestConnection(ExchangeServerEntry server, string externalHostname, CancellationToken ct) => new();

    public IReadOnlyList<ExchangeCertInfo> GetCertificates(ExchangeServerEntry server, CancellationToken ct)
    {
        Calls.Add($"Get {server.Fqdn}");
        return Store(server).ToList();
    }

    public string ImportCertificate(ExchangeServerEntry server, byte[] pfx, string password, bool exportable, CancellationToken ct)
    {
        Calls.Add($"Import {server.Fqdn}");
        var col = X509CertificateLoader.LoadPkcs12Collection(pfx, password);
        var leaf = col.First(c => c.HasPrivateKey);
        var names = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToList();
        Store(server).Add(new ExchangeCertInfo(leaf.Thumbprint.ToUpperInvariant(), leaf.Subject, leaf.Issuer, null,
            leaf.NotBefore, leaf.NotAfter, Array.Empty<string>(), names, true));
        if (ImportThrowsButSucceeds.Remove(server.Fqdn)) throw new TimeoutException("Remote-Session getrennt");
        return leaf.Thumbprint.ToUpperInvariant();
    }

    public void EnableCertificate(ExchangeServerEntry server, string thumbprint, string services, CancellationToken ct)
    {
        Calls.Add($"Enable {server.Fqdn} {services}");
        var store = Store(server);
        var svc = ExchangeCertInfo.ParseServices(services);
        for (int i = 0; i < store.Count; i++)
        {
            var c = store[i];
            if (c.Thumbprint == thumbprint)
                store[i] = c with { Services = c.Services.Union(svc).ToList() };
            else
                store[i] = c with { Services = c.Services.Where(s => !(s == "IIS" && svc.Contains("IIS"))).ToList() };
        }
        StaleIis.Remove(server.Fqdn);
    }

    public void RemoveCertificate(ExchangeServerEntry server, string thumbprint, CancellationToken ct)
    {
        Calls.Add($"Remove {server.Fqdn} {thumbprint}");
        Store(server).RemoveAll(c => c.Thumbprint == thumbprint);
    }

    public void IisReset(ExchangeServerEntry server, CancellationToken ct) => Calls.Add($"IisReset {server.Fqdn}");

    public string? PresentedOverride { get; set; }

    public string? GetPresentedThumbprint(string host, int port, string sniHost, TimeSpan timeout)
    {
        if (PresentedOverride != null) return PresentedOverride;
        if (StaleIis.Contains(host)) return "STALE000000000000000000000000000000000000";
        return Stores.TryGetValue(host, out var l) ? l.FirstOrDefault(c => c.HasService("IIS"))?.Thumbprint : null;
    }
}
