using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpnSenseACME2Exchange.Core.Certificates;

public static class HostMatcher
{
    /// <summary>
    /// RFC-6125-artiger Vergleich: exakt oder Wildcard über genau ein Label ("*.example.de" ⇒ "mail.example.de").
    /// HAProxy-Domainmuster ".example.de" gelten als Suffix.
    /// </summary>
    public static bool Matches(string pattern, string host)
    {
        if (string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(host)) return false;
        pattern = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        host = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (pattern == host) return true;
        if (pattern.StartsWith("*."))
        {
            var suffix = pattern[1..]; // ".example.de"
            if (!host.EndsWith(suffix, StringComparison.Ordinal)) return false;
            var label = host[..^suffix.Length];
            return label.Length > 0 && !label.Contains('.');
        }
        if (pattern.StartsWith('.'))
            return host.EndsWith(pattern, StringComparison.Ordinal) || host == pattern[1..];
        return false;
    }

    public static bool Covers(IEnumerable<string> dnsNames, string host) => dnsNames.Any(n => Matches(n, host));
}

public sealed record CertificateInfo(
    string Subject,
    string Issuer,
    string Thumbprint,
    string SerialNumber,
    DateTime NotBefore,
    DateTime NotAfter,
    IReadOnlyList<string> DnsNames,
    string KeyAlgorithm,
    bool HasPrivateKey,
    int ChainCount)
{
    public bool Covers(string host) => HostMatcher.Covers(DnsNames, host);
    public bool IsEcdsa => KeyAlgorithm.StartsWith("ECDSA", StringComparison.OrdinalIgnoreCase);
    public string ShortDescription => $"{Subject} | gültig bis {NotAfter:dd.MM.yyyy HH:mm} | {Thumbprint}";
}

/// <summary>
/// Ein Zertifikat aus einer PEM-Datei der OPNsense (HAProxy-Format: Zertifikat + Kette + Private Key).
/// Der Private Key wird nur im Speicher gehalten und nie geloggt.
/// </summary>
public sealed class CertificateBundle : IDisposable
{
    private readonly AsymmetricAlgorithm? _key;

    private CertificateBundle(X509Certificate2 leaf, List<X509Certificate2> chain, AsymmetricAlgorithm? key, string source)
    {
        Leaf = leaf;
        Chain = chain;
        _key = key;
        Source = source;
        Info = Describe(leaf, key != null, chain.Count);
    }

    public X509Certificate2 Leaf { get; }
    public IReadOnlyList<X509Certificate2> Chain { get; }
    public CertificateInfo Info { get; }
    public string Source { get; }
    public bool HasPrivateKey => _key != null;

    public static CertificateBundle Parse(string pemText, string source)
    {
        var certs = new List<X509Certificate2>();
        AsymmetricAlgorithm? key = null;

        ReadOnlySpan<char> data = pemText.AsSpan();
        while (PemEncoding.TryFind(data, out var fields))
        {
            var label = data[fields.Label].ToString();
            var block = data[fields.Location].ToString();
            switch (label)
            {
                case "CERTIFICATE":
                    var der = Convert.FromBase64String(data[fields.Base64Data].ToString());
                    certs.Add(X509CertificateLoader.LoadCertificate(der));
                    break;
                case "PRIVATE KEY":
                case "RSA PRIVATE KEY":
                case "EC PRIVATE KEY":
                    key ??= LoadKey(block);
                    break;
                case "ENCRYPTED PRIVATE KEY":
                    throw new CryptographicException($"{source}: verschlüsselter Private Key wird nicht unterstützt.");
            }
            data = data[fields.Location.End..];
        }

        if (certs.Count == 0)
            throw new CryptographicException($"{source}: keine Zertifikate in der Datei gefunden.");

        X509Certificate2? leaf = null;
        if (key != null)
        {
            var keySpki = key switch
            {
                RSA r => r.ExportSubjectPublicKeyInfo(),
                ECDsa e => e.ExportSubjectPublicKeyInfo(),
                _ => Array.Empty<byte>()
            };
            leaf = certs.FirstOrDefault(c => c.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(keySpki));
            if (leaf == null)
                throw new CryptographicException($"{source}: Private Key passt zu keinem enthaltenen Zertifikat.");
        }
        leaf ??= certs.FirstOrDefault(c => !IsCa(c)) ?? certs[0];

        var chain = certs.Where(c => !ReferenceEquals(c, leaf)).ToList();
        return new CertificateBundle(leaf, chain, key, source);
    }

    private static AsymmetricAlgorithm LoadKey(string pem)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception) { /* kein RSA */ }

        try
        {
            var ec = ECDsa.Create();
            ec.ImportFromPem(pem);
            return ec;
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Private Key konnte nicht gelesen werden (weder RSA noch ECDSA).", ex);
        }
    }

    private static bool IsCa(X509Certificate2 c) =>
        c.Extensions.OfType<X509BasicConstraintsExtension>().Any(b => b.CertificateAuthority);

    public static CertificateInfo Describe(X509Certificate2 cert, bool hasKey, int chainCount)
    {
        var names = new List<string>();
        foreach (var san in cert.Extensions.OfType<X509SubjectAlternativeNameExtension>())
            names.AddRange(san.EnumerateDnsNames());
        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
        if (names.Count == 0 && !string.IsNullOrWhiteSpace(cn)) names.Add(cn);

        string alg;
        using (var rsa = cert.GetRSAPublicKey())
        using (var ec = rsa == null ? cert.GetECDsaPublicKey() : null)
        {
            alg = rsa != null ? $"RSA {rsa.KeySize}"
                : ec != null ? $"ECDSA {ec.KeySize}"
                : cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unbekannt";
        }

        return new CertificateInfo(
            cert.Subject,
            cert.Issuer,
            cert.Thumbprint.ToUpperInvariant(),
            cert.SerialNumber,
            cert.NotBefore,
            cert.NotAfter,
            names.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            alg,
            hasKey,
            chainCount);
    }

    /// <summary>
    /// Baut eine PFX (Zertifikat + Private Key + Kette) für Import-ExchangeCertificate.
    /// TripleDES/SHA1 als PBE, damit auch ältere Windows-Server-Versionen die Datei importieren.
    /// </summary>
    public byte[] ExportPfx(string password)
    {
        if (_key == null) throw new InvalidOperationException("Kein Private Key vorhanden – PFX nicht möglich.");

        using var withKey = _key switch
        {
            RSA r => Leaf.CopyWithPrivateKey(r),
            ECDsa e => Leaf.CopyWithPrivateKey(e),
            _ => throw new NotSupportedException("Schlüsseltyp nicht unterstützt.")
        };

        var collection = new X509Certificate2Collection { withKey };
        foreach (var c in Chain) collection.Add(c);
        return collection.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, password);
    }

    public static string GeneratePassword(int length = 32) =>
        RandomNumberGenerator.GetString("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!$%&*+-_=", length);

    public void Dispose()
    {
        _key?.Dispose();
        Leaf.Dispose();
        foreach (var c in Chain) c.Dispose();
    }
}

public static class CertificateValidator
{
    public sealed record Result(List<string> Errors, List<string> Warnings)
    {
        public bool Ok => Errors.Count == 0;
    }

    public static Result Validate(CertificateInfo info, IEnumerable<string> requiredNames, DateTime now)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (!info.HasPrivateKey) errors.Add("Kein Private Key in der PEM-Datei.");
        if (now < info.NotBefore) errors.Add($"Zertifikat ist erst ab {info.NotBefore:dd.MM.yyyy HH:mm} gültig.");
        if (now > info.NotAfter) errors.Add($"Zertifikat ist seit {info.NotAfter:dd.MM.yyyy HH:mm} abgelaufen.");

        foreach (var name in requiredNames.Where(n => !string.IsNullOrWhiteSpace(n)))
            if (!info.Covers(name)) errors.Add($"Zertifikat deckt '{name}' nicht ab (SAN: {string.Join(", ", info.DnsNames)}).");

        if (errors.Count == 0 && (info.NotAfter - now).TotalDays < 7)
            warnings.Add($"Zertifikat läuft in {(info.NotAfter - now).TotalDays:0.#} Tagen ab – ACME-Erneuerung auf der OPNsense prüfen.");
        if (info.IsEcdsa)
            warnings.Add("ECDSA-Schlüssel: Exchange unterstützt ECC-Zertifikate nur eingeschränkt bzw. erst nach Aktivierung. Für Exchange im ACME-Client möglichst RSA (2048/4096) wählen.");
        if (info.ChainCount == 0)
            warnings.Add("Keine Zwischenzertifikate in der PEM-Datei – Kette muss auf den Exchange-Servern bereits vorhanden sein.");

        return new Result(errors, warnings);
    }
}
