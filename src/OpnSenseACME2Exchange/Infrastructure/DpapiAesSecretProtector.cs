using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using OpnSenseACME2Exchange.Core.Config;

namespace OpnSenseACME2Exchange.Infrastructure;

/// <summary>
/// AES-256-GCM mit zufälligem Master-Key. Der Master-Key liegt DPAPI-geschützt (LocalMachine-Scope + Entropy)
/// in key.bin; die Datei ist per ACL auf SYSTEM, Administratoren und den anlegenden Benutzer beschränkt.
/// Damit können GUI und geplante Aufgabe (anderer Benutzer, gleiche Maschine) dieselbe Konfiguration lesen.
/// </summary>
public sealed class DpapiAesSecretProtector : ISecretProtector
{
    private const string Prefix = "v1:";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("OpnSenseACME2Exchange/MasterKey/v1");
    private readonly string _keyPath;
    private byte[]? _key;

    public DpapiAesSecretProtector(string keyPath) => _keyPath = keyPath;

    private byte[] Key => _key ??= LoadOrCreateKey();

    private byte[] LoadOrCreateKey()
    {
        if (File.Exists(_keyPath))
            return ProtectedData.Unprotect(File.ReadAllBytes(_keyPath), Entropy, DataProtectionScope.LocalMachine);

        var key = RandomNumberGenerator.GetBytes(32);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_keyPath))!);
        File.WriteAllBytes(_keyPath, ProtectedData.Protect(key, Entropy, DataProtectionScope.LocalMachine));
        TryRestrictAcl(_keyPath);
        return key;
    }

    private static void TryRestrictAcl(string path)
    {
        try
        {
            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var full = FileSystemRights.FullControl;
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), full, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), full, AccessControlType.Allow));
            var me = WindowsIdentity.GetCurrent().User;
            if (me != null) sec.AddAccessRule(new FileSystemAccessRule(me, full, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(sec);
        }
        catch
        {
            // ACL ist Härtung, kein Muss (z.B. auf FAT/Netzlaufwerk)
        }
    }

    public string Protect(string plain)
    {
        var data = Encoding.UTF8.GetBytes(plain);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[data.Length];
        using (var gcm = new AesGcm(Key, 16)) gcm.Encrypt(nonce, data, cipher, tag);
        CryptographicOperations.ZeroMemory(data);

        var buf = new byte[nonce.Length + tag.Length + cipher.Length];
        nonce.CopyTo(buf, 0);
        tag.CopyTo(buf, 12);
        cipher.CopyTo(buf, 28);
        return Prefix + Convert.ToBase64String(buf);
    }

    public string Unprotect(string protectedValue)
    {
        if (!protectedValue.StartsWith(Prefix, StringComparison.Ordinal))
            throw new CryptographicException("Unbekanntes Format für geschützte Daten.");
        var buf = Convert.FromBase64String(protectedValue[Prefix.Length..]);
        if (buf.Length < 28) throw new CryptographicException("Geschützte Daten beschädigt.");

        var plain = new byte[buf.Length - 28];
        using (var gcm = new AesGcm(Key, 16))
            gcm.Decrypt(buf.AsSpan(0, 12), buf.AsSpan(28), buf.AsSpan(12, 16), plain);
        var s = Encoding.UTF8.GetString(plain);
        CryptographicOperations.ZeroMemory(plain);
        return s;
    }
}
