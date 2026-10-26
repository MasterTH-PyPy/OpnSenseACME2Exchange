using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace OpnSenseACME2Exchange.Core.Net;

public interface ITlsProbe
{
    /// <summary>Liefert den Thumbprint des Zertifikats, das der Server präsentiert (ohne Vertrauensprüfung).</summary>
    string? GetPresentedThumbprint(string host, int port, string sniHost, TimeSpan timeout);
}

public sealed class TlsProbe : ITlsProbe
{
    public string? GetPresentedThumbprint(string host, int port, string sniHost, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        using var tcp = new TcpClient();
        tcp.ConnectAsync(host, port, cts.Token).AsTask().GetAwaiter().GetResult();

        string? thumb = null;
        using var ssl = new SslStream(tcp.GetStream(), false, (_, cert, _, _) =>
        {
            if (cert != null)
            {
                using var c2 = new X509Certificate2(cert);
                thumb = c2.Thumbprint.ToUpperInvariant();
            }
            return true; // nur auslesen, nicht vertrauen
        });

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = string.IsNullOrWhiteSpace(sniHost) ? host : sniHost,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };
        ssl.AuthenticateAsClientAsync(options, cts.Token).GetAwaiter().GetResult();
        return thumb;
    }
}
