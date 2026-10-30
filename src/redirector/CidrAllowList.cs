using System.Net;

namespace Rod.Redirector;

/// <summary>
/// An IPv4/IPv6 source-address allow-list parsed from CIDR notation
/// (architecture.md Sec 8, ADR 0011). An empty list allows every source -- the
/// redirector is typically fronted by a VPS firewall and the real identity gate
/// is the teamserver's mTLS handshake (architecture.md Sec 9), so the allow-list
/// is a deployment-time tightening, not the security boundary. This is the only
/// filtering an opaque L4 forwarder can do without terminating transport; the
/// malleable User-Agent/URI routing of Sec 7 is a TLS-terminating-edge concern.
/// </summary>
internal sealed class CidrAllowList
{
    /// <summary>The permissive default: no CIDRs means allow every source.</summary>
    public static CidrAllowList AllowAll { get; } = new(Array.Empty<IPNetwork>());

    private readonly IPNetwork[] _networks;

    private CidrAllowList(IPNetwork[] networks) => _networks = networks;

    /// <summary>
    /// True when <paramref name="address"/> falls in any CIDR, or when the list
    /// is empty (the default, which allows everything).
    /// </summary>
    public bool Allows(IPAddress address)
    {
        if (_networks.Length == 0)
            return true;

        foreach (var network in _networks)
        {
            if (network.Contains(address))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Parses comma- and whitespace-separated CIDRs ("10.0.0.0/8, 192.168.0.0/16")
    /// into an allow-list. A null or empty input yields <see cref="AllowAll"/>. Each
    /// token must be valid CIDR notation (IPv4 or IPv6); a malformed token throws
    /// <see cref="ArgumentException"/> so config validation can surface it cleanly.
    /// </summary>
    public static CidrAllowList Parse(IEnumerable<string?>? raw)
    {
        var networks = new List<IPNetwork>();
        foreach (var token in Tokens(raw))
        {
            if (!IPNetwork.TryParse(token, out var network))
                throw new ArgumentException($"'{token}' is not valid CIDR notation.");
            networks.Add(network);
        }

        return networks.Count == 0 ? AllowAll : new CidrAllowList(networks.ToArray());
    }

    private static IEnumerable<string> Tokens(IEnumerable<string?>? raw)
    {
        if (raw is null)
            yield break;

        foreach (var entry in raw)
        {
            if (entry is null || entry.Length == 0)
                continue;
            foreach (var piece in entry.Split(
                         ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                yield return piece;
            }
        }
    }
}
