using Microsoft.Extensions.Configuration;

namespace Rod.Transport.Listeners.WireGuard;

// The optional WireGuard transport's configuration (architecture.md Sec 8,
// Sec 15.3 ADR-004 as amended). The transport is default-disabled; a
// deployment that enables it provisions each listener's static X25519
// server key -- operator-provisioned material, the shape the Pki section
// takes -- and names the native library (ROD_WG_LIB, or the copy beside
// the server binary) to terminate on.

/// <summary>
/// The <c>WireGuard</c> section: the enable switch and the per-listener
/// server keys, keyed by listener id (the Guid as a string).
/// </summary>
internal sealed record WireGuardOptions
{
    /// <summary>
    /// Whether the wireguard transport registers at all. Default false: the
    /// transport does not exist unless a deployment names it, which is the
    /// default-disabled posture the platform's open-not-on rule takes.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Each wireguard listener's static X25519 private key, base64 (32
    /// bytes decoded), keyed by the listener's name -- stable across
    /// restarts on both tiers (a runtime-created listener keeps its name in
    /// the durable record; a startup listener's name is its configuration).
    /// The key is the deployment's own material: generated where the
    /// deployment's other keys are, never minted by the server, and its
    /// public half is what a WireGuard-enabled build bakes as the implant's
    /// peer.
    /// </summary>
    public IReadOnlyDictionary<string, string> ListenerKeys { get; init; }
        = new Dictionary<string, string>();

    /// <summary>
    /// Reads the listener's server private key, or null when the slot is
    /// absent or malformed (not base64, not 32 bytes).
    /// </summary>
    public byte[]? TryPrivateKey(string listenerName)
    {
        if (!ListenerKeys.TryGetValue(listenerName, out var encoded))
            return null;
        try
        {
            var key = Convert.FromBase64String(encoded);
            return key.Length == 32 ? key : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static WireGuardOptions FromConfiguration(IConfiguration? configuration)
    {
        if (configuration is null)
            return new WireGuardOptions();
        var enabled = configuration.GetSection("WireGuard:Enabled").Get<bool>();
        var keys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        configuration.GetSection("WireGuard:ListenerKeys").Bind(keys);
        return new WireGuardOptions { Enabled = enabled, ListenerKeys = keys };
    }
}
