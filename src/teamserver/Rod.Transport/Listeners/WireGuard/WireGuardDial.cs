namespace Rod.Transport.Listeners.WireGuard;

// The wireguard family's baked dial (architecture.md Sec 8): the
// listener's public endpoint completed under wg:// -- the UDP address the
// artifact's tunnel dials. One derivation, shared by the build parser
// (which bakes it and records it on the payload) and the listener's
// restart restore (which matches stored payloads back to the listener
// their artifact dials), so the two can never disagree on the shape.

/// <summary>The wg:// dial of one wireguard listener's public endpoint.</summary>
internal static class WireGuardDial
{
    public static string Of(Listener listener)
    {
        var trimmed = listener.PublicEndpoint.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var dial) && dial.Scheme == "wg")
            return trimmed;
        return $"wg://{trimmed}";
    }
}
