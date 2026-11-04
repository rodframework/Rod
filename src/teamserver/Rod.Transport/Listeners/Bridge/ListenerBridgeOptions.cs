namespace Rod.Transport.Listeners.Bridge;

/// <summary>
/// The listener bridge's deployment knobs (ADR-025): where the per-listener
/// local sockets live. A relative directory names a directory beside the
/// binary, the same base the module store resolves against, so the shipped
/// default lands deterministically no matter the working directory.
/// </summary>
public sealed class ListenerBridgeOptions
{
    public const string SectionName = "Listeners:Bridge";

    /// <summary>
    /// The directory per-listener Unix-domain sockets are created in (a
    /// named pipe on Windows needs no directory; its name is derived from
    /// the listener id alone). The directory is created with user-only
    /// permissions: the bridge is the kernel's own ingress to a child
    /// process, nothing for another local user to reach.
    /// </summary>
    public string SocketDirectory { get; set; } = "listener-bridges";
}
