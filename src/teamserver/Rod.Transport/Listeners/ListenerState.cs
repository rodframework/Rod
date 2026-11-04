namespace Rod.Transport.Listeners;

/// <summary>
/// Where a <see cref="Listener"/> sits in its lifecycle. Listeners are bound at
/// host startup and repointed in place (architecture.md Sec 8), so the registry
/// only ever observes the terminal states: the host marks a listener Running
/// once its endpoint is bound, and a listener is removed rather than stopped.
/// The one runtime transition is the supervised process's health (ADR-025):
/// a dead listener process marks its listener Unhealthy -- the kernel keeps
/// serving, the supervisor restarts, and the state returns to Running.
/// </summary>
public enum ListenerState
{
    /// <summary>Configured but not yet bound by the host.</summary>
    Stopped,

    /// <summary>The socket is open and accepting implant connections.</summary>
    Running,

    /// <summary>
    /// The listener's supervised process is down (ADR-025): its exit marked
    /// the listener unhealthy while the supervisor's restart schedule waits.
    /// The kernel process is untouched -- no session lived in the child -- so
    /// this state costs an outage window, never a kernel one.
    /// </summary>
    Unhealthy,
}
