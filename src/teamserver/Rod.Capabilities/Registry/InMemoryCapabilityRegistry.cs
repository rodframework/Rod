using System.Collections.Concurrent;
using Rod.Capabilities.Modules;
using Rod.CoreState.Implants;

namespace Rod.Capabilities.Registry;

/// <summary>
/// The default in-memory <see cref="ICapabilityRegistry"/>
/// (architecture.md Sec 4.1 layer 6). Backed by a concurrent dictionary keyed by
/// verb (case-insensitive); insertion order is preserved separately so
/// <see cref="ListAsync"/> reflects registration order despite the dictionary's
/// unordered enumeration.
/// </summary>
/// <remarks>
/// Single-process by design: the teamserver is a monolithic kernel
/// (architecture.md Sec 4), so an in-process registry is sufficient until a
/// durable store is warranted. All operations are allocation-free on the hot
/// read path (<see cref="FindAsync"/> is a dictionary lookup).
/// </remarks>
public sealed class InMemoryCapabilityRegistry : ICapabilityRegistry
{
    // Verb (case-insensitive) -> the module registered for it. A later
    // registration replaces the prior entry, so the last module loaded for a
    // verb is the authority.
    private readonly ConcurrentDictionary<string, ICapabilityModule> _byVerb = new(StringComparer.OrdinalIgnoreCase);

    // Registration order, distinct, so ListAsync is stable and deduplicated when
    // a re-registration replaces a verb. Guarded by a lock since ConcurrentDictionary
    // does not preserve insertion order.
    private readonly List<ICapabilityModule> _ordered = new();
    private readonly object _orderLock = new();

    public Task RegisterAsync(ICapabilityModule module, CancellationToken cancellationToken = default)
    {
        // A malformed parameter schema is a registration failure, not a
        // catalog quirk: the UI renders the schema it is handed, so a form
        // that cannot render is a verb the operator cannot task. Loud at
        // startup, where every other misconfiguration already lands.
        var schemaErrors = module.Descriptor.ValidateParameters();
        if (schemaErrors.Count > 0)
        {
            throw new InvalidOperationException(
                $"capability module for '{module.Descriptor.Verb}' declares an invalid parameter schema: "
                + string.Join(" ", schemaErrors));
        }

        // The ATT&CK declaration rides the same rule (ADR-007): the matrix and
        // the Navigator layer render these ids verbatim, so a malformed one is
        // a registration failure too.
        var techniqueErrors = module.Descriptor.ValidateTechniques();
        if (techniqueErrors.Count > 0)
        {
            throw new InvalidOperationException(
                $"capability module for '{module.Descriptor.Verb}' declares an invalid ATT&CK mapping: "
                + string.Join(" ", techniqueErrors));
        }

        // The requirement rows ride it too (ADR-017): the runtime gate matches
        // these names against the closed vocabulary, so an unknown one is a
        // registration failure -- a typo must never silently skip the gate the
        // way the manifest loader refuses the same typo at publish.
        if (module.Requires is { } requires)
        {
            foreach (var name in requires)
            {
                if (!WireCapabilities.IsRequirable(name))
                {
                    throw new InvalidOperationException(
                        $"capability module for '{module.Descriptor.Verb}' requires '{name}', which is not "
                        + "a wire capability a module may require; the vocabulary is: "
                        + string.Join(", ", WireCapabilities.Requirable) + ".");
                }
            }
        }

        var verb = module.Descriptor.Verb;
        _byVerb[verb] = module;

        lock (_orderLock)
        {
            // Drop any prior entry for this verb first, then append, so the list
            // stays deduplicated and the latest registration is last.
            for (var i = _ordered.Count - 1; i >= 0; i--)
            {
                if (string.Equals(_ordered[i].Descriptor.Verb, verb, StringComparison.OrdinalIgnoreCase))
                    _ordered.RemoveAt(i);
            }
            _ordered.Add(module);
        }

        return Task.CompletedTask;
    }

    public Task<ICapabilityModule?> FindAsync(string verb, CancellationToken cancellationToken = default)
        => Task.FromResult(_byVerb.TryGetValue(verb, out var module) ? module : null);

    public Task<ICapabilityModule?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        // The name index is a scan, not a dictionary: names are display
        // metadata most modules do not carry, so a second concurrent map for
        // the handful that do costs more than the rare module.load-time scan
        // through the ordered list.
        if (string.IsNullOrWhiteSpace(name))
            return Task.FromResult<ICapabilityModule?>(null);

        lock (_orderLock)
        {
            ICapabilityModule? found = null;
            foreach (var module in _ordered)
            {
                if (string.Equals(module.Name, name, StringComparison.OrdinalIgnoreCase))
                    found = module;
            }

            // Last registration wins here too, mirroring the verb index's
            // authority rule: a module re-registered under the same name is
            // the one the runtime gate should read.
            return Task.FromResult(found);
        }
    }

    public Task<IReadOnlyList<CapabilityDescriptor>> ListAsync(CancellationToken cancellationToken = default)
    {
        lock (_orderLock)
        {
            return Task.FromResult<IReadOnlyList<CapabilityDescriptor>>(
                _ordered.Select(m => m.Descriptor).ToArray());
        }
    }

    public Task<IReadOnlyList<ICapabilityModule>> ListModulesAsync(CancellationToken cancellationToken = default)
    {
        lock (_orderLock)
        {
            return Task.FromResult<IReadOnlyList<ICapabilityModule>>(_ordered.ToArray());
        }
    }
}
