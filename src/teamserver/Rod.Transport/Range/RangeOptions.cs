using Microsoft.Extensions.Configuration;

namespace Rod.Transport.Range;

/// <summary>
/// Range mode's deployment switch (architecture.md Sec 15.3). Off by default
/// and off in every shipped configuration: a range turns a teamserver into
/// its own implant fleet's operator, which a real deployment wants only when
/// it explicitly asks for it. The pattern follows <c>WireGuard:Enabled</c> --
/// a bool off a configuration section, absent meaning off.
/// </summary>
public sealed record RangeOptions(bool Enabled)
{
    public static RangeOptions FromConfiguration(IConfiguration? configuration)
        => new(configuration?.GetSection("Range:Enabled").Get<bool>() ?? false);
}
