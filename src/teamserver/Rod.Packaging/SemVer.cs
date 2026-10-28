namespace Rod.Packaging;

/// <summary>
/// A SemVer 2.0 version restricted to what the module ecosystem needs:
/// core triple plus an optional prerelease, build metadata ignored. The
/// manifest, the registry entry, and the lock all carry versions as these
/// (architecture.md Sec 15.2), and the compatibility check is a plain
/// ordered comparison against one.
/// </summary>
public readonly record struct SemVer(int Major, int Minor, int Patch, string? Prerelease)
    : IComparable<SemVer>
{
    /// <summary>Parses <c>M.m.p</c> or <c>M.m.p-pre</c>; build metadata (<c>+…</c>) is accepted and dropped.</summary>
    public static bool TryParse(string text, out SemVer version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var span = text.AsSpan();
        var plus = span.IndexOf('+');
        if (plus >= 0)
            span = span[..plus];

        var dash = span.IndexOf('-');
        var core = dash >= 0 ? span[..dash] : span;
        var pre = dash >= 0 ? span[(dash + 1)..] : Span<char>.Empty;
        // A trailing dash is a malformed prerelease, not a release.
        if (dash >= 0 && pre.IsEmpty)
            return false;

        var parts = core.ToString().Split('.', 3);
        if (parts.Length is not 3)
            return false;
        if (!int.TryParse(parts[0], out var major) || major < 0
            || !int.TryParse(parts[1], out var minor) || minor < 0
            || !int.TryParse(parts[2], out var patch) || patch < 0)
            return false;

        // Leading zeros are a SemVer violation and a quiet typo source in
        // compatibility floors, so they parse as invalid.
        foreach (var part in parts)
        {
            if (part.Length > 1 && part[0] == '0')
                return false;
        }

        var prerelease = pre.IsEmpty ? null : pre.ToString();
        if (prerelease is not null && !PrereleaseValid(prerelease))
            return false;

        version = new SemVer(major, minor, patch, prerelease);
        return true;
    }

    public static SemVer Parse(string text)
        => TryParse(text, out var version)
            ? version
            : throw new FormatException($"'{text}' is not a SemVer version (M.m.p[-pre]).");

    private static bool PrereleaseValid(string prerelease)
    {
        if (prerelease.Length == 0)
            return false;
        foreach (var identifier in prerelease.Split('.'))
        {
            if (identifier.Length == 0)
                return false;
            var numeric = true;
            foreach (var c in identifier)
            {
                if (c is >= '0' and <= '9')
                    continue;
                numeric = false;
                if (c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '-')
                    continue;
                return false;
            }

            if (numeric && identifier.Length > 1 && identifier[0] == '0')
                return false;
        }
        return true;
    }

    public int CompareTo(SemVer other)
    {
        var core = Major.CompareTo(other.Major);
        if (core != 0) return core;
        core = Minor.CompareTo(other.Minor);
        if (core != 0) return core;
        core = Patch.CompareTo(other.Patch);
        if (core != 0) return core;

        // A release outranks any prerelease of the same triple; otherwise
        // prerelease identifiers compare per SemVer 2.0 (numeric below
        // alphanumeric, longer set wins on a tie prefix).
        if (Prerelease is null && other.Prerelease is null) return 0;
        if (Prerelease is null) return 1;
        if (other.Prerelease is null) return -1;

        var left = Prerelease.Split('.');
        var right = other.Prerelease.Split('.');
        for (var i = 0; i < Math.Min(left.Length, right.Length); i++)
        {
            var lNum = long.TryParse(left[i], out var l);
            var rNum = long.TryParse(right[i], out var r);
            if (lNum && rNum)
            {
                if (l != r) return l.CompareTo(r);
            }
            else
            {
                var order = string.CompareOrdinal(left[i], right[i]);
                if (order != 0) return order;
            }
        }
        return left.Length.CompareTo(right.Length);
    }

    public override string ToString()
        => Prerelease is null ? $"{Major}.{Minor}.{Patch}" : $"{Major}.{Minor}.{Patch}-{Prerelease}";
}
