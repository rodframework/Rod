using Rod.Packaging;
namespace Rod.Cli.Tests;

public class SemVerTests
{
    [Theory]
    [InlineData("1.0.0", true)]
    [InlineData("0.1.0", true)]
    [InlineData("10.20.30", true)]
    [InlineData("1.0.0-dev", true)]
    [InlineData("1.0.0-dev.2+build.5", true)] // build metadata accepted, dropped
    [InlineData("1.0", false)]
    [InlineData("1.0.0.0", false)]
    [InlineData("01.0.0", false)] // leading zero is a violation and a typo source
    [InlineData("1.0.0-", false)]
    [InlineData("v1.0.0", false)]
    [InlineData("", false)]
    public void Parsing_FollowsTheNeededSubsetOfSemVer(string text, bool valid)
        => Assert.Equal(valid, SemVer.TryParse(text, out _));

    [Fact]
    public void Comparison_OrdersCoreThenPrerelease()
    {
        var ordered = new[]
        {
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        }.Select(SemVer.Parse).ToList();

        for (var i = 1; i < ordered.Count; i++)
        {
            Assert.True(ordered[i - 1].CompareTo(ordered[i]) < 0,
                $"{ordered[i - 1]} must sort below {ordered[i]} (the SemVer 2.0 ordering).");
        }
    }

    [Fact]
    public void APrereleaseFloor_RejectsTheMatchingRelease()
    {
        // The compatibility direction that matters: a module demanding
        // 1.0.0 refuses a 1.0.0-dev teamserver (the stamp a development
        // tree carries), so a dev CLI cannot quietly satisfy a release floor.
        var floor = SemVer.Parse("1.0.0");
        var dev = SemVer.Parse("1.0.0-dev");
        Assert.True(floor.CompareTo(dev) > 0);
    }
}
