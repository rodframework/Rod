using System.Net;
using Rod.Redirector;

namespace Rod.Redirector.Tests;

public class ConfigTests
{
    [Fact]
    public void Parses_Required_Flags_And_Defaults_Allow_All()
    {
        var config = RedirectorConfig.Parse(new[] { "-listen", "127.0.0.1:8000", "-upstream", "teamserver:9000" });

        Assert.Equal("127.0.0.1", config.ListenHost);
        Assert.Equal(8000, config.ListenPort);
        Assert.Equal("teamserver", config.UpstreamHost);
        Assert.Equal(9000, config.UpstreamPort);
        Assert.Same(CidrAllowList.AllowAll, config.Allow);
    }

    [Fact]
    public void Long_Form_Flags_Work()
    {
        var config = RedirectorConfig.Parse(new[] { "--listen", "*:8000", "--upstream", "up:9000" });

        Assert.Equal(IPAddress.Any, config.ListenAddress);
        Assert.Equal(8000, config.ListenPort);
        Assert.Equal(9000, config.UpstreamPort);
    }

    [Fact]
    public void Env_Provides_Defaults()
    {
        Environment.SetEnvironmentVariable("ROD_LISTEN", "*:7000");
        Environment.SetEnvironmentVariable("ROD_UPSTREAM", "upstream:9000");
        try
        {
            var config = RedirectorConfig.Parse(Array.Empty<string>());
            Assert.Equal(7000, config.ListenPort);
            Assert.Equal("upstream", config.UpstreamHost);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ROD_LISTEN", null);
            Environment.SetEnvironmentVariable("ROD_UPSTREAM", null);
        }
    }

    [Fact]
    public void Flag_Wins_Over_Env()
    {
        Environment.SetEnvironmentVariable("ROD_UPSTREAM", "from-env:1");
        try
        {
            var config = RedirectorConfig.Parse(new[] { "-listen", "*:1", "-upstream", "from-flag:2" });
            Assert.Equal("from-flag", config.UpstreamHost);
            Assert.Equal(2, config.UpstreamPort);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ROD_UPSTREAM", null);
        }
    }

    [Theory]
    [InlineData("")]                 // missing
    [InlineData("127.0.0.1")]        // no port
    [InlineData(":8000")]            // no host
    [InlineData("127.0.0.1:999999")] // bad port
    public void Rejects_Bad_Listen_Endpoint(string listen)
    {
        var ex = Assert.Throws<ExitProgramException>(
            () => RedirectorConfig.Parse(new[] { "-listen", listen, "-upstream", "up:9000" }));

        Assert.Equal(2, ex.ExitCode);
    }

    [Fact]
    public void Rejects_Missing_Required()
    {
        Environment.SetEnvironmentVariable("ROD_LISTEN", null);
        Environment.SetEnvironmentVariable("ROD_UPSTREAM", null);
        var ex = Assert.Throws<ExitProgramException>(() => RedirectorConfig.Parse(Array.Empty<string>()));

        Assert.Contains("missing required", ex.Message);
    }

    [Fact]
    public void Rejects_Non_Addressable_Listen_Host()
    {
        // A DNS hostname is not a bindable address.
        var ex = Assert.Throws<ExitProgramException>(
            () => RedirectorConfig.Parse(new[] { "-listen", "example.com:8000", "-upstream", "up:9000" }));

        Assert.Contains("not a bindable IP address", ex.Message);
    }

    [Fact]
    public void Parses_Allow_Cidrs()
    {
        var config = RedirectorConfig.Parse(new[]
        {
            "-listen", "*:8000", "-upstream", "up:9000",
            "-allow", "10.0.0.0/8, 192.168.0.0/16",
        });

        Assert.True(config.Allow.Allows(IPAddress.Parse("10.1.2.3")));
        Assert.True(config.Allow.Allows(IPAddress.Parse("192.168.1.1")));
        Assert.False(config.Allow.Allows(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public void Rejects_Bad_Allow_Cidr()
    {
        var ex = Assert.Throws<ExitProgramException>(
            () => RedirectorConfig.Parse(new[]
            {
                "-listen", "*:8000", "-upstream", "up:9000", "-allow", "not-a-cidr",
            }));

        Assert.Contains("-allow", ex.Message);
    }

    [Fact]
    public void Help_Exits_With_Code_2_And_No_Message()
    {
        var ex = Assert.Throws<ExitProgramException>(() => RedirectorConfig.Parse(new[] { "-h" }));

        Assert.Equal(2, ex.ExitCode);
        Assert.False(ex.HasMessage);
    }

    [Fact]
    public void Unknown_Flag_Rejected()
    {
        var ex = Assert.Throws<ExitProgramException>(
            () => RedirectorConfig.Parse(new[] { "-listen", "*:1", "-upstream", "u:2", "-bogus" }));

        Assert.Contains("unknown flag", ex.Message);
    }

    [Theory]
    [InlineData("-version")]
    [InlineData("--version")]
    public void Version_Flag_Prints_Stamp_And_Exits_Zero(string flag)
    {
        // The stamp must answer without the required flags: a runbook checks a
        // deployed binary before configuring it.
        using var stdout = new StringWriter();
        var original = Console.Out;
        Console.SetOut(stdout);
        try
        {
            var ex = Assert.Throws<ExitProgramException>(() => RedirectorConfig.Parse(new[] { flag }));

            Assert.Equal(0, ex.ExitCode);
            Assert.False(ex.HasMessage);
        }
        finally
        {
            Console.SetOut(original);
        }

        // The printed line is the same pair the startup log reports, so both
        // surfaces stay interchangeable when verifying a deployment.
        Assert.Equal(
            $"rod-redirector {BuildStamp.Version} (commit {BuildStamp.SourceCommit}){Environment.NewLine}",
            stdout.ToString());
    }

    [Fact]
    public void Bracketed_Ipv6_Listen_Parses()
    {
        var config = RedirectorConfig.Parse(new[] { "-listen", "[::1]:8000", "-upstream", "up:9000" });

        Assert.Equal(IPAddress.IPv6Loopback, config.ListenAddress);
        Assert.Equal(8000, config.ListenPort);
    }
}
