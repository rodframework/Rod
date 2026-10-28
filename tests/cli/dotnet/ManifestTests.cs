using Rod.Packaging;

namespace Rod.Cli.Tests;

public class ManifestTests
{
    private const string Valid = """
        [module]
        name = "demo-sweep"
        version = "1.2.0"
        entry = "server"
        license = "MIT"
        description = "A demonstration module."
        homepage = "https://example.test/demo-sweep"

        [compatibility]
        teamserver = "1.0.0"

        [[compatibility.targets]]
        implant-class = "implant"
        platform = "linux"
        arch = "amd64"

        [opsec]
        lands-on-disk = true
        notes = "Stages one file."

        [attack]
        techniques = ["t1082", "T1059.003"]

        [package]
        include = ["src/**"]
        exclude = ["**/bin/**"]
        """;

    [Fact]
    public void ACompleteManifest_ParsesIntoTheModel()
    {
        var errors = ManifestToml.Load(Valid, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal("demo-sweep", manifest!.Name);
        Assert.Equal(new SemVer(1, 2, 0, null), manifest.Version);
        Assert.Equal(ModuleEntryKind.Server, manifest.Entry);
        Assert.Equal("MIT", manifest.License);
        Assert.Equal(new SemVer(1, 0, 0, null), manifest.TeamserverMin);
        var target = Assert.Single(manifest.Targets);
        Assert.Equal("implant", target.ImplantClass);
        Assert.True(manifest.Opsec.LandsOnDisk);
        // Techniques normalize to their canonical uppercase shape.
        Assert.Equal(["T1082", "T1059.003"], manifest.Techniques);
        Assert.NotNull(manifest.Package);
    }

    [Fact]
    public void VerbRows_ParseWithVersionsAndFloors()
    {
        // The version matrix (architecture.md Sec 15.2's third contract):
        // one row per verb, its module-scoped version, an optional per-verb
        // teamserver floor.
        var toml = Valid + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"

            [[verbs]]
            name = "demo.sweep"
            version = "0.3.1"
            teamserver = "1.4.0"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal(2, manifest!.Verbs.Count);
        // Member-wise: the record's Techniques is an interface-typed list, so
        // record equality would compare references.
        Assert.Equal("demo.run", manifest.Verbs[0].Name);
        Assert.Equal(new SemVer(1, 0, 0, null), manifest.Verbs[0].Version);
        Assert.Null(manifest.Verbs[0].TeamserverMin);
        Assert.Empty(manifest.Verbs[0].Techniques ?? []);
        Assert.Equal("demo.sweep", manifest.Verbs[1].Name);
        Assert.Equal(new SemVer(0, 3, 1, null), manifest.Verbs[1].Version);
        Assert.Equal(new SemVer(1, 4, 0, null), manifest.Verbs[1].TeamserverMin);
        Assert.Empty(manifest.Verbs[1].Techniques ?? []);
    }

    [Fact]
    public void VerbRows_CarryTheirTechniques()
    {
        // The per-verb ATT&CK declaration (ADR-007): the row's techniques are
        // the authoritative mapping the coverage matrix renders, normalizing
        // to canonical uppercase like the module-level list. Here the verb
        // rows' union matches the module-level roll-up, so validation passes.
        var toml = Valid + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"
            techniques = ["t1082"]

            [[verbs]]
            name = "demo.sweep"
            version = "0.3.1"
            teamserver = "1.4.0"
            techniques = ["T1059.003"]
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal(["T1082"], manifest!.Verbs[0].Techniques);
        Assert.Equal(["T1059.003"], manifest.Verbs[1].Techniques);
    }

    [Fact]
    public void DescriptorRows_ParseTheirWholeHalf()
    {
        // ADR-018: a row that names a category declares the verb's whole
        // server-side half as manifest data -- the OPSEC flags, the parameter
        // schema, and the output declaration -- the zero-.NET path a novel
        // namespace rides.
        var toml = Valid.Replace("techniques = [\"t1082\", \"T1059.003\"]", "techniques = []") + """

            [[verbs]]
            name = "sweep.discover"
            version = "0.3.0"
            category = "recon"
            opsec = { "touches-network" = true, "writes-to-disk" = false }
            techniques = ["T1046"]
            output-kind = "enumeration"
            output-help = "One JSON finding per line."

              [[verbs.parameters]]
              name = "host"
              label = "Host"
              kind = "string"
              required = true
              placeholder = "10.0.0.7"

              [[verbs.parameters]]
              name = "ports"
              label = "Port range"
              kind = "string"
              help = "1-1024 or a comma list."
              placeholder = "1-1024"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        var row = manifest!.Verbs[0];
        Assert.True(row.IsDescriptor);
        Assert.Equal("recon", row.Category);
        Assert.False(row.Opsec!["writes-to-disk"]);
        Assert.True(row.Opsec!["touches-network"]);
        Assert.Equal("enumeration", row.Output!.Kind);
        Assert.Equal("One JSON finding per line.", row.Output.Help);
        Assert.Equal(2, row.Parameters!.Count);

        var host = row.Parameters[0];
        Assert.Equal("host", host.Name);
        Assert.Equal("string", host.Kind);
        Assert.True(host.Required);
        // The serialization defaults normalize at parse (required/trailing
        // false, inline true), so the canonical form is a function of the
        // declared fields, not the syntax that carried them.
        Assert.False(host.Trailing);
        Assert.True(host.Inline);

        var ports = row.Parameters[1];
        Assert.False(ports.Required);
        Assert.Equal("1-1024 or a comma list.", ports.Help);
    }

    [Fact]
    public void DescriptorFields_WithoutACategory_AreNamed()
    {
        // The mixed shape both loading paths refuse: descriptor fields with
        // no anchor category mean a row that is neither a version row nor a
        // descriptor row.
        var toml = Valid.Replace("techniques = [\"t1082\", \"T1059.003\"]", "techniques = []") + """

            [[verbs]]
            name = "sweep.discover"
            version = "0.3.0"
            output-kind = "enumeration"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("carries descriptor fields but no category"));
    }

    [Fact]
    public void DescriptorRows_ValidateAgainstTheClosedVocabularies()
    {
        var toml = Valid.Replace("techniques = [\"t1082\", \"T1059.003\"]", "techniques = []") + """

            [[verbs]]
            name = "sweep.discover"
            version = "0.3.0"
            category = "reconnaissance"
            output-kind = "portscan"

              [[verbs.parameters]]
              name = "host"
              label = "Host"
              kind = "hostname"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("category 'reconnaissance' is not a capability category"));
        Assert.Contains(errors, e => e.Contains("output-kind 'portscan' is not an output kind"));
        Assert.Contains(errors, e => e.Contains("kind 'hostname' is not a parameter kind"));
    }

    [Fact]
    public void DescriptorRows_RefuseSchemasTheUiCannotRender()
    {
        // The registry's own rendering invariants (the UI renders the schema
        // verbatim) stated at publish: an enum without choices, a duplicate
        // name, a trailing parameter that is not last.
        var toml = Valid.Replace("techniques = [\"t1082\", \"T1059.003\"]", "techniques = []") + """

            [[verbs]]
            name = "sweep.discover"
            version = "0.3.0"
            category = "recon"

              [[verbs.parameters]]
              name = "host"
              label = "Host"
              kind = "enum"
              trailing = true

              [[verbs.parameters]]
              name = "host"
              label = "Host again"
              kind = "string"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'host' is an enum and needs at least one choice"));
        Assert.Contains(errors, e => e.Contains("declares the parameter 'host' twice"));
        Assert.Contains(errors, e => e.Contains("'host' is trailing but not last"));
    }

    [Fact]
    public void VerbTechniques_MustMatchTheModuleLevelRollUp()
    {
        // ADR-007: once verb rows declare techniques, the module-level
        // [attack] list is their roll-up; a mismatch is refused so the
        // catalog and the matrix cannot disagree.
        var toml = Valid + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"
            techniques = ["T1046"]
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("must be exactly the union of the verbs' techniques"));
    }

    [Fact]
    public void VerbTechniques_OutsideTheIdGrammar_AreNamed()
    {
        var toml = Valid.Replace("techniques = [\"t1082\", \"T1059.003\"]", "techniques = []") + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"
            techniques = ["T105"]
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'T105' is not an ATT&CK technique id"));
    }

    [Fact]
    public void MalformedVerbRows_AreEachNamed()
    {
        // Row-level parse failures (a missing name, an unparseable version)
        // name their own row and stop the load.
        var toml = Valid + """

            [[verbs]]
            name = "demo.run"
            version = "not-semver"

            [[verbs]]
            version = "1.0.0"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Null(manifest);
        Assert.Contains(errors, e => e.Contains("needs a SemVer version"));
        Assert.Contains(errors, e => e.Contains("verbs[1].name is missing"));
    }

    [Fact]
    public void VerbRowsOutsideTheNamespaceGrammar_AreNamedByValidation()
    {
        // The namespace grammar (namespace.action, lowercase segments) is a
        // field-level rule the validator names once the rows themselves
        // parse -- the same two-stage reporting every other manifest field
        // follows.
        var toml = Valid + """

            [[verbs]]
            name = "NotNamespaced"
            version = "1.0.0"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'NotNamespaced' is not a namespaced verb"));
    }

    [Fact]
    public void DuplicateVerbRows_AreRefused()
    {
        var toml = Valid + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"

            [[verbs]]
            name = "demo.run"
            version = "1.1.0"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'demo.run' is declared twice"));
    }

    [Fact]
    public void AssetRows_ParseWithNamesAndPaths()
    {
        // The module layer's content seam (Sec 15.1): an asset row binds a
        // logical kebab name a consumer resolves as module/asset to a
        // package-relative path.
        var toml = Valid.Replace("entry = \"server\"", "entry = \"assets\"") + """

            [[assets]]
            name = "hook"
            path = "assets/hook.js"

            [[assets]]
            name = "legacy-page"
            path = "assets/pages/old.html"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal(ModuleEntryKind.Assets, manifest!.Entry);
        Assert.Equal("hook", manifest.Assets[0].Name);
        Assert.Equal("assets/hook.js", manifest.Assets[0].Path);
        Assert.Equal("assets/pages/old.html", manifest.Assets[1].Path);
    }

    [Fact]
    public void MalformedAssetRows_AreEachNamed()
    {
        // A row missing its shape (name or path) is a parse failure: the
        // load stops before a manifest exists, same as a malformed verb row.
        var toml = Valid + """

            [[assets]]
            name = "hook"
            path = "assets/hook.js"

            [[assets]]
            path = "assets/other.js"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);
        Assert.Null(manifest);
        Assert.Contains(errors, e => e.Contains("assets[1] needs both a name and a path"));

        // Field-level problems parse and are named by validation.
        var invalid = Valid + """

            [[assets]]
            name = "Hook!"
            path = "../outside.js"

            [[assets]]
            name = "manifest"
            path = "rod-module.toml"
            """;
        errors = ManifestToml.Load(invalid, out manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'Hook!' must be kebab-case"));
        Assert.Contains(errors, e => e.Contains("'Hook!' path '../outside.js' must be a package-relative path"));
        Assert.Contains(errors, e => e.Contains("'manifest' cannot point at the manifest itself"));
    }

    [Fact]
    public void DuplicateAssetNames_AreRefused()
    {
        var toml = Valid + """

            [[assets]]
            name = "hook"
            path = "assets/hook.js"

            [[assets]]
            name = "hook"
            path = "assets/hook-v2.js"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'hook' is declared twice"));
    }

    [Fact]
    public void AnAssetsEntryWithoutAssetRows_IsRefused()
    {
        var toml = Valid.Replace("entry = \"server\"", "entry = \"assets\"");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("an assets module declares no [[assets]] rows"));
    }

    [Fact]
    public void CanonicalForm_CoversTheVerbRows()
    {
        // The verb rows ride the signed canonical form: a tampered verb
        // version or floor breaks the signature exactly like a tampered
        // payload byte.
        ManifestToml.Load(Valid + """

            [[verbs]]
            name = "demo.sweep"
            version = "0.3.1"
            teamserver = "1.4.0"

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"
            """, out var manifest);
        var canonical = CanonicalForm.Build(manifest!, new Dictionary<string, string>());

        Assert.Contains("verb/demo.run=1.0.0\n", canonical);
        // The last verb line carries no trailing newline, like the canonical
        // form's own last line.
        Assert.EndsWith("verb/demo.sweep=0.3.1 teamserver=1.4.0", canonical);

        // The rows are name-sorted regardless of declaration order, so the
        // form is a function of the manifest's fields, not its layout.
        ManifestToml.Load(Valid + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"

            [[verbs]]
            name = "demo.sweep"
            version = "0.3.1"
            teamserver = "1.4.0"
            """, out var reordered);
        Assert.Equal(canonical, CanonicalForm.Build(reordered!, new Dictionary<string, string>()));
    }

    [Fact]
    public void CanonicalForm_FoldsVerbTechniquesIntoTheRowLine()
    {
        // The row's techniques ride the same signed line as its version and
        // floor (ADR-007): a tampered technique list breaks the signature
        // exactly like a tampered version.
        ManifestToml.Load(Valid + """

            [[verbs]]
            name = "demo.run"
            version = "1.0.0"
            techniques = ["t1082", "T1059.003"]

            [[verbs]]
            name = "demo.sweep"
            version = "0.3.1"
            teamserver = "1.4.0"
            techniques = ["T1082"]
            """, out var manifest);
        var canonical = CanonicalForm.Build(manifest!, new Dictionary<string, string>());

        // Ids normalize to uppercase and sort ordinally within the line.
        Assert.EndsWith(
            "verb/demo.sweep=0.3.1 teamserver=1.4.0 techniques=T1082",
            canonical);
        Assert.Contains("verb/demo.run=1.0.0 techniques=T1059.003,T1082\n", canonical);
    }

    [Fact]
    public void CapabilityRequires_ParseFromTheClosedVocabulary()
    {
        // ADR-017: a plugin declares what the hosting implant must support,
        // names drawn from the closed wire-capability vocabulary so a store
        // filter compares like against like.
        var toml = Valid.Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader/exec-v1\", \"exfil-chunks\"]");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal(["plugin-loader/exec-v1", "exfil-chunks"], manifest!.Requires);
    }

    [Fact]
    public void CapabilityRequires_OutsideTheVocabulary_AreNamedWithIt()
    {
        // A typo'd or speculative capability is a refused manifest, never a
        // silent mismatch the store would filter wrong. The bare family
        // prefix without an ABI is exactly such a name.
        var toml = Valid.Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"cha-cha-20\", \"plugin-loader\", \"plugin-loader\"]");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'cha-cha-20' is not a wire capability") && e.Contains("plugin-loader/exec-v1") && e.Contains("staged-uploads"));
        Assert.Contains(errors, e => e.Contains("'plugin-loader' is not a wire capability"));
    }

    [Fact]
    public void CapabilityRequires_BelongToEntriesWithAnExecutionHalf()
    {
        // A build unit is the implant itself; an assets module runs nothing
        // on a target; an extension compiles into the implant -- a
        // requirement there names nothing real.
        var buildUnit = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"")
            .Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader/exec-v1\"]") + UnitTable;
        var errors = ManifestToml.Load(buildUnit, out var manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("requires constrains an implant hosting this module's execution half"));

        var assets = Valid.Replace("entry = \"server\"", "entry = \"assets\"")
            .Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader/exec-v1\"]") + """

            [[assets]]
            name = "hook"
            path = "assets/hook.js"
            """;
        errors = ManifestToml.Load(assets, out manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("requires constrains an implant hosting this module's execution half"));
    }

    // A build-unit manifest's [unit] table (ADR-021): appended by the tests
    // that switch a fixture to the build-unit entry kind.
    private const string UnitTable = """

        [unit]
        id = "community-nim"
        command = "./build.sh"
        """;

    [Fact]
    public void ConformanceReports_ParseOnBuildUnits()
    {
        // The build unit's half of the compatibility collapse: the tier its
        // candidate proved, the harness generation, the date, the clauses.
        var toml = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"") + UnitTable + """

            [conformance]
            tier = 1
            harness = "1.0.0"
            date = "2026-01-15"
            clauses = ["enroll.public-key-and-token", "task.round-trip", "signature.verification"]
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        var report = manifest!.Conformance!;
        Assert.Equal(1, report.Tier);
        Assert.Equal(new SemVer(1, 0, 0, null), report.Harness);
        Assert.Equal("2026-01-15", report.Date);
        Assert.Equal(3, report.Clauses.Count);
        Assert.Equal("community-nim", manifest.Unit!.Id);
        Assert.Equal("./build.sh", manifest.Unit.Command);
    }

    [Fact]
    public void ConformanceReports_AreBuildUnitOnlyAndWhole()
    {
        // On any other entry kind the report names nothing; and a partial
        // section is a claim missing its proof shape, not a report.
        var onServer = Valid + """

            [conformance]
            tier = 0
            harness = "1.0.0"
            date = "2026-01-15"
            """;
        var errors = ManifestToml.Load(onServer, out var manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("reports what a build unit's candidate proved"));

        var partial = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"") + """

            [conformance]
            tier = 2
            """;
        errors = ManifestToml.Load(partial, out manifest);
        Assert.Null(manifest);
        Assert.Contains(errors, e => e.Contains("conformance.harness is missing"));
        Assert.Contains(errors, e => e.Contains("conformance.date is missing"));
    }

    [Fact]
    public void ConformanceReports_ValidateTheirFieldShapes()
    {
        var toml = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"") + """

            [conformance]
            tier = 3
            harness = "1.0.0"
            date = "15-Jan-2026"
            clauses = ["task.round-trip", "task.round-trip", "not a token"]
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("conformance.tier '3' must be 0, 1, or 2"));
        Assert.Contains(errors, e => e.Contains("conformance.date '15-Jan-2026'"));
        Assert.Contains(errors, e => e.Contains("'not a token' must be a single lowercase token"));
        Assert.Contains(errors, e => e.Contains("'task.round-trip' is declared twice"));
    }

    [Fact]
    public void MissingRequiredFields_AreEachNamed()
    {
        var errors = ManifestToml.Load("[module]\nname = \"x\"\n", out var manifest);

        Assert.Null(manifest);
        Assert.Contains(errors, e => e.Contains("module.version"));
        Assert.Contains(errors, e => e.Contains("module.entry"));
        Assert.Contains(errors, e => e.Contains("module.license"));
        Assert.Contains(errors, e => e.Contains("compatibility.teamserver"));
        Assert.Contains(errors, e => e.Contains("opsec.lands-on-disk"));
    }

    [Theory]
    [InlineData("name = \"Demo_Sweep\"", "kebab-case")]
    [InlineData("version = \"1.0\"", "SemVer")]
    [InlineData("entry = \"sidecar\"", "server, plugin, extension, build-unit, or assets")]
    public void InvalidValues_FailValidation(string line, string expectedFragment)
    {
        // Each variant omits the field under test from the base document so
        // the inline copy is its only (invalid) declaration.
        var omit = line.Split(' ')[0];
        var toml = $"""
            [module]
            name = "demo-sweep"
            version = "1.0.0"
            entry = "server"
            license = "MIT"
            {line}

            [compatibility]
            teamserver = "1.0.0"

            [opsec]
            lands-on-disk = true
            """.Replace($"name = \"demo-sweep\"\n", omit == "name" ? "" : "name = \"demo-sweep\"\n")
               .Replace($"version = \"1.0.0\"\n", omit == "version" ? "" : "version = \"1.0.0\"\n")
               .Replace($"entry = \"server\"\n", omit == "entry" ? "" : "entry = \"server\"\n");
        var errors = ManifestToml.Load(toml, out var manifest);
        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains(expectedFragment));
    }

    [Fact]
    public void AMultilineField_IsRejected_BeforeItCanPoisonTheCanonicalForm()
    {
        var toml = Valid.Replace("\"A demonstration module.\"", "\"\"\"\nline one\nline two\n\"\"\"");
        var errors = ManifestToml.Load(toml, out _);
        Assert.Contains(errors, e => e.Contains("single line"));
    }

    [Fact]
    public void SyntaxErrors_ReportTheParserMessage()
    {
        var errors = ManifestToml.Load("[module]\nname = \n", out var manifest);
        Assert.Null(manifest);
        Assert.NotEmpty(errors);
    }

    [Fact]
    public void UnknownKeysAreIgnored_SoNewerManifestsStillParse()
    {
        var toml = Valid.Replace("[opsec]", "future-field = 42\n[opsec]");
        var errors = ManifestToml.Load(toml, out var manifest);
        Assert.Empty(errors);
        Assert.NotNull(manifest);
    }
    [Fact]
    public void PluginArtifacts_RequireTheirAbisUnionAsRequires()
    {
        // ADR-020: a plugin's artifact rows carry the loader ABI each
        // prebuilt half targets, and the requirement rows state exactly
        // their union -- the static filter cannot tell another story than
        // the artifacts do.
        var toml = Valid
            .Replace("entry = \"server\"", "entry = \"plugin\"")
            .Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader/exec-v1\"]") + """

            [[plugin.artifacts]]
            platform = "linux"
            arch = "amd64"
            path = "bin/demo-sweep-linux-amd64"
            abi = "exec-v1"

            [[plugin.artifacts]]
            platform = "windows"
            arch = "amd64"
            path = "bin/demo-sweep-windows-amd64.dll"
            abi = "native-v1"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains("must be exactly the union of the plugin artifacts' ABIs"));

        var honest = toml.Replace("requires = [\"plugin-loader/exec-v1\"]",
            "requires = [\"plugin-loader/exec-v1\", \"plugin-loader/native-v1\"]");
        errors = ManifestToml.Load(honest, out manifest);
        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal(2, manifest!.PluginArtifacts.Count);
        Assert.Equal("exec-v1", manifest.PluginArtifacts[0].Abi);
        Assert.Equal("bin/demo-sweep-windows-amd64.dll", manifest.PluginArtifacts[1].Path);
    }

    [Fact]
    public void PluginArtifacts_ValidateTheirRows()
    {
        // The path rule is the asset rows' own, the ABI comes from the
        // closed vocabulary, and one platform carries one artifact -- a
        // second row for the same target is a staging ambiguity.
        var toml = Valid.Replace("entry = \"server\"", "entry = \"plugin\"") + """

            [[plugin.artifacts]]
            platform = "linux"
            arch = "amd64"
            path = "../escape"
            abi = "exec-v1"

            [[plugin.artifacts]]
            platform = "linux"
            arch = "amd64"
            path = "bin/a"
            abi = "software"

            [[plugin.artifacts]]
            platform = "linux"
            arch = "amd64"
            path = "bin/b"
            abi = "exec-v1"
            """;
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("no '..' segments"));
        Assert.Contains(errors, e => e.Contains("abi 'software' is not a loader ABI"));
        Assert.Contains(errors, e => e.Contains("arch 'amd64' twice"));
    }

    [Fact]
    public void APluginWithoutArtifactRows_IsRefused()
    {
        var toml = Valid.Replace("entry = \"server\"", "entry = \"plugin\"");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("declares no [[plugin.artifacts]] rows"));
    }

    [Fact]
    public void ExtensionTargets_NameTheBuildUnitTheyCompileInto()
    {
        // ADR-022: an extension is compiled in by the build unit its target
        // rows name (with an optional floor) -- a manifest that targets no
        // unit is a portable plugin mis-declared as an extension.
        var toml = Valid.Replace("entry = \"server\"", "entry = \"extension\"").Replace(TargetsBlock, "");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("declares no [[compatibility.targets]]"));

        var targeted = Valid.Replace("entry = \"server\"", "entry = \"extension\"").Replace(TargetsBlock, TargetedBlock);
        errors = ManifestToml.Load(targeted, out manifest);
        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal("rod-rust", manifest!.Targets[0].BuildUnit);
        Assert.Equal(new SemVer(1, 0, 0, null), manifest.Targets[0].UnitRange);

        var untargeted = targeted.Replace("build-unit = \"rod-rust\"\nunit-range = \"1.0.0\"\n", "");
        errors = ManifestToml.Load(untargeted, out manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("carries no build-unit"));
    }

    // The base fixture's targeting block, flush-left as the document carries
    // it (raw-string literals strip their indentation), and its build-unit
    // targeting variant.
    private const string TargetsBlock = """
        [[compatibility.targets]]
        implant-class = "implant"
        platform = "linux"
        arch = "amd64"
        """;

    private const string TargetedBlock = """
        [[compatibility.targets]]
        implant-class = "implant"
        platform = "linux"
        arch = "amd64"
        build-unit = "rod-rust"
        unit-range = "1.0.0"
        """;

    [Fact]
    public void UnitTables_RideBuildUnitsOnlyAndMustBeWhole()
    {
        // ADR-021: the [unit] table is the external build contract's face --
        // a build unit must carry one, and nobody else may.
        var unitless = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"");
        var errors = ManifestToml.Load(unitless, out var manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("carries no [unit] table"));

        var foreign = Valid + UnitTable;
        errors = ManifestToml.Load(foreign, out manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("[unit] declares the external build command"));

        var brokenId = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"") + """

            [unit]
            id = "Community Nim"
            command = ""
            timeout-minutes = 0
            """;
        errors = ManifestToml.Load(brokenId, out manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("unit.id 'Community Nim' must be kebab-case"));
        Assert.Contains(errors, e => e.Contains("unit.command is required"));
        Assert.Contains(errors, e => e.Contains("unit.timeout-minutes '0'"));
    }

    [Fact]
    public void TargetingRows_RideTheCanonicalForm()
    {
        // The targeting half is signature-bound: a tampered build-unit or
        // floor breaks verification like a tampered platform.
        var targeted = Valid.Replace("""
                [[compatibility.targets]]
                implant-class = "implant"
                platform = "linux"
                arch = "amd64"
                """, """
                [[compatibility.targets]]
                implant-class = "implant"
                platform = "linux"
                arch = "amd64"
                build-unit = "rod-rust"
                unit-range = "1.2.0"
                """);
        ManifestToml.Load(targeted, out var manifest);
        var canonical = CanonicalForm.Build(manifest!, new Dictionary<string, string>());

        Assert.Contains("unit=rod-rust unit-floor=1.2.0", canonical);

        var unit = ((Valid.Replace("entry = \"server\"", "entry = \"build-unit\"")) + UnitTable)
            .Replace("command = \"./build.sh\"", "command = \"./build.sh --hermetic\"");
        ManifestToml.Load(unit, out manifest);
        canonical = CanonicalForm.Build(manifest!, new Dictionary<string, string>());
        Assert.Contains("unit=community-nim command=./build.sh --hermetic timeout=-", canonical);

        var plugin = Valid.Replace("entry = \"server\"", "entry = \"plugin\"") + """

            requires = ["plugin-loader/exec-v1"]

            [[plugin.artifacts]]
            platform = "linux"
            arch = "amd64"
            path = "bin/demo"
            abi = "exec-v1"
            """;
        ManifestToml.Load(plugin, out manifest);
        canonical = CanonicalForm.Build(manifest!, new Dictionary<string, string>());
        Assert.Contains("plugin-artifact/linux/amd64=path=bin/demo abi=exec-v1", canonical);
    }
}

public class CanonicalFormTests
{
    private static ModuleManifest Manifest() => new()
    {
        Name = "demo-sweep",
        Version = new SemVer(1, 2, 0, null),
        Entry = ModuleEntryKind.Server,
        License = "MIT",
        Description = "A demonstration module.",
        Homepage = "https://example.test",
        TeamserverMin = new SemVer(1, 0, 0, null),
        Targets = [new TargetMatrix("implant", "linux", "amd64")],
        Opsec = new OpsecMetadata(true, "Stages one file."),
        Techniques = ["T1082"],
        Verbs = [new VerbDeclaration("demo-sweep.run", new SemVer(0, 1, 0, null), null, ["T1082"])],
        Assets = [new AssetDeclaration("hook", "assets/hook.js")],
    };

    [Fact]
    public void EveryFieldAndEveryPayloadDigest_Participates()
    {
        var payload = new Dictionary<string, string> { ["src/a.cs"] = "aa", ["src/b.cs"] = "bb" };
        var baseline = CanonicalForm.Build(Manifest(), payload);

        // Each metadata field edit changes the signed bytes.
        var edits = new[]
        {
            Manifest() with { Name = "other" },
            Manifest() with { Version = new SemVer(1, 2, 1, null) },
            Manifest() with { License = "Apache-2.0" },
            Manifest() with { Description = "Different." },
            Manifest() with { TeamserverMin = new SemVer(1, 1, 0, null) },
            Manifest() with { Opsec = new OpsecMetadata(false, "Stages one file.") },
            Manifest() with { Techniques = ["T1005"] },
            Manifest() with { Targets = [new TargetMatrix("implant", "windows", "amd64")] },
            Manifest() with { Verbs = [new VerbDeclaration("demo-sweep.run", new SemVer(0, 1, 0, null), null, ["T1005"])] },
            // The asset mapping is signed like a verb row: re-pointing a
            // known asset name at a different file breaks verification.
            Manifest() with { Assets = [new AssetDeclaration("hook", "assets/hook-v2.js")] },
            // The compatibility rows (ADR-017): a tampered requirement or
            // conformance claim breaks verification the same way.
            Manifest() with { Requires = ["plugin-loader"] },
            Manifest() with { Conformance = new ConformanceReport(0, new SemVer(1, 0, 0, null), "2026-01-15", []) },
            // The descriptor half (ADR-018): a tampered category, flag,
            // schema, or output kind breaks verification the same way -- the
            // metadata decides what the UI renders and where results land.
            Manifest() with { Verbs = [DescriptorVerb() with { Category = "collect" }] },
            Manifest() with { Verbs = [DescriptorVerb() with { Opsec = new Dictionary<string, bool> { ["persists"] = true } }] },
            Manifest() with { Verbs = [DescriptorVerb() with
            {
                Parameters =
                [
                    new VerbParameterDeclaration("host", "Host", "string", Required: true, Placeholder: "10.0.0.8"),
                    new VerbParameterDeclaration("range", "Range", "string"),
                ],
            }] },
            Manifest() with { Verbs = [DescriptorVerb() with
            {
                Parameters =
                [
                    new VerbParameterDeclaration("range", "Range", "string"),
                    new VerbParameterDeclaration("host", "Host", "string", Required: true, Placeholder: "10.0.0.7"),
                ],
            }] },
            Manifest() with { Verbs = [DescriptorVerb() with { Output = new VerbOutputDeclaration("text") }] },
        };
        foreach (var edited in edits)
            Assert.NotEqual(baseline, CanonicalForm.Build(edited, payload));

        // Each payload digest edit changes the signed bytes.
        Assert.NotEqual(baseline, CanonicalForm.Build(Manifest(), new Dictionary<string, string> { ["src/a.cs"] = "cc", ["src/b.cs"] = "bb" }));
        Assert.NotEqual(baseline, CanonicalForm.Build(Manifest(), new Dictionary<string, string> { ["src/a.cs"] = "aa" }));
    }

    // The descriptor-declaring variant of the fixture's one verb row.
    private static VerbDeclaration DescriptorVerb() => new(
        "demo-sweep.run", new SemVer(0, 1, 0, null), null, ["T1082"],
        Category: "recon",
        Opsec: new Dictionary<string, bool> { ["touches-network"] = true },
        Parameters: [new VerbParameterDeclaration("host", "Host", "string", Required: true, Placeholder: "10.0.0.7")],
        Output: new VerbOutputDeclaration("enumeration", "One finding per line."));

    [Fact]
    public void CompatibilityRows_RideTheFormSorted_OrDashWhenAbsent()
    {
        var manifest = Manifest() with
        {
            Requires = ["staged-uploads", "plugin-loader", "plugin-loader"],
            Conformance = new ConformanceReport(1, new SemVer(2, 0, 0, null), "2026-01-15",
                ["task.round-trip", "enroll.public-key-and-token"]),
        };
        var canonical = CanonicalForm.Build(manifest, new Dictionary<string, string>());

        // Names sort ordinally and duplicates drop, so the form is a function
        // of the requirement set, not its declaration order.
        Assert.Contains("requires=plugin-loader,staged-uploads\n", canonical);
        Assert.Contains("conformance=1/2.0.0/2026-01-15\n", canonical);
        Assert.Contains("conformance-clauses=enroll.public-key-and-token,task.round-trip\n", canonical);

        // Absent rows read as dashes: the line set is stable across modules.
        var bare = CanonicalForm.Build(Manifest(), new Dictionary<string, string>());
        Assert.Contains("requires=-\n", bare);
        Assert.Contains("conformance=-\n", bare);
        Assert.Contains("conformance-clauses=-\n", bare);
    }

    [Fact]
    public void AssetRows_RideTheFormNameSorted()
    {
        var manifest = Manifest() with
        {
            Assets =
            [
                new AssetDeclaration("z-page", "assets/z.html"),
                new AssetDeclaration("hook", "assets/hook.js"),
            ],
        };
        var canonical = CanonicalForm.Build(manifest, new Dictionary<string, string>());

        // The rows bind the logical name to the declared path, name-sorted
        // regardless of declaration order.
        Assert.Contains("asset/hook=assets/hook.js\n", canonical);
        Assert.EndsWith("asset/z-page=assets/z.html", canonical);
    }

    [Fact]
    public void DescriptorRows_RideTheForm_WithSchemaAndOutputLines()
    {
        // The descriptor half's own lines (ADR-018): the category and OPSEC
        // flags fold into the verb line; the parameter schema and the output
        // declaration ride their own lines, parameters in declaration order
        // (the order is data) and flags key-sorted (the set is the data).
        var manifest = Manifest() with { Verbs = [DescriptorVerb()], Assets = [] };
        var canonical = CanonicalForm.Build(manifest, new Dictionary<string, string>());

        Assert.Contains(
            "verb/demo-sweep.run=0.1.0 techniques=T1082 category=recon opsec=touches-network=true\n",
            canonical);
        Assert.Contains(
            "param/demo-sweep.run/host=kind=string required=true trailing=false inline=true choices=- label=Host placeholder=10.0.0.7 help=-\n",
            canonical);
        Assert.EndsWith(
            "output/demo-sweep.run=kind=enumeration help=One finding per line.",
            canonical);

        // A version-only row contributes its verb line alone: the line set is
        // stable across the two row shapes.
        var bare = CanonicalForm.Build(Manifest(), new Dictionary<string, string>());
        Assert.Contains("verb/demo-sweep.run=0.1.0 techniques=T1082\n", bare);
        Assert.DoesNotContain("param/", bare);
        Assert.DoesNotContain("output/", bare);
    }

    [Fact]
    public void PayloadOrdering_IsPathSorted_NotEnumerationAccident()
    {
        var first = CanonicalForm.Build(Manifest(), new Dictionary<string, string>
        {
            ["z/last.cs"] = "1",
            ["a/first.cs"] = "2",
        });
        var second = CanonicalForm.Build(Manifest(), new Dictionary<string, string>
        {
            ["a/first.cs"] = "2",
            ["z/last.cs"] = "1",
        });
        Assert.Equal(first, second);
    }
    [Fact]
    public void TheForm_CarriesItsVersionLineAndNoTrailingNewline()
    {
        var form = CanonicalForm.Build(Manifest(), new Dictionary<string, string>());
        // v4 names the form whose field set carries the plugin artifact
        // rows, the targets' build-unit targeting, and the [unit] table
        // (ADRs 020 through 022) -- the shape change is the bump.
        Assert.StartsWith("rod-module-manifest-v4\n", form);
        Assert.False(form.EndsWith('\n'));
        Assert.StartsWith("name=demo-sweep\n", form[(CanonicalForm.VersionLine.Length + 1)..]);
    }

}
