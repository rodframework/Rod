using Rod.Cli.Manifest;

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
        var toml = Valid.Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader\", \"exfil-chunks\"]");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.Empty(errors);
        Assert.NotNull(manifest);
        Assert.Equal(["plugin-loader", "exfil-chunks"], manifest!.Requires);
    }

    [Fact]
    public void CapabilityRequires_OutsideTheVocabulary_AreNamedWithIt()
    {
        // A typo'd or speculative capability is a refused manifest, never a
        // silent mismatch the store would filter wrong.
        var toml = Valid.Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"cha-cha-20\", \"plugin-loader\", \"plugin-loader\"]");
        var errors = ManifestToml.Load(toml, out var manifest);

        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("'cha-cha-20' is not a wire capability") && e.Contains("plugin-loader, exfil-chunks, staged-uploads"));
        Assert.Contains(errors, e => e.Contains("'plugin-loader' is declared twice"));
    }

    [Fact]
    public void CapabilityRequires_BelongToEntriesWithAnExecutionHalf()
    {
        // A build unit is the implant itself; an assets module runs nothing
        // on a target -- a requirement there names nothing real.
        var buildUnit = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"")
            .Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader\"]");
        var errors = ManifestToml.Load(buildUnit, out var manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("requires constrains an implant hosting this module's execution half"));

        var assets = Valid.Replace("entry = \"server\"", "entry = \"assets\"")
            .Replace("teamserver = \"1.0.0\"", "teamserver = \"1.0.0\"\nrequires = [\"plugin-loader\"]") + """

            [[assets]]
            name = "hook"
            path = "assets/hook.js"
            """;
        errors = ManifestToml.Load(assets, out manifest);
        Assert.NotNull(manifest);
        Assert.Contains(errors, e => e.Contains("requires constrains an implant hosting this module's execution half"));
    }

    [Fact]
    public void ConformanceReports_ParseOnBuildUnits()
    {
        // The build unit's half of the compatibility collapse: the tier its
        // candidate proved, the harness generation, the date, the clauses.
        var toml = Valid.Replace("entry = \"server\"", "entry = \"build-unit\"") + """

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
    [InlineData("entry = \"sidecar\"", "server, implant, build-unit, or assets")]
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
        };
        foreach (var edited in edits)
            Assert.NotEqual(baseline, CanonicalForm.Build(edited, payload));

        // Each payload digest edit changes the signed bytes.
        Assert.NotEqual(baseline, CanonicalForm.Build(Manifest(), new Dictionary<string, string> { ["src/a.cs"] = "cc", ["src/b.cs"] = "bb" }));
        Assert.NotEqual(baseline, CanonicalForm.Build(Manifest(), new Dictionary<string, string> { ["src/a.cs"] = "aa" }));
    }

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
        // v2 names the form whose field set carries the compatibility rows
        // (requires, conformance) -- the shape change is the bump.
        Assert.StartsWith("rod-module-manifest-v2\n", form);
        Assert.False(form.EndsWith('\n'));
        Assert.StartsWith("name=demo-sweep\n", form[(CanonicalForm.VersionLine.Length + 1)..]);
    }
}
