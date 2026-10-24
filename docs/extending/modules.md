# Rod -- Writing capability modules

How a capability joins Rod as a module -- server-side gate and catalog,
implant-side execution -- through one loading path, whether the module ships
in the tree or arrives from outside it. The sensitive categories (evasion,
exploit) exist in the platform as **contracts only**: the core ships their
interfaces, registration, dispatch, and data shapes, and supplies no concrete
techniques ([architecture.md Sec 13](../architecture.md)). What a module does
on the target is the module author's responsibility and must stay within the
authorization the operator holds.

The design goal is that adding a capability is **registration, never
modification**: no core edits, no composition-root changes, no protocol
changes. In-tree reference modules obey the same rule as external ones --
the tree's own modules live under `modules/` (server-side) and
`src/implant/rust/modules/` (implant-side), load through exactly the path an
operator's module takes, and a kernel change must answer *why it cannot be a
module* ([architecture.md Sec 15.1](../architecture.md)).

## The two halves of a capability

A capability verb has a server-side half (who may issue it) and an
implant-side half (what runs on the target). They meet at the verb string and
the opaque argument string -- nothing else.

| Half | Lives in | Decides |
|------|----------|---------|
| Gate + catalog | teamserver, `Rod.Capabilities` | whether an operator may issue the verb; what the UI shows |
| Execution | implant, handler registry | what the verb actually does |

The teamserver never executes tradecraft (architecture.md Sec 10.2): it gates,
forwards, and records. Execution lives where the target's filesystem, network,
and credentials actually are.

## The contract trilogy: declare the schema, the output, the version

The descriptor carries more than the gate (architecture.md Sec 15.2,
ADR-003). Its **parameter schema** is what the operator UI renders the task
form from, its **output declaration** is what routes results to the generic
panels, and the manifest's **verb rows** carry the module-scoped version each
verb iterates under. A module that declares all three is fully interactive on
a teamserver that has never heard of it -- no UI change, no framework change:

```csharp
public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
    "sweep.discover",
    CapabilityCategory.Recon,
    "0.3",
    parameters: new[]
    {
        new VerbParameter("host", "Host", VerbParameterKind.String, Required: true),
        new VerbParameter("range", "Port range", VerbParameterKind.String, Required: true),
    },
    output: new VerbOutput(VerbOutputKind.Enumeration,
        "One JSON finding per line: host, port, state, service."));
```

**The parameter schema.** One `VerbParameter` per argument field, in the
order the verb's grammar joins them. The serialization rule is fixed and
shared: values join with single spaces in declaration order, empty optionals
drop out, a `Trailing` final parameter takes everything after as the raw
remainder (the trailing-command shape -- a value with spaces belongs there),
and a `File` parameter rides the content arm -- inline base64 under the 1 MiB
ceiling when `Inline` is true (the default), staged bytes otherwise, where the
server binds the sha256 into the signed arguments. Kinds: `String`, `Text`
(free text, renders wide), `Number`, `Boolean`, `Enum` (carries `Choices`),
`File`, `Array` (a comma list). The wire is untouched: the UI builds the
opaque argument string and the verb's own handler stays the parser
(architecture.md Sec 10). Registration refuses a schema the UI cannot render
(trailing not last, a duplicate name, an enum without choices).

**The output declaration.** `VerbOutput` names the taxonomy kind the results
speak; the grammar behind each row kind is JSON lines (one object per line,
required fields present, unknown fields ignored):

| Kind | Grammar (one JSON object per line) | The panel it earns |
|------|------------------------------------|--------------------|
| `Enumeration` | `host` required; `port`, `state`, `service`, `addresses`, `os`, `arch` optional | the topology view and the task row's structure table |
| `ProcessList` | `pid`, `image` required; `ppid`, `user` optional | the process table |
| `FileList` | `name` required; `dir`, `size`, `mtime` optional | the file table |
| `Credential` | `kind`, `principal` required; `secret`, `source`, `host`, `note` optional | the credentials board (Assets slot) and the task row's credential table |
| `File` | no inline grammar -- the bulk rides the exfil chunk path into the artifact store | the loot board's file kind, the task row's artifact download |
| `Screenshot` | a PNG artifact through the exfil chunk path | the loot board's screenshot kind, the inline preview |
| `Text` | none | the transcript alone (the default and the degradation target) |

A verb whose output does not parse against its declared kind degrades to
plain text: the UI keeps working, the module just earns no panels. Secret
material in `Credential` rows renders masked until revealed, and never enters
the audit chain.

**The version rows.** The manifest carries one `[[verbs]]` row per verb --
its module-scoped version and an optional per-verb `teamserver` floor -- so a
verb iterates independently of the package and install refuses a version
whose verbs outrun the deployment, naming the verb:

```toml
[[verbs]]
name = "sweep.discover"
version = "0.3.0"
# teamserver = "1.4.0"   # optional per-verb floor
```

The rows ride the signed canonical form (a tampered verb version breaks
`rod mod verify` exactly like a tampered payload byte) and mirror into the
registry entry, where `rod mod search` finds a module by verb name and
`rod mod info` lists the rows.

## Server-side half: register a module

Implement `ICapabilityModule` -- a registration-only contract carrying exactly
one `CapabilityDescriptor`:

```csharp
using Rod.Capabilities;
using Rod.Capabilities.Modules;

public sealed class MyPingModule : ICapabilityModule
{
    public CapabilityDescriptor Descriptor { get; } = CapabilityDescriptor.Of(
        "demo.ping",
        CapabilityCategory.Core,
        "1.0",
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Free-form OPSEC metadata; the UI badges known keys.
            ["touches-network"] = "false",
        });
}
```

Build it, drop `MyModules.dll` next to the teamserver binary, and list the
type under `Capabilities:Modules` in `appsettings.json`:

```json
{
  "Capabilities": {
    "Modules": [ "MyModules.MyPingModule, MyModules" ]
  }
}
```

The in-tree reference module `modules/hostenum` took this exact path: the
teamserver's build deploys its assembly beside the binary and the shipped
configuration names it, so it loads through the same config list your module
lands in -- being in-tree changes nothing about the path.

That is the whole server-side integration:

- Registration is **last-wins over the placeholder** -- every built-in verb
  (the contract-only `evasion.*` / `exploit.*` included) is held by a
  placeholder module precisely so your module replaces it by registration.
- A registered module **widens the task gate**: the registry-backed resolver
  admits the verb for task issuance even when no implant class's reduced set
  lists it. This is the path the sensitive categories depend on -- they are
  deliberately not class-gated (architecture.md Sec 5.2, Sec 10.3).
- Failures are loud: a wrong type name, a missing assembly, or a throwing
  constructor aborts startup. A red team cannot afford "registered but not
  what the operator deployed".

The loader resolves assemblies **only** by that explicit list (already loaded,
or a same-named dll in the application directory) -- it never scans
directories. A module reaches the process exactly when an operator built it,
placed it, and named it.

## Asset modules: ship content, not code

The module layer's second half is content (architecture.md Sec 15.1): hook
scripts and phishing templates chase browser versions and the SMTP
ecosystem, churn no kernel should absorb. An asset module is pure files --
no assembly, nothing executes on the teamserver:

```toml
[module]
name = "my-lures"
version = "1.0.0"
entry = "assets"
license = "Apache-2.0"
description = "Lure templates for the quarterly engagements."

[compatibility]
teamserver = "1.0.0"

[[assets]]
name = "renewal-notice"
path = "assets/renewal-notice.txt"
```

Each `[[assets]]` row binds a logical name to a package-relative file. Drop
the directory on the host and list it under `Capabilities:AssetModules`
(paths are relative to the teamserver binary; the build deploys the in-tree
set under `modules/` beside the binary):

```json
{
  "Capabilities": {
    "AssetModules": [ "modules/lure-templates", "/opt/rod/modules/my-lures" ]
  }
}
```

The host reads the manifest's module name and asset rows at startup and
serves the bytes by `module/asset` name. Failures are loud, matching the
assembly loader: a listed directory that is missing, a manifest that does
not parse, an asset path that escapes the module tree, or a declared file
that is absent each aborts startup. Two modules claiming one name resolve
last-listed-wins -- the authority rule every module seam applies. `rod mod
init --entry assets` scaffolds the whole shape, the asset rows ride the
signed canonical form like verb rows, and the file bytes ride it through
the per-file digests, so the trust chain is the same one an assembly
module rides.

What an asset *means* is the consumer's contract, and each consumer names
its own:

- **The browser hook** (module `browser-hook`, asset `hook`): a JavaScript
  template that carries the `__ROD_BAKE_JSON__` placeholder exactly once.
  The mint substitutes one compact camelCase JSON bake object (endpoints,
  credential, seal, cadence, verbs) and serves the result. A served hook is
  reviewable as "the template plus this bake" and nothing else; while no
  module is listed, the mint refuses with 503 naming the config section.
- **Campaign templates** (any module, referenced as `module/asset` in the
  campaign's `template.ref`): one file per template -- a `Subject: ` first
  line, one blank line, then the body; the declared path's extension
  selects plain (`.txt`) against HTML (`.html`/`.htm`). Creation resolves
  the reference, runs the result through the same validation as inline
  text (the merge grammar `{{link}}`, `{{pixel}}`, `{{email}}`, `{{name}}`
  is the kernel's contract), and stores the resolved subject and body on
  the campaign row.

The in-tree reference pair ships under `modules/browserhook` and
`modules/lure-templates`; both load through exactly this path.

## Implant-side half: write a plugin module

The crate fork (below) adds a handler at build time. The plugin seam adds
one to an artifact already deployed (architecture.md Sec 5.4): a C-ABI
module written against the `rod-plugin-sdk` crate
(`src/implant/rust/plugin-sdk/`), delivered over the sealed task channel by
`module.load`'s staged content, dispatched like any compiled verb. The
authoring surface is a plain Rust trait plus one macro:

```rust
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

pub struct Sweep;

impl Plugin for Sweep {
    fn name(&self) -> &'static str { "sweep" }
    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("recon.portscan", portscan)]
    }
}

fn portscan(arguments: &str) -> Result<String, String> {
    // arguments is the opaque task string; Ok is the task's output,
    // Err its failure. Print recon findings in the JSON-lines grammar
    // below and the topology view picks them up.
    Ok(sweep(arguments))
}

rod_plugin!(Sweep);
```

One source builds both delivery shapes: `cargo build --release` in the
module's tree emits the Linux executable (build against a musl triple,
`--target x86_64-unknown-linux-musl` on an amd64 host, for a static
module that runs from any artifact with no libc coupling) and the
Windows `cdylib`. Issue the load with the artifact's bytes as the task's
content: `module.load sweep`. The loader stages the bytes in a memfd and
execs the module through the anonymous fd on Linux -- one process per
dispatch, nothing on disk -- or maps the PE by hand on Windows; the
verbs join the dispatch table, and the next contact advertises them --
the operator's console reads a module verb exactly like a built-in one.
`module.list` reports what is loaded, and `module.unload sweep` retracts
it (best-effort: routes drop immediately, a running handler finishes).

The reference pair in-tree is the worked example to copy: the server-side
half at `modules/hostenum/` and the implant-side half at
`src/implant/rust/modules/hostenum/` -- `recon.hostenum` against the SDK,
benign and readable, one verb string declared on both sides and nothing
shared between them.

The rules the loader enforces, all reported on the load task itself:

- **Namespaced verbs only.** `namespace.action`, the grammar every Rod
  verb follows.
- **The compiled set and the channel verbs stay compiled.** A module
  cannot register a verb the artifact compiles (the compiled arm would
  shadow it forever) or a channel verb (`shell.interact`,
  `tunnel.forward`, `tunnel.socks`) -- a live channel owns process
  handles and carriage multiplexing that span tasking cycles, which no
  post-build module can reach (architecture.md Sec 13's line).
- **Replacement is last-registration-wins.** A later module's verb
  replaces an earlier module's route, the same rule the server-side seam
  applies.
- **Panics are fenced.** On Windows the shim catches a panicking
  handler and reports it as the task's failure (build without
  `panic = "abort"`, which turns that fence off). On Linux the process
  edge is the fence: a panicking or aborted module reads as a dead child
  and the task fails with the cause.

**The scope boundary.** The two loader shapes divide the labor the
domain already draws: a Linux module answers one request per process --
the stateless long tail, no state between calls -- while resident
tradecraft (an input-capture hook that stays) is the Windows in-process
shape's half. Build the Linux shape against a musl triple and it loads
from any artifact, the static musl fielded build included.

**Pairing with the server half.** A module verb in a standard namespace
(recon, lateral, persist, collect, exfil) is class-admissible for the
Implant class already, so it tasks with no server-side ceremony. A module
carrying a novel namespace pairs with a server-side descriptor module
(the `ICapabilityModule` half above) that widens the issuance gate -- two
halves, one verb string, nothing else shared.

The dispatch grammar your code answers either way is the task contract's
own: string arguments in, outcome plus output back, with exfil chunks for
bulk -- the same shape the compiled handlers speak, so an operator's console
reads a module verb exactly like a built-in one.

## Recon output grammar (the topology contract)

Recon findings are the structural output the server reads back widest: the
engagement's topology view ([architecture.md Sec
11.2](../architecture.md)) parses the completed output of every task whose
verb declares the `Enumeration` output kind -- the built-in
`recon.portscan` and `recon.hostenum` and any module verb that declares the
kind -- into the picture's observed hosts and ports.
The grammar is JSON lines -- one finding per line, `host` required,
everything else optional, unknown fields ignored:

```json
{"host":"10.0.0.5","port":445,"state":"open","service":"smb"}
{"host":"web01","addresses":["10.0.0.5"],"os":"linux","arch":"x86_64"}
```

A line carrying a `port` is a portscan finding; one carrying `addresses`
or `os`/`arch` is a hostenum finding. A line that does not parse is not a
finding: it stays in the transcript, and nothing errors -- print your
sweep in this shape and the operator's picture assembles itself, print
anything else and the transcript remains the read, which is the honest
fallback. The parse is bounded (ten thousand lines per task), so a sweep
against a /24 may print freely.

## Building an artifact that carries your handler

The build unit compiles the Rust crate through the uniform build contract
(`Build:RustSourceDirectory` names your tree on an installed teamserver;
unset keeps the repo walk-up): a hermetic staging copy, the per-artifact
profile baked into `src/baked.rs`, and a `cargo build --release --target
<triple>` for the requested target. Your tree is independent and disposable
-- coupled to the teamserver only by the wire contracts (rod.proto, the
baked profile's base64url JSON, the sealed envelope), so a fork tracks the
contract, not the teamserver's code.

## OPSEC metadata and ROE

Give the descriptor honest attributes (`writes-to-disk`, `touches-network`,
`modifies-defenses`, ...): they render as risk badges in the operator UI, and
operators writing ROE profiles can gate on namespaces (`evasion.*` wildcards
work in `PermittedVerbs`). An engagement whose ROE profile omits your verb
refuses it at queue time with an audit record naming the violated rule --
build the metadata as if the operator's report depends on it, because it does.

Four of those attributes also decide the verb's **unattended posture**
([architecture.md Sec 10.4](../architecture.md)): declare `reads-input`,
`reads-memory`, `executes-code`, or `modifies-defenses`, or register under
the Evasion/Exploit categories, and the verb never fires without a human --
the automation engine refuses to build a rule on it. The stance is deliberate: the
metadata you declare is the whole contract, so a module nobody anticipated
gets the right posture at registration and no list anywhere needs an edit.
Attributes the policy does not key on (`reads-credential`, `persists`,
`reads-screen`, ...) leave the verb automatable -- describe what the verb
does, and the platform decides; do not game the vocabulary.

## Build-time transforms

Build-time artifact transformation -- the slot where Metasploit put its
encoders and payload encryption -- follows the same pattern as a capability
module, one layer down ([architecture.md Sec 6](../architecture.md)). The
platform ships only the seam; no transform ships in-tree, because each one
owns its key material and its decode contract end to end -- the teamserver
generates none, stores none, and knows nothing about how the bytes unwrap on
the target.

Implement `IPayloadTransform`: name yourself (the name lands on the artifact
and in the audit trail, so make it find the code), take the built bytes plus
the build context (class, target, transport and beacon profiles), and return
the transformed bytes plus a short metadata note:

```csharp
using Rod.BuildPipeline.PayloadBuild;

public sealed class MyWrapTransform : IPayloadTransform
{
    public string Name => "my-wrap";

    public Task<PayloadTransformOutput> ApplyAsync(
        PayloadTransformInput input, CancellationToken cancellationToken = default)
    {
        var wrapped = MyCodec.Wrap(input.Artifact, key: /* yours, not the server's */);
        return Task.FromResult(new PayloadTransformOutput(wrapped, Metadata: "v1"));
    }
}
```

Drop the assembly next to the teamserver binary and list it under
`Build:Transforms`; the listed order is the application order, each
transform's output feeding the next:

```json
{
  "Build": {
    "Transforms": [ "MyTransforms.MyWrapTransform, MyTransforms" ]
  }
}
```

The loader resolves assemblies only by that explicit list -- the same bounded
shape as `Capabilities:Modules` -- and a wrong entry fails startup loudly. The
chain runs after the build unit and before anything is recorded, so the
stored fingerprint covers exactly the transformed bytes and the
`PayloadBuilt` audit event names every applied transform (with its metadata
note): the engagement report never lies about what a transform produced.
Remember the implant side is still yours -- nothing in-tree unwraps your
bytes, so your decode stub travels with whatever artifact you ship.

## Distributing and installing

Both halves travel as one module through the ecosystem's file contracts
([architecture.md Sec 15.2](../architecture.md)): `rod mod init`
scaffolds the repository and generates the publisher's Ed25519 keypair,
`rod mod publish` packages, signs, and writes the index entry for a pull
request against `rod-registry`, and an operator `rod mod search`es the
registry, `rod mod install`s with the signature, compatibility, and
per-verb floors verified, and pins the result in `rod.modules.lock.json`
-- usage detail lives in `rod mod help <verb>`. The in-tree
`modules/hostenum` carries the same `rod-module.toml` an external module
carries (verb row included) and rides the same
chain; being in-tree changes nothing about the path here either.

## What the core ships, and where your module sits

The reference set is the standard, documented surface (architecture.md
Sec 13); everything beyond it -- in-the-wild zero-days, weaponized PoCs,
novel tradecraft -- lives in modules like yours, arriving through the module
seams. The core keeps the interfaces, registration, dispatch, and data
models; the tradecraft is yours.
