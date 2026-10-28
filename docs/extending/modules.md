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

## The five entry kinds (manifest v4, ADRs 020-023)

One manifest shape, five ways to ship:

- **`server`** -- descriptor rows are the whole module: the verbs register
  from the manifest alone, zero code (ADR-018's default authoring path).
- **`plugin`** -- the portable implant-side tier: prebuilt execution
  halves as `[[plugin.artifacts]]` rows (platform, arch, path, and the
  loader `abi` -- `exec-v1` or `native-v1`; `coff-v1`/`wasm-v1` are
  reserved names publish refuses until their loaders ship), with the
  requirement rows pinned to the artifacts' ABI union. The operator
  console's install surfaces and the `/modules/{name}/artifact` fetch
  pick the platform-matched row for a `module.load` task's content.
- **`extension`** -- the implant-native tier (ADR-022): sources a build
  unit compiles *into* the artifact. Every `[[compatibility.targets]]`
  row must name its `build-unit` (optionally a `unit-range` floor) -- the
  hard gate the build-time catalog holds. For `rod-rust` the overlay is a
  source merge: the package's `src/` tree compiles as modules inside the
  implant crate (the implant's types behind `crate::` paths -- the
  tier's reach, and what keeps the graph acyclic), and the unit
  regenerates the registry the dispatch chain reads: compiled core,
  extensions, then runtime plugins.
- **`build-unit`** -- the external build contract (ADR-021): the
  `[unit]` table (`id`, `command`, optional `timeout-minutes`) the
  pipeline spawns under `Build:ExternalUnits`. A new implant language
  registers a package, not a recompile.
- **`assets`** -- pure content (ADR unchanged since the first asset
  modules).

The canonical form is `rod-module-manifest-v4`: the targets carry
`build-unit`/`unit-floor`, plugin artifact rows ride one line per
target, and the `[unit]` table rides the signature like every field.

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

```toml
[[verbs]]
name = "sweep.discover"
version = "0.3.0"
category = "recon"
opsec = { "touches-network" = true }
techniques = ["T1046"]
output-kind = "enumeration"
output-help = "One JSON finding per line: host, port, state, service."

  [[verbs.parameters]]
  name = "host"
  label = "Host"
  kind = "string"
  required = true
  placeholder = "10.0.0.7"

  [[verbs.parameters]]
  name = "range"
  label = "Port range"
  kind = "string"
  required = true
```

**The parameter schema.** One `[[verbs.parameters]]` row per argument
field, in the order the verb's grammar joins them. The serialization rule
is fixed and shared: values join with single spaces in declaration order,
empty optionals drop out, a `trailing = true` final parameter takes
everything after as the raw remainder (the trailing-command shape -- a
value with spaces belongs there), and a `file` parameter rides the content
arm -- inline base64 under the 1 MiB ceiling when `inline` is true (the
default), staged bytes otherwise, where the server binds the sha256 into
the signed arguments. Kinds: `string`, `text` (free text, renders wide),
`number`, `boolean`, `enum` (carries `choices`), `file`, `array` (a comma
list). The wire is untouched: the UI builds the opaque argument string and
the verb's own handler stays the parser (architecture.md Sec 10).
Validation refuses a schema the UI cannot render (trailing not last, a
duplicate name, an enum without choices) -- at publish through the CLI, at
startup through the registry's own gate.

**The output declaration.** `output-kind` names the taxonomy kind the
results speak; the grammar behind each row kind is JSON lines (one object
per line, required fields present, unknown fields ignored):

| Kind | Grammar (one JSON object per line) | The panel it earns |
|------|------------------------------------|--------------------|
| `enumeration` | `host` required; `port`, `state`, `service`, `addresses`, `os`, `arch` optional | the topology view and the task row's structure table |
| `process-list` | `pid`, `image` required; `ppid`, `user` optional | the process table |
| `file-list` | `name` required; `dir`, `size`, `mtime` optional | the file table |
| `credential` | `kind`, `principal` required; `secret`, `source`, `host`, `note` optional | the credentials board (Assets slot) and the task row's credential table |
| `file` | no inline grammar -- the bulk rides the exfil chunk path into the artifact store | the loot board's file kind, the task row's artifact download |
| `screenshot` | a PNG artifact through the exfil chunk path | the loot board's screenshot kind, the inline preview |
| `text` | none | the transcript alone (the default and the degradation target) |

A verb whose output does not parse against its declared kind degrades to
plain text: the UI keeps working, the module just earns no panels. Secret
material in `credential` rows renders masked until revealed, and never
enters the audit chain.

**The verb rows.** The manifest carries one `[[verbs]]` row per verb --
its module-scoped version and an optional per-verb `teamserver` floor -- so
a verb iterates independently of the package and install refuses a version
whose verbs outrun the deployment, naming the verb. A row that names a
`category` is a **descriptor row** (ADR-018): the verb's whole server-side
half as manifest data -- the category (one of `core`, `recon`, `lateral`,
`persist`, `collect`, `exfil`, `tunnel`, `module`, `browser`, `evasion`,
`exploit`), the per-verb OPSEC attribute flags (the `opsec` table, free-form
keys the UI badges), the parameter schema, and the output declaration -- so
a novel namespace opens its issuance gate with zero .NET code. A row
without a category is a version row only: the server-side half lives in an
assembly the operator lists separately, and the two shapes never mix their
fields.

The rows ride the signed canonical form (a tampered verb version, choice
set, or output kind breaks `rod mod verify` exactly like a tampered payload
byte) and mirror into the registry entry, where `rod mod search` finds a
module by verb name and `rod mod info` lists the rows.

## Capability requirements and the conformance report

Compatibility is a property each artifact holds against the contract,
never against each other (architecture.md Sec 15.2, ADR-017): a plugin
declares what the hosting implant must support, an implant declares what
it proved, and a store matches the two -- plugins-times-implants never
multiplies into a test matrix.

**The requirement rows.** `requires` under `[compatibility]`, names from
a closed vocabulary -- the task-path wire capabilities a plugin's verbs
can depend on:

| Name | The hosting implant must |
|------|--------------------------|
| `plugin-loader` | carry the `module.load` family (the loader that hosts plugins) |
| `exfil-chunks` | emit `ExfilChunk` frames (bulk output, implants.md Tier 2) |
| `staged-uploads` | answer `StagedPull` with `StagedChunk` runs (bulk input, Tier 2) |

```toml
[compatibility]
teamserver = "1.0.0"
requires = ["plugin-loader", "exfil-chunks"]
```

Declare `requires` only on the entries that carry an execution half
(server and implant modules): a build unit *is* the implant and an
assets module runs nothing on a target, so a requirement there names
nothing real and the manifest is refused. An unknown name is refused
with the vocabulary named -- a typo never silently mismatches a store
filter. The vocabulary grows additively with the wire tiers. The runtime
truth is the implant's own handshake advertisement; the rows are the
store's static filter and the operator's install-time screen.

A server-side module mirrors its rows onto the `Requires` property of
its `ICapabilityModule` (validated at registration against the same
vocabulary): the manifest is the packaging truth the store and CLI
read, the property is what the live task path sees. The runtime gate
reads it -- a `module.load` naming a registered module is refused at
issuance when the implant's active session did not advertise what the
rows cover, the missing capability named in the refusal. Coverage is
the advertisement's verb set: the loader family is `module.load`, bulk
output rides `file.pull` past its inline cap, downstream bulk rides
`file.push` through the staged arm. An implant with no active session
(a task queued ahead of the next contact) keeps the store-advisory
posture; the gate re-arms on the next handshake.

**The conformance report.** A build unit (a community implant
distribution) carries `[conformance]` instead: what its candidate proved
against the conformance harness
([implants.md](implants.md), "Conformance harness") -- the tier
achieved, the harness generation, the date, the clauses that passed:

```toml
[conformance]
tier = 1
harness = "1.0.0"
date = "2026-01-15"
clauses = ["enroll.public-key-and-token", "handshake.first-frame-ok", "task.round-trip", "signature.verification"]
```

The report is a publisher's self-claim, but a signature-bound one: it
rides the canonical form, so a badge a registry index edits without the
publisher's key breaks verification exactly like a tampered payload
byte. Declare it honestly -- the operator comparing your implant's
report against a plugin's requirements is the collapse doing its job.

## Server-side half: declare the descriptors, or write an assembly

**The manifest path (zero .NET, the default).** A server-entry module's
whole server-side half is its verb rows: fill in each row's `category`,
`opsec` flags, parameters, and output declaration (the grammar above), and
list the module directory under `Capabilities:DescriptorModules` in
`appsettings.json` -- paths are relative to the teamserver binary, and the
build deploys the in-tree set under `modules/` beside the binary:

```json
{
  "Capabilities": {
    "DescriptorModules": [ "modules/hostenum", "/opt/rod/modules/sweep" ]
  }
}
```

That is the whole integration, and it is the path every in-tree reference
module rides:

- The host reads the manifest's name, requirement rows, and descriptor rows
  at startup and registers one module per row. Registration is
  **last-wins over the placeholder** -- every built-in verb (the
  contract-only `evasion.*` / `exploit.*` included) is held by a
  placeholder module precisely so your module replaces it by registration.
- A registered module **widens the task gate**: the registry-backed resolver
  admits the verb for task issuance even when no implant class's reduced set
  lists it. This is the path a novel namespace depends on.
- The module must be whole: every verb row carries its category. A listed
  module with a version-only row would gate some of its verbs and silently
  skip its own -- the host refuses it at startup, naming the row. A module
  whose rows are version-only is an assembly module; it lists under
  `Capabilities:Modules` instead.
- Failures are loud: a listed directory that is missing, a manifest that
  does not parse, an unknown category or kind, or a schema the UI cannot
  render each aborts startup. A red team cannot afford "registered but not
  what the operator deployed".

**The assembly path (when you want server-side code).** The seam a .NET
module rides is unchanged: implement `ICapabilityModule` -- a
registration-only contract carrying exactly one `CapabilityDescriptor`:

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
type under `Capabilities:Modules`:

```json
{
  "Capabilities": {
    "Modules": [ "MyModules.MyPingModule, MyModules" ]
  }
}
```

The loader resolves assemblies **only** by that explicit list (already
loaded, or a same-named dll in the application directory) -- it never scans
directories. A module reaches the process exactly when an operator built it,
placed it, and named it. The tree itself ships no assemblies this way: every
in-tree module's half is descriptor data, and the assembly path is the
escape hatch an operator's own .NET module takes when it wants code the
manifest grammar cannot express.

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

The reference pairs in-tree are the worked examples to copy: the
server-side halves at `modules/hostenum/` and `modules/domainenum/`, the
implant-side halves at `src/implant/rust/modules/hostenum/` and
`src/implant/rust/modules/domainenum/` -- each one verb string declared
on both sides and nothing shared between them.

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
carrying a novel namespace pairs with a server-side descriptor -- the
manifest's verb row (or the `ICapabilityModule` assembly above) that widens
the issuance gate -- two halves, one verb string, nothing else shared.

## A plugin in C (the any-toolchain proof)

The seam's boundaries are ABI-stable, not compiler-stable (architecture.md
Sec 5.4): the six exported symbols on Windows, the length-prefixed stdio
frames on Linux. The Rust SDK is convenience, not requirement -- the same
module in C is a page, which is the whole point. Both shapes below speak
exactly what `rod-plugin-sdk` speaks (ABI and protocol version 1; the SDK
crate is the authority if this page and the code ever drift).

**The Linux shape** -- one `main`, a frame loop over stdin/stdout, a verb
table. Build static (`cc -static -Os`) and the module runs from any
artifact, the musl posture without the musl toolchain:

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The stdio protocol, little-endian (plugin-sdk/src/protocol.rs):
   request  [op:u8][arg:u32][len:u32][len bytes]
   response [version:u8][status:u8][len:u32][len bytes] */
enum { OP_PING = 0, OP_NAME = 1, OP_COUNT = 2, OP_VERB_NAME = 3, OP_RUN = 4 };
enum { ST_OK = 0, ST_FAILED = 1, ST_BAD_REQUEST = 2 };

/* The verbs this module registers, in table order. */
static const char *const verbs[] = { "sweep.portscan" };
#define VERB_COUNT (sizeof verbs / sizeof verbs[0])

static int read_exact(unsigned char *buf, size_t len) {
    return fread(buf, 1, len, stdin) == len ? 0 : -1;
}

static void respond(uint8_t status, const void *payload, uint32_t len) {
    unsigned char head[6] = { 1 /* protocol version */, status };
    memcpy(head + 2, &len, sizeof len);          /* little-endian host */
    fwrite(head, 1, sizeof head, stdout);
    fwrite(payload, 1, len, stdout);
    fflush(stdout);
}

/* One verb's execution half: the opaque argument string in, the output
   out. Print recon findings as JSON lines and the topology view parses
   them (the grammar below on this page). */
static int portscan(const char *args, char *out, size_t out_size) {
    (void)args;
    return snprintf(out, out_size,
                    "{\"host\":\"127.0.0.1\",\"port\":443,\"state\":\"open\"}");
}

int main(void) {
    for (;;) {
        unsigned char head[9];
        if (read_exact(head, sizeof head) != 0)
            return 0;                              /* stdin ended: done */
        uint8_t op = head[0];
        uint32_t arg, len;
        memcpy(&arg, head + 1, sizeof arg);
        memcpy(&len, head + 5, sizeof len);
        unsigned char payload[65536];
        if (len > sizeof payload || read_exact(payload, len) != 0)
            return 1;                              /* a broken frame ends us */
        payload[len < sizeof payload ? len : 0] = 0; /* NUL for the handlers */

        if (op == OP_PING) respond(ST_OK, "", 0);
        else if (op == OP_NAME) respond(ST_OK, "sweep", 5);
        else if (op == OP_COUNT) {
            uint32_t count = (uint32_t)VERB_COUNT;
            respond(ST_OK, &count, sizeof count);
        } else if (op == OP_VERB_NAME && arg < VERB_COUNT) {
            const char *name = verbs[arg];
            respond(ST_OK, name, (uint32_t)strlen(name));
        } else if (op == OP_RUN && arg < VERB_COUNT) {
            char out[65536];
            int n = portscan((const char *)payload, out, sizeof out);
            if (n >= 0) respond(ST_OK, out, (uint32_t)n);
            else respond(ST_FAILED, "portscan failed", 15);
        } else respond(ST_BAD_REQUEST, "", 0);
    }
}
```

**The Windows shape** -- the six `extern "C"` exports the manual PE map
resolves. Strings cross as `RodStr`, a `(ptr, len)` pair, never a
NUL-terminated string; memory a module returns dies in the module's own
`rod_plugin_free`:

```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t *ptr; size_t len; } RodStr;

static const char *const verbs[] = { "sweep.portscan" };
#define VERB_COUNT (sizeof verbs / sizeof verbs[0])

__declspec(dllexport) uint32_t rod_plugin_abi(void) { return 1; }

__declspec(dllexport) RodStr rod_plugin_name(void) {
    return (RodStr){ (uint8_t *)"sweep", 5 };
}

__declspec(dllexport) uint32_t rod_plugin_init(void) {
    return (uint32_t)VERB_COUNT;               /* the verb count */
}

__declspec(dllexport) RodStr rod_plugin_verb_name(uint32_t index) {
    if (index >= VERB_COUNT) return (RodStr){ NULL, 0 };
    const char *name = verbs[index];
    return (RodStr){ (uint8_t *)name, strlen(name) };
}

/* 0 success, 1 a handler failure (the output carries the cause),
   negative a shim error -- the same return grammar the SDK's macro emits. */
__declspec(dllexport) int32_t rod_plugin_run(
    uint32_t index, RodStr arguments, RodStr *out) {
    if (index >= VERB_COUNT) { *out = (RodStr){ NULL, 0 }; return -1; }
    /* Your tradecraft: arguments is the opaque task string; build the
       output in memory you allocate and hand it back through *out. */
    const char *finding = "{\"host\":\"127.0.0.1\",\"port\":443,\"state\":\"open\"}";
    size_t len = strlen(finding);
    uint8_t *copy = malloc(len);
    if (copy == NULL) { *out = (RodStr){ NULL, 0 }; return -3; }
    memcpy(copy, finding, len);
    *out = (RodStr){ copy, len };
    return 0;
}

/* The host frees module memory through here, never itself. */
__declspec(dllexport) void rod_plugin_free(uint8_t *ptr, size_t len) {
    (void)len;
    free(ptr);
}
```

A C module pairs with a server half like any other: declare the verb row
in a `rod-module.toml` (an `implant`-entry package), gate it with a
descriptor or a standard namespace, and `module.load` delivers whichever
artifact the platform built. The Rust SDK remains the comfortable path;
this page is the proof the seam rents no toolchain.

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
profile staged as `rod.profile.json` into the crate root, and a `cargo
build --release --target <triple>` for the requested target. Your tree is
independent and disposable -- coupled to the teamserver only by the wire
contracts (rod.proto, the baked profile file, the sealed envelope), so a
fork tracks the contract, not the teamserver's code.

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

## Shipping a module: init through publish

The whole lifecycle runs on the `rod` CLI over the file contracts --
no account, no portal, no standing service anywhere. The walk below ships
a first module end to end; this page plus `rod mod help <verb>` is the
entire documentation the path needs.

### 1. Scaffold the repository

```
rod mod init my-sweep --entry server --license Apache-2.0
```

The scaffold is the contribution threshold: one directory carrying a
`rod-module.toml` with honest defaults (version 0.1.0, a `my-sweep.run`
verb row, the compatibility floor set to this CLI's platform generation),
template source for the entry kind (`server`, `implant`, `build-unit`, or
`assets`), a README, a `.gitignore`, and the publisher keypair
(`rod-module.key` / `rod-module.pub`, raw Ed25519). **Keep the secret
key**: it is your publisher identity, and a fresh key is a new identity
that every install pinning the old one will refuse. The key never ships
-- publish rejects any packaging rule that would include it.

### 2. Author the manifest

The manifest is the whole contract; every field rides the signed
canonical form, so a tampered anything breaks verification at install and
at `rod mod verify`. The annotated reference is
`modules/hostenum/rod-module.toml` in the tree -- the same file shape an
external module carries. What each part decides:

| Part | Decides | Enforced at |
|------|---------|-------------|
| `[module]` | name (kebab-case), version, entry kind, license, description | publish refuses `UNLICENSED`; the name is what a lock pins a key to |
| `[compatibility] teamserver` | the minimum platform generation the module runs on | install, per version |
| `[compatibility] requires` | the wire capabilities the hosting implant must support (the closed vocabulary below) | install, plus the runtime gate: a module.load onto a session whose advertisement does not cover the rows is refused naming what is missing |
| `[[compatibility.targets]]` | implant-class / platform / arch rows the module claims | surfaced at search and install |
| `[[verbs]]` | each verb's module-scoped version, optional per-verb teamserver floor, its ATT&CK techniques, and -- with a `category` -- the whole descriptor (OPSEC flags, parameter schema, output declaration; ADR-018) | floors at install; techniques feed every coverage face; the descriptor registers the verb at startup |
| `[conformance]` (build units) | what the candidate proved against the conformance harness -- tier, harness generation, date, clauses | surfaced at info and install; rides the signed form |
| `[opsec]` | `lands-on-disk` and the free-text note | shown at search and install -- an operator screens the target impact before fetching |
| `[attack]` | the module-level technique roll-up | must be exactly the union of the verb rows' techniques (or omitted) |
| `[package]` | which files ship (default: everything except bin/obj/dist and keys) | publish |

The verb row's `techniques` is the **coverage declaration** (ADR-007):
`T####` or `T####.###` ids, the authoritative claim of what the verb
covers. It replaces the kernel's mapping for that verb at registration,
mirrors into the registry index, and renders in the coverage matrix --
a technique the kernel's catalog carries no metadata for is fine; it
appears by id alone. Check what your declaration produces before the
pull request:

```
rod mod coverage --path my-sweep
```

### 3. Develop against a live teamserver

Both halves load beside the binary exactly as the sections above
describe: the server-side assembly (or asset tree) dropped and listed
under `Capabilities:Modules` / `Capabilities:AssetModules`, the
implant-side half loaded over the channel with `module.load`. Your tests
travel with the module (`modules/<name>/tests/`), pin its content, and
run in the module CI lane.

### 4. Publish

```
rod mod publish --path my-sweep --registry ~/checkouts/rod-registry
```

Publish packs per `[package]`, signs the canonical form with the secret
key, and writes `dist/my-sweep-<version>.zip` plus the version's index
entry. With `--registry` pointing at a local rod-registry checkout the
entry lands under `modules/my-sweep.json`; **publication is the pull
request, never a push the tool makes** -- `git add modules/ commit` and
open the PR against the tap. The registry is a git repository in the
Homebrew-tap shape under the Rod organization with merge rights held by
review; third-party taps work by construction (`--registry` takes any
git URL or local checkout).

Publish refuses two drifts on purpose: republishing an indexed version
with different content (bump `module.version`), and a package whose
selection would include key material.

### 5. What the reviewer and the operator see

The review is the trust model, not a formality: publishers sign, the
registry vouches for nothing. The reviewer compares the entry's key
fingerprint with the publisher's out-of-band channel, then the operator
side is three commands -- `rod mod search` (by name, verb, technique, or
description), `rod mod info my-sweep` (every version with digest,
fingerprint, floors, and technique rows), and `rod mod install
my-sweep@1.0.0`, which verifies the package digest, re-derives the
canonical form from the extracted files, checks the signature, enforces
the compatibility and per-verb floors, and pins the key in
`rod.modules.lock.json` -- trust on first use. `rod mod verify` re-proves
the installed tree offline afterwards. A later version under a different
key fails the install loudly; that is the pin doing its job.

### Version discipline

The module version and the verb versions iterate independently: a verb
row's `version` is the verb's own line (bump it when the verb's behavior
or schema changes), the module version is the package's. The registry
indexes every published version; operators install exact versions and
upgrade by naming them.

## What the core ships, and where your module sits

The reference set is the standard, documented surface (architecture.md
Sec 13); everything beyond it -- in-the-wild zero-days, weaponized PoCs,
novel tradecraft -- lives in modules like yours, arriving through the module
seams. The core keeps the interfaces, registration, dispatch, and data
models; the tradecraft is yours.
