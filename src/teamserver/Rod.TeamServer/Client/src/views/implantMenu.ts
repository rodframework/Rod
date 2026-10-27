import type { Implant } from '../api'
import type { MenuEntry, MenuItem } from '../components/ContextMenu'

// The per-implant context menu shared by the fleet table and the session
// console: the capability verbs an operator reaches for, grouped the way the
// categories already group them, each entry gated on the implant's class.
// Every item carries a hover title that says what it does -- the menu is
// scanned, not studied, so the label names the action and the title carries
// the one sentence behind it. (Labels deliberately end without an ellipsis;
// the desktop "opens a dialog" dot convention read as clipping here.)

// The class verb table mirrored client-side for menu gating, carrying only
// the verbs the menu below gates on. The server's ImplantClassCapabilities
// (the issuance gate) is the authority; this mirror only decides what the
// menu offers, exactly like the channel-verb mirror -- the server still
// refuses anything this table gets wrong. Verbs the menu never offers
// (lateral, exfil, the tunnel pair) are reached from the session console's
// quick commands or the raw-task form and need no row here; a Pivot implant
// therefore gates every menu verb off.
const CLASS_VERBS: Record<string, readonly string[]> = {
  Implant: [
    'shell.exec', 'shell.interact', 'file.push', 'file.pull', 'fs.list', 'proc.kill',
    'beacon.sleep',
    'recon.portscan', 'recon.hostenum', 'recon.service', 'recon.ps',
    'persist.install', 'persist.remove', 'persist.list',
    'collect.cred', 'collect.screenshot',
    'module.load', 'module.unload', 'module.list',
  ],
  WebShell: ['shell.exec'],
  Ephemeral: ['shell.exec'],
  Pivot: [],
  Browser: [
    'browser.fingerprint', 'browser.cookies', 'browser.dom',
    'browser.screenshot', 'browser.redirect', 'browser.prompt',
  ],
}

function classVerbs(klass: string): ReadonlySet<string> {
  return new Set(CLASS_VERBS[klass] ?? [])
}

// The zero-argument verbs the menu issues outright. Shared with the command
// palette so both surfaces make the same direct-or-dialog call; a verb this
// mirror misses simply opens the raw-arguments dialog instead -- the server's
// gates remain the authority either way.
export const DIRECT_VERBS: readonly string[] = [
  'recon.ps', 'recon.hostenum', 'collect.screenshot', 'persist.list',
  'browser.fingerprint', 'browser.cookies', 'browser.screenshot',
  'module.list',
]

export interface ImplantMenuActions {
  // Open the session console. Omitted where it would be a no-op (the console
  // itself) -- the menu's Interact entry follows it.
  onConsole?: () => void
  // Start the live interactive shell channel (shell.interact).
  onShell: () => void
  // Issue a zero-argument verb directly; the caller owns any confirmation.
  onIssue: (verb: string) => void
  // Open the per-verb dialog for an argument-bearing verb.
  onDialog: (verb: string) => void
  onProcesses: () => void
  onFiles: () => void
  onNotes?: () => void
  // Save a task snippet from this console's recent transcript (the console
  // alone offers it -- the flow reads the transcript it sits on).
  onSaveSnippet?: () => void
  onRetire?: () => void
}

export function implantMenuEntries(
  implant: Implant,
  actions: ImplantMenuActions,
  advertised?: readonly string[],
): MenuEntry[] {
  const verbs = classVerbs(implant.class)
  // ADR-017's runtime half, mirrored client-side: the session's handshake
  // advertisement decides whether the module family is loadable here at all.
  // Undefined (no live session known to the caller) stays permissive -- the
  // server's issuance gate remains the authority, and an offline implant's
  // queued tasking keeps the store-advisory posture.
  const moduleFamilyHeld =
    advertised === undefined || advertised.some((verb) => verb.toLowerCase() === 'module.load')
  const push = (entry: MenuItem, verb: string, requiresModuleFamily = false) => {
    entry.disabled =
      !verbs.has(verb) || !!implant.retiredAt || (requiresModuleFamily && !moduleFamilyHeld)
    return entry
  }

  const entries: MenuEntry[] = []
  if (actions.onConsole) {
    entries.push({
      kind: 'item',
      label: 'Interact',
      icon: 'terminal',
      title: 'Open this implant\'s session console',
      onSelect: actions.onConsole,
    })
    entries.push({ kind: 'sep' })
  }
  entries.push(
    { kind: 'label', label: 'Beacon' },
    push(
      {
        kind: 'item',
        label: 'Contact interval',
        icon: 'clock',
        opensDialog: true,
        title: 'beacon.sleep -- retune the live contact cadence (e.g. 10s, 5m, or 0 0 for back-to-back, near-interactive polling)',
        onSelect: () => actions.onDialog('beacon.sleep'),
      },
      'beacon.sleep',
    ),
    { kind: 'label', label: 'Shell' },
    push(
      {
        kind: 'item',
        label: 'Run command',
        icon: 'terminal',
        opensDialog: true,
        title: 'shell.exec -- run one command through the system shell and return its output',
        onSelect: () => actions.onDialog('shell.exec'),
      },
      'shell.exec',
    ),
    push(
      {
        kind: 'item',
        label: 'Interactive shell',
        icon: 'terminal',
        title: 'shell.interact -- a live typing channel: real terminal semantics on Linux, line-based elsewhere',
        onSelect: actions.onShell,
      },
      'shell.interact',
    ),
    { kind: 'label', label: 'Files' },
    push(
      {
        kind: 'item',
        label: 'Browse files',
        icon: 'folder',
        title: 'fs.list -- walk the target\'s filesystem; cached between visits, refreshed on demand',
        onSelect: actions.onFiles,
      },
      'fs.list',
    ),
    push(
      {
        kind: 'item',
        label: 'Upload file',
        icon: 'package',
        opensDialog: true,
        title: 'file.push -- push a local file to a target path',
        onSelect: () => actions.onDialog('file.push'),
      },
      'file.push',
    ),
    push(
      {
        kind: 'item',
        label: 'Download file',
        icon: 'package',
        opensDialog: true,
        title: 'file.pull -- pull a target file back (inline when small, else to the artifact store)',
        onSelect: () => actions.onDialog('file.pull'),
      },
      'file.pull',
    ),
    { kind: 'label', label: 'Processes' },
    push(
      {
        kind: 'item',
        label: 'Browse processes',
        icon: 'list',
        title: 'recon.ps -- list the host\'s processes; cached between visits, refreshed on demand',
        onSelect: actions.onProcesses,
      },
      'recon.ps',
    ),
    push(
      {
        kind: 'item',
        label: 'Kill pid',
        icon: 'list',
        danger: true,
        opensDialog: true,
        title: 'proc.kill -- terminate one process by pid (observable, irreversible)',
        onSelect: () => actions.onDialog('proc.kill'),
      },
      'proc.kill',
    ),
    { kind: 'label', label: 'Recon' },
    push(
      {
        kind: 'item',
        label: 'Host facts',
        icon: 'cpu',
        title: 'recon.hostenum -- local host facts (os, users, network) in one dump',
        onSelect: () => actions.onIssue('recon.hostenum'),
      },
      'recon.hostenum',
    ),
    push(
      {
        kind: 'item',
        label: 'Port scan',
        icon: 'globe',
        opensDialog: true,
        title: 'recon.portscan -- sweep a host\'s port range',
        onSelect: () => actions.onDialog('recon.portscan'),
      },
      'recon.portscan',
    ),
    push(
      {
        kind: 'item',
        label: 'Probe services',
        icon: 'globe',
        opensDialog: true,
        title: 'recon.service -- fingerprint the services behind specific ports',
        onSelect: () => actions.onDialog('recon.service'),
      },
      'recon.service',
    ),
    { kind: 'label', label: 'Collect' },
    push(
      {
        kind: 'item',
        label: 'Screenshot',
        icon: 'file',
        title: 'collect.screenshot -- capture the target\'s display',
        onSelect: () => actions.onIssue('collect.screenshot'),
      },
      'collect.screenshot',
    ),
    push(
      {
        kind: 'item',
        label: 'Credentials',
        icon: 'users',
        opensDialog: true,
        title: 'collect.cred -- harvest stored credentials',
        onSelect: () => actions.onDialog('collect.cred'),
      },
      'collect.cred',
    ),
    { kind: 'label', label: 'Persistence' },
    push(
      {
        kind: 'item',
        label: 'List',
        icon: 'list',
        title: 'persist.list -- the persistence mechanisms this implant installed',
        onSelect: () => actions.onIssue('persist.list'),
      },
      'persist.list',
    ),
    push(
      {
        kind: 'item',
        label: 'Install',
        icon: 'clock',
        opensDialog: true,
        title: 'persist.install -- install a persistence mechanism',
        onSelect: () => actions.onDialog('persist.install'),
      },
      'persist.install',
    ),
    push(
      {
        kind: 'item',
        label: 'Remove',
        icon: 'clock',
        opensDialog: true,
        title: 'persist.remove -- remove an installed persistence mechanism',
        onSelect: () => actions.onDialog('persist.remove'),
      },
      'persist.remove',
    ),
    { kind: 'label', label: 'Modules' },
    push(
      {
        kind: 'item',
        label: 'Load module',
        icon: 'package',
        opensDialog: true,
        title: 'module.load -- deliver a plugin module as staged content; its verbs join this implant\'s advertised set',
        onSelect: () => actions.onDialog('module.load'),
      },
      'module.load',
      true,
    ),
    push(
      {
        kind: 'item',
        label: 'List modules',
        icon: 'list',
        title: 'module.list -- the modules this implant carries and the verbs they registered',
        onSelect: () => actions.onIssue('module.list'),
      },
      'module.list',
      true,
    ),
    push(
      {
        kind: 'item',
        label: 'Unload module',
        icon: 'x',
        opensDialog: true,
        title: 'module.unload -- drop a loaded module and the routes it registered',
        onSelect: () => actions.onDialog('module.unload'),
      },
      'module.unload',
      true,
    ),
    { kind: 'label', label: 'Browser' },
    push(
      {
        kind: 'item',
        label: 'Fingerprint',
        icon: 'cpu',
        title: 'browser.fingerprint -- the hooked browser\'s navigator facts as JSON',
        onSelect: () => actions.onIssue('browser.fingerprint'),
      },
      'browser.fingerprint',
    ),
    push(
      {
        kind: 'item',
        label: 'Read cookies',
        icon: 'globe',
        title: 'browser.cookies -- the current origin\'s document.cookie (non-HttpOnly only)',
        onSelect: () => actions.onIssue('browser.cookies'),
      },
      'browser.cookies',
    ),
    push(
      {
        kind: 'item',
        label: 'Read DOM',
        icon: 'list',
        opensDialog: true,
        title: 'browser.dom -- the page\'s outerHTML, optionally narrowed by a CSS selector',
        onSelect: () => actions.onDialog('browser.dom'),
      },
      'browser.dom',
    ),
    push(
      {
        kind: 'item',
        label: 'Screenshot',
        icon: 'file',
        title: 'browser.screenshot -- rasterize the DOM into a PNG artifact (structure and inline styling)',
        onSelect: () => actions.onIssue('browser.screenshot'),
      },
      'browser.screenshot',
    ),
    push(
      {
        kind: 'item',
        label: 'Redirect tab',
        icon: 'logout',
        danger: true,
        opensDialog: true,
        title: 'browser.redirect -- navigate the tab to a URL (the hook dies with the page it leaves)',
        onSelect: () => actions.onDialog('browser.redirect'),
      },
      'browser.redirect',
    ),
    push(
      {
        kind: 'item',
        label: 'Prompt user',
        icon: 'terminal',
        opensDialog: true,
        title: 'browser.prompt -- show the user a dialog and return the answer',
        onSelect: () => actions.onDialog('browser.prompt'),
      },
      'browser.prompt',
    ),
  )
  if (actions.onNotes || (actions.onRetire && !implant.retiredAt) || actions.onSaveSnippet) {
    entries.push({ kind: 'sep' })
    if (actions.onNotes) {
      entries.push({
        kind: 'item',
        label: 'Notes',
        icon: 'list',
        title: 'Free-text notes on this implant, attributed and durable',
        onSelect: actions.onNotes,
      })
    }
    if (actions.onSaveSnippet) {
      entries.push({
        kind: 'item',
        label: 'Save task snippet',
        icon: 'copy',
        title: 'Pick recent transcript lines and save them as one named sequence, replayed from the palette',
        onSelect: actions.onSaveSnippet,
      })
    }
    if (actions.onRetire && !implant.retiredAt) {
      entries.push({
        kind: 'item',
        label: 'Retire (burn)',
        icon: 'logout',
        danger: true,
        title: 'Take the implant out of operation: refused at handshake and untaskable afterwards',
        onSelect: actions.onRetire,
      })
    }
  }
  return entries
}
