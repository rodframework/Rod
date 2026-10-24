import { useCallback, useEffect, useRef, useState } from 'react'
import './App.css'
import { type Engagement, type LoginInput, type SessionOperator, getSessionOperator, listEngagements, login, logout } from './api'
import { CommandPalette } from './components/CommandPalette'
import { Icon } from './components/Icons'
import { EngagementNav } from './components/Nav'
import { useLive } from './shell'
import { resolveEngagementLocation } from './slots'
import { SLOTS, engagementPath } from './slots'
import { useTableDensity } from './clientPrefs'
import { EngagementView } from './views/EngagementView'
import { EngagementsView } from './views/EngagementsView'
import { HomeView } from './views/HomeView'
import { SettingsView } from './views/SettingsView'
import { SystemView } from './views/SystemView'
import { RedirectorsView } from './views/RedirectorsView'
import { CoverageView } from './views/CoverageView'
import { DiagnosticsView } from './views/DiagnosticsView'
import { LoginView } from './views/LoginView'

// Operator UI shell: the topbar carries what is global -- the breadcrumb,
// the command palette, the global surfaces (home, engagements, redirectors,
// settings, system), the live engagement state, and the signed-in operator
// -- while the sidebar is purely contextual: the brand (itself a link home),
// the engagement's tab groups inside an engagement, and a
// recent-engagements quick-jump outside one. Each open engagement holds a
// Server-Sent Events stream open so every connected operator sees tasking,
// results, and presence in real time.
//
// The session is the teamserver's cookie: GET /operators/me resolves the signed-
// in operator (never a client-generated id), and an unauthenticated browser is
// routed to the login view. Navigation is hash-based so the host's static-file
// fallback keeps deep links working without a server-side router.

type Route =
  | { kind: 'home' }
  | { kind: 'engagements' }
  | {
      kind: 'engagement'
      engagementId: string
      // Raw hash segments; App resolves them (legacy tabs included) into
      // the slot/sub pair the engagement view renders.
      slot: string
      sub?: string
      entityId?: string
      interact?: boolean
    }
  | { kind: 'coverage' }
  | { kind: 'settings' }
  | { kind: 'system' }
  | { kind: 'redirectors' }
  | { kind: 'diagnostics' }

function parseHash(): Route {
  const hash = window.location.hash.replace(/^#/, '')
  // Most specific first: the session console in both its shapes (the
  // pre-slot implants drill-in, and the slot-shaped interact route), then
  // any entity detail, sub-surface, slot, and bare engagement route.
  const consoleRoute = /^\/engagements\/([\da-fA-F-]+)\/implants\/([\da-fA-F-]+)\/?$/.exec(hash)
  if (consoleRoute) {
    return {
      kind: 'engagement',
      engagementId: consoleRoute[1],
      slot: 'action',
      sub: 'implants',
      entityId: consoleRoute[2],
      interact: true,
    }
  }
  const detail = /^\/engagements\/([\da-fA-F-]+)\/(\w+)\/(\w+)\/([\da-fA-F-]+)(?:\/(interact))?\/?$/.exec(
    hash,
  )
  if (detail) {
    return {
      kind: 'engagement',
      engagementId: detail[1],
      slot: detail[2],
      sub: detail[3],
      entityId: detail[4],
      interact: detail[5] === 'interact' || undefined,
    }
  }
  const subbed = /^\/engagements\/([\da-fA-F-]+)\/(\w+)\/(\w+)\/?$/.exec(hash)
  if (subbed) return { kind: 'engagement', engagementId: subbed[1], slot: subbed[2], sub: subbed[3] }
  const slotted = /^\/engagements\/([\da-fA-F-]+)\/(\w+)\/?$/.exec(hash)
  if (slotted) return { kind: 'engagement', engagementId: slotted[1], slot: slotted[2] }
  const match = /^\/engagements\/([\da-fA-F-]+)\/?$/.exec(hash)
  if (match) return { kind: 'engagement', engagementId: match[1], slot: 'overview' }
  if (/^\/engagements\/?$/.test(hash)) return { kind: 'engagements' }
  if (/^\/redirectors\/?$/.test(hash)) return { kind: 'redirectors' }
  if (/^\/coverage\/?$/.test(hash)) return { kind: 'coverage' }
  if (/^\/settings\/?$/.test(hash)) return { kind: 'settings' }
  if (/^\/system\/?$/.test(hash)) return { kind: 'system' }
  if (/^\/diagnostics\/?$/.test(hash)) return { kind: 'diagnostics' }
  // Everything else -- the bare hash, #/home, and any unrecognized link --
  // lands on the dashboard, so the console opens and falls back somewhere
  // orienting.
  return { kind: 'home' }
}

function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseHash())
  useEffect(() => {
    const onHash = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])
  return route
}

// Up to two leading characters of a handle, for avatar tiles.
function initials(handle: string): string {
  return handle.replace(/[^a-zA-Z0-9]/g, '').slice(0, 2).toUpperCase() || '?'
}

// The engagement's display name for the crumb, resolved off the list (the
// API has no single-engagement read) and cached for the session. Roster
// mutations reset the shared load so a created or renamed engagement
// resolves on the spot.
const engagementNames = new Map<string, string>()
let engagementNamesLoad: Promise<void> | null = null

function useEngagementName(engagementId: string): string | undefined {
  const [name, setName] = useState<string | undefined>(engagementNames.get(engagementId))

  const resolve = useCallback((): Promise<void> => {
    // A failed read resets the load so a later navigation retries.
    engagementNamesLoad ??= listEngagements()
      .then((all) => {
        for (const e of all) engagementNames.set(e.engagementId, e.name)
      })
      .catch(() => {
        engagementNamesLoad = null
      })
    return engagementNamesLoad
  }, [])

  useEffect(() => {
    let cancelled = false
    const apply = () => {
      const resolved = engagementNames.get(engagementId)
      if (!cancelled) setName(resolved)
    }
    const load = () => void resolve().then(apply)
    // A roster change can rename this engagement or be the reason it exists;
    // re-read rather than showing a stale or missing name.
    const onRosterChanged = () => {
      engagementNamesLoad = null
      load()
    }
    if (engagementNames.get(engagementId) === undefined) load()
    else apply()
    window.addEventListener('rod-engagements-changed', onRosterChanged)
    return () => {
      cancelled = true
      window.removeEventListener('rod-engagements-changed', onRosterChanged)
    }
  }, [engagementId, resolve])

  return name
}

// Outside an engagement the sidebar has no context to navigate, so it carries
// the recent list instead: quick jumps into the workspaces the operator
// actually uses, newest first. Sealed records stay off it -- the engagements
// list remains the full account.
function RecentEngagements() {
  const [items, setItems] = useState<Engagement[]>([])

  useEffect(() => {
    let cancelled = false
    const load = () => {
      listEngagements()
        .then((all) => {
          if (!cancelled) {
            setItems(
              all
                .filter((e) => !e.retiredAt)
                .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
                .slice(0, 6),
            )
          }
        })
        .catch(() => {
          // A failed read just leaves the quick-jump as it is; the list page
          // is the authoritative surface.
        })
    }
    load()
    // A roster change (create, close-out) re-sorts the quick-jump on the
    // spot instead of waiting for a full reload.
    window.addEventListener('rod-engagements-changed', load)
    return () => {
      cancelled = true
      window.removeEventListener('rod-engagements-changed', load)
    }
  }, [])

  if (items.length === 0) return null

  return (
    <nav className="sidebar-nav">
      <div className="nav-group">
        <div className="nav-group-label">Recent engagements</div>
        {items.map((e) => (
          <a
            key={e.engagementId}
            className="nav-item"
            href={`#/engagements/${e.engagementId}`}
            title={`${e.name} (${e.engagementId.slice(0, 8)})`}
          >
            <Icon name="globe" />
            <span className="label">{e.name}</span>
          </a>
        ))}
      </div>
    </nav>
  )
}

// The density toggle (ADR-013): comfortable is the reading posture,
// compact the scanning one. Browser-local and instant -- the shell's
// data attribute cascades into every table and feed row.
function DensityToggle() {
  const [density, setDensity] = useTableDensity()
  const compact = density === 'compact'
  return (
    <button
      className="ghost sm"
      onClick={() => setDensity(compact ? 'comfortable' : 'compact')}
      title={
        compact
          ? 'Tables are compact (scanning posture). Click for comfortable rows.'
          : 'Tables are comfortable (reading posture). Click for compact rows.'
      }
    >
      {compact ? 'Compact' : 'Comfortable'}
    </button>
  )
}

// The engagement's position in the topbar: its name once resolved, then the
// short id chip every other surface joins by.
function EngagementCrumb({ engagementId }: { engagementId: string }) {
  const name = useEngagementName(engagementId)
  return name ? (
    <>
      <span className="crumb-name" title={name}>
        {name}
      </span>
      <Icon name="chevronRight" className="sep-icon" />
      <span className="current" title={engagementId}>
        {engagementId.slice(0, 8)}
      </span>
    </>
  ) : (
    <span className="current" title={engagementId}>
      {engagementId.slice(0, 8)}
    </span>
  )
}

function Topbar({
  route,
  operator,
  onOpenPalette,
  onLogout,
}: {
  route: Route
  operator: SessionOperator
  onOpenPalette: () => void
  onLogout: () => void
}) {
  const live = useLive()
  // Others' presence; the signed-in operator sits at the corner as their own
  // identity instead of appearing inside the stack a second time.
  const others = (live?.operators ?? []).filter((o) => o.id !== operator.operatorId)
  return (
    <header className="topbar">
      {/* The crumb is position, not navigation: the way back to the roster
          is the topbar's Engagements anchor, so no leading link duplicates
          it. */}
      <div className="topbar-crumb">
        {route.kind === 'home' && <span className="current">Home</span>}
        {route.kind === 'engagement' && <EngagementCrumb engagementId={route.engagementId} />}
        {(route.kind === 'settings' ||
          route.kind === 'system' ||
          route.kind === 'redirectors' ||
          route.kind === 'diagnostics') && (
          <span className="current">
            {route.kind === 'settings'
              ? 'Settings'
              : route.kind === 'redirectors'
                ? 'Redirectors'
                : route.kind === 'diagnostics'
                  ? 'Diagnostics'
                  : 'System'}
          </span>
        )}
        {route.kind === 'coverage' && <span className="current">Coverage</span>}
      </div>
      <div className="topbar-actions">
        <button
          className="ghost sm palette-trigger"
          onClick={onOpenPalette}
          title="Open the command palette (Ctrl+K)"
        >
          Search… <kbd>ctrl k</kbd>
        </button>
        <DensityToggle />
        {live && route.kind === 'engagement' && (
          <>
            <span
              className="chip"
              title={live.connected ? 'Live stream connected' : 'Live stream reconnecting…'}
            >
              <span className={`live-dot${live.connected ? '' : ' offline'}`} />
              {live.connected ? 'Live' : 'Reconnecting'}
            </span>
            <span
              className="chip optional"
              title={`${live.onlineCount} of ${live.implantCount} enrolled implants online`}
            >
              <span className="dot online" />
              <strong>{live.onlineCount}</strong>
              <span>/ {live.implantCount} online</span>
            </span>
            {others.length > 0 && (
              <span className="avatar-stack" title={others.map((o) => o.handle).join(', ')}>
                {others.slice(0, 4).map((o) => (
                  <span key={o.id} className="avatar">
                    {initials(o.handle || o.id)}
                  </span>
                ))}
              </span>
            )}
          </>
        )}
        {/* The global surfaces, labeled: navigation that belongs to no
            single context rides the topbar instead of the sidebar's context
            navigation. Home leads: the dashboard is the landing surface the
            brand and the bare hash both resolve to. */}
        <a
          className={`topbar-link${route.kind === 'home' ? ' active' : ''}`}
          href="#/"
          title="The home dashboard: posture and activity across your engagements"
        >
          <Icon name="home" />
          <span className="label">Home</span>
        </a>
        <a
          className={`topbar-link${route.kind === 'engagements' ? ' active' : ''}`}
          href="#/engagements"
          title="The engagements list"
        >
          <Icon name="globe" />
          <span className="label">Engagements</span>
        </a>
        <a
          className={`topbar-link${route.kind === 'redirectors' ? ' active' : ''}`}
          href="#/redirectors"
          title="The enrolled redirector fleet (architecture.md Sec 8): roster, enrollment credentials, retirement"
        >
          <Icon name="radio" />
          <span className="label">Redirectors</span>
        </a>
        <a
          className={`topbar-link${route.kind === 'coverage' ? ' active' : ''}`}
          href="#/coverage"
          title="The ATT&CK coverage matrix: what this deployment can do, and the gaps that read as the work queue"
        >
          <Icon name="target" />
          <span className="label">Coverage</span>
        </a>
        <a
          className={`topbar-link${route.kind === 'settings' ? ' active' : ''}`}
          href="#/settings"
          title="Teamserver runtime settings"
        >
          <Icon name="settings" />
          <span className="label">Settings</span>
        </a>
        <a
          className={`topbar-link${route.kind === 'system' ? ' active' : ''}`}
          href="#/system"
          title="The host and its build environment -- detected toolchains and what is missing"
        >
          <Icon name="cpu" />
          <span className="label">System</span>
        </a>
        {operator.role === 'admin' && (
          <a
            className={`topbar-link${route.kind === 'diagnostics' ? ' active' : ''}`}
            href="#/diagnostics"
            title="The deployment's own health -- beacon turnaround, queue depth, operator streams, build durations, loaded modules"
          >
            <Icon name="activity" />
            <span className="label">Diagnostics</span>
          </a>
        )}
        <Identity operator={operator} onLogout={onLogout} />
      </div>
    </header>
  )
}

// The signed-in operator at the topbar's right corner: the identity the
// server's session vouches for, the viewing-scope mark when the session
// cannot act, and sign-out underneath. The menu closes on any click outside
// it, so a navigation click never leaves it dangling.
function Identity({
  operator,
  onLogout,
}: {
  operator: SessionOperator
  onLogout: () => void
}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  return (
    <div className="identity" ref={root}>
      <button
        className={`identity-button${open ? ' open' : ''}`}
        onClick={() => setOpen((v) => !v)}
        title={`Signed in as ${operator.handle}`}
      >
        <span className="avatar">{initials(operator.handle)}</span>
        <span className="handle">{operator.handle}</span>
      </button>
      {open && (
        <div className="identity-menu">
          <div className="identity-menu-head">
            {/* The handle is the identity the crew reads; the account's id
                stays one hover away for support work. */}
            <strong title={operator.operatorId}>{operator.handle}</strong>
            <span
              className="muted"
              title={
                operator.role === 'admin'
                  ? 'Deployment admin: provisions accounts, holds the disable switch, writes the fleet and runtime settings.'
                  : 'Deployment member: self-service over your own password and tokens; deployment management belongs to the admin.'
              }
            >
              {operator.role === 'admin' ? 'admin' : 'member'}
            </span>
          </div>
          <button className="link" onClick={onLogout}>
            Sign out
          </button>
        </div>
      )}
    </div>
  )
}

function App() {
  const route = useRoute()
  // The operator identity is whatever the teamserver says it is over the session
  // cookie. null while the session is being resolved or when no session exists;
  // the route guard renders the login view in the latter case.
  const [operator, setOperator] = useState<SessionOperator | null>(null)
  const [contactg, setContactg] = useState(true)
  // The command palette (docs/operations/operator-ui.md): Ctrl+K opens it
  // anywhere in the authenticated shell, Esc closes it.
  const [paletteOpen, setPaletteOpen] = useState(false)
  // The density every table and feed row inherits (ADR-013).
  const [density] = useTableDensity()

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen((open) => !open)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Slot jumps (ADR-013's keyboard-first console): g then the slot's
  // number (1-7, the sidebar's order) navigates while an engagement is
  // open. The chord dies on a pause, any other key, a modifier, or focus
  // in a field -- it must never eat an operator's typing.
  useEffect(() => {
    let goAt = 0
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const typing =
        !!target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable)
      if (typing || event.ctrlKey || event.metaKey || event.altKey) {
        goAt = 0
        return
      }
      if (event.key === 'g' || event.key === 'G') {
        goAt = Date.now()
        return
      }
      if (goAt > 0 && Date.now() - goAt < 1500 && /^[1-7]$/.test(event.key)) {
        goAt = 0
        if (route.kind === 'engagement') {
          const slot = SLOTS[Number(event.key) - 1]
          window.location.hash = engagementPath(route.engagementId, slot.subs[0].id)
        }
        return
      }
      goAt = 0
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [route])

  useEffect(() => {
    let cancelled = false
    getSessionOperator()
      .then((op) => {
        if (!cancelled) setOperator(op)
      })
      .catch(() => {
        // No session cookie (401); stay on the login view.
      })
      .finally(() => {
        if (!cancelled) setContactg(false)
      })
    // A mid-session 401 (cookie expired or revoked) anywhere in the API layer
    // returns the shell to the login view instead of leaving a half-working UI
    // that errors on every call.
    const onUnauthorized = () => setOperator(null)
    window.addEventListener('rod-unauthorized', onUnauthorized)
    return () => {
      cancelled = true
      window.removeEventListener('rod-unauthorized', onUnauthorized)
    }
  }, [])

  const onLogin = useCallback(async (input: LoginInput) => {
    await login(input)
    setOperator(await getSessionOperator())
  }, [])

  const onLogout = useCallback(async () => {
    await logout()
    setOperator(null)
  }, [])

  if (contactg) {
    return (
      <div className="boot">
        <div className="boot-inner">
          <span className="spinner" />
          <span className="muted">Loading session…</span>
        </div>
      </div>
    )
  }

  if (!operator) {
    return <LoginView onLogin={onLogin} />
  }

  // The route's raw slot/sub segments resolve through the slot module
  // (legacy pre-slot tabs included); anything unrecognized lands on the
  // timeline -- the orienting surface.
  const location =
    route.kind === 'engagement' ? resolveEngagementLocation(route) : null

  return (
    <div className="shell" data-density={density}>
      <aside className="sidebar">
        <a className="brand" href="#/" title="Back to the home dashboard">
          <img className="brand-logo" src="brand-logo.png" alt="" width="28" height="28" />
          <span className="brand-text">
            <span className="brand-name">Rod</span>
            <span className="brand-sub">teamserver</span>
          </span>
        </a>
        {route.kind === 'engagement' ? (
          <nav className="sidebar-nav">
            <EngagementNav
              engagementId={route.engagementId}
              active={location?.slot.id ?? 'overview'}
            />
          </nav>
        ) : (
          <RecentEngagements />
        )}
      </aside>
      <div className="frame">
        <Topbar
          route={route}
          operator={operator}
          onOpenPalette={() => setPaletteOpen(true)}
          onLogout={() => void onLogout()}
        />
        <main className="main">
          {route.kind === 'home' ? (
            <HomeView />
          ) : route.kind === 'engagements' ? (
            <EngagementsView />
          ) : route.kind === 'settings' ? (
            <SettingsView operator={operator} />
          ) : route.kind === 'system' ? (
            <SystemView />
          ) : route.kind === 'redirectors' ? (
            <RedirectorsView operator={operator} />
          ) : route.kind === 'coverage' ? (
            <CoverageView />
          ) : route.kind === 'diagnostics' ? (
            operator.role === 'admin' ? (
              <DiagnosticsView />
            ) : (
              // The route answers the admin claim with 403 for everyone else;
              // say so plainly instead of rendering a page of errors.
              <p className="muted">Diagnostics is the deployment admin's surface.</p>
            )
          ) : route.kind === 'engagement' && location ? (
            <EngagementView
              engagementId={route.engagementId}
              operator={operator}
              sub={location.sub.id}
              entityId={location.entityId}
              interact={location.interact}
            />
          ) : null}
        </main>
      </div>
      {paletteOpen && (
        <CommandPalette
          engagementId={route.kind === 'engagement' ? route.engagementId : null}
          contextImplantId={
            route.kind === 'engagement' && location?.sub.id === 'implants'
              ? (location.entityId ?? null)
              : null
          }
          onClose={() => setPaletteOpen(false)}
        />
      )}
    </div>
  )
}

export default App
