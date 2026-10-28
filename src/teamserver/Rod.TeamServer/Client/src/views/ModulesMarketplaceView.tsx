import { useCallback, useEffect, useState } from 'react'
import {
  type InstalledModule,
  type RegistryEntrySummary,
  installModule,
  listInstalledModules,
  listRegistryModules,
  uninstallModule,
} from '../api'
import { HelpHint } from '../components/HelpHint'

// The module marketplace (ADR-023): the operator console's day-2 module
// workflow, on the system page beside the build environment it feeds.
// The left column is what the deployment holds -- installed through here
// or listed in its config -- with each package's entry kind and the
// publisher fingerprint its trust pins to. The right column is the
// registry: browse, install (verified through the trust chain server
// side, hot-registered, audit-chained to the acting operator), and the
// installed list updates without a restart.
//
// What this surface installs is data: descriptor rows, plugin artifacts,
// extension sources, build-unit tables, asset files. The in-proc assembly
// path stays a deployment owner's config-listed decision -- code that runs
// inside the teamserver is never a click away.

const ENTRY_LABELS: Record<string, string> = {
  server: 'server descriptors',
  plugin: 'portable plugin',
  extension: 'compiled-in extension',
  'build-unit': 'external build unit',
  assets: 'assets',
}

export function ModulesMarketplaceView() {
  const [installed, setInstalled] = useState<InstalledModule[]>([])
  const [registry, setRegistry] = useState<RegistryEntrySummary[]>([])
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [installedList, registryList] = await Promise.all([
        listInstalledModules(),
        listRegistryModules().catch(() => [] as RegistryEntrySummary[]),
      ])
      setInstalled(installedList)
      setRegistry(registryList)
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const onInstall = async (name: string) => {
    setBusy(name)
    setNotice(null)
    try {
      await installModule(name, null)
      setNotice(`Installed ${name}.`)
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  const onUninstall = async (name: string) => {
    if (!window.confirm(`Uninstall ${name}? Its verbs keep their last registration; its assets and build-side registrations retract.`))
      return
    setBusy(name)
    setNotice(null)
    try {
      await uninstallModule(name)
      setNotice(`Removed ${name}.`)
      await refresh()
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(null)
    }
  }

  const installedNames = new Set(installed.map((m) => m.name))
  const upgradable = registry.filter((entry) => !installedNames.has(entry.name))

  return (
    <section className="view">
      <h2>
        Modules
        <HelpHint>
          The module ecosystem's console surface: what this deployment holds, and the registry it
          can pull from. Every install verifies the package's signature through the trust chain and
          records the action in the audit ledger; every install is live -- verbs, assets, and build
          units register without a restart.
        </HelpHint>
      </h2>
      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}
      <div className="twoColumn">
        <div className="card">
          <h3>Installed</h3>
          {installed.length === 0 && (
            <p className="dim">
              Nothing installed through the store yet; modules listed in this deployment's
              configuration ride their config path.
            </p>
          )}
          <ul className="moduleList">
            {installed.map((module) => (
              <li key={module.name}>
                <div>
                  <strong>{module.name}</strong>{' '}
                  <span className="dim">
                    {module.version} · {ENTRY_LABELS[module.entry] ?? module.entry} · key{' '}
                    {module.fingerprint.slice(0, 8)}
                  </span>
                </div>
                <button
                  type="button"
                  disabled={busy === module.name}
                  onClick={() => onUninstall(module.name)}
                >
                  Uninstall
                </button>
              </li>
            ))}
          </ul>
        </div>
        <div className="card">
          <h3>Registry</h3>
          {registry.length === 0 && (
            <p className="dim">
              No registry configured (Modules:Registry names its address), or it carries nothing.
            </p>
          )}
          <ul className="moduleList">
            {upgradable.map((entry) => (
              <li key={entry.name}>
                <div>
                  <strong>{entry.name}</strong>{' '}
                  <span className="dim">
                    {entry.latest ?? ''} · {ENTRY_LABELS[entry.entry] ?? entry.entry}
                  </span>
                  {entry.description && <div className="dim">{entry.description}</div>}
                </div>
                <button
                  type="button"
                  disabled={busy === entry.name}
                  onClick={() => onInstall(entry.name)}
                >
                  Install
                </button>
              </li>
            ))}
            {registry
              .filter((entry) => installedNames.has(entry.name))
              .map((entry) => (
                <li key={entry.name} className="dim">
                  <div>
                    <strong>{entry.name}</strong> — installed
                    {entry.latest ? ` (registry carries ${entry.latest})` : ''}
                  </div>
                </li>
              ))}
          </ul>
        </div>
      </div>
    </section>
  )
}
