import { describe, expect, it } from 'vitest'
import { coversRequirement, loadableModules } from './capabilities'
import type { CapabilityDescriptor } from './api'

// ADR-017's runtime half, mirrored client-side: the session's handshake
// advertisement decides the loadable plugin set. The coverage rule mirrors
// the server's WireCapabilities (each tier's task-path verb); the server's
// issuance gate stays the authority.

describe('coversRequirement', () => {
  it('maps each tier to its task-path verb', () => {
    expect(coversRequirement(['module.load', 'shell.exec'], 'plugin-loader')).toBe(true)
    expect(coversRequirement(['shell.exec'], 'plugin-loader')).toBe(false)
    expect(coversRequirement(['file.pull'], 'exfil-chunks')).toBe(true)
    expect(coversRequirement(['file.pull'], 'staged-uploads')).toBe(false)
    expect(coversRequirement(['file.push'], 'staged-uploads')).toBe(true)
  })

  it('is case-insensitive on the held verbs', () => {
    expect(coversRequirement(['Module.Load'], 'plugin-loader')).toBe(true)
  })

  it('never covers an unknown name', () => {
    expect(coversRequirement(['shell.exec'], 'cha-cha-20')).toBe(false)
  })
})

function descriptor(verb: string, module: string | null, requires: string[] | null): CapabilityDescriptor {
  return { verb, category: 'Collect', version: '1.0', attributes: {}, parameters: null, output: null, techniques: [], module, requires }
}

describe('loadableModules', () => {
  it('lists named modules with their coverage, placeholders never', () => {
    const catalog = [
      descriptor('collect.hives', 'hives', ['plugin-loader']),
      descriptor('collect.browser', 'browser', ['plugin-loader', 'exfil-chunks']),
      descriptor('shell.exec', null, null),
    ]

    const modules = loadableModules(catalog, ['shell.exec', 'module.load'])

    expect(modules.map((m) => m.module)).toEqual(['browser', 'hives'])
    expect(modules.find((m) => m.module === 'hives')!.covered).toBe(true)
    expect(modules.find((m) => m.module === 'browser')!.missing).toEqual(['exfil-chunks'])
  })

  it('marks everything uncovered when the loader is absent', () => {
    const modules = loadableModules(
      [descriptor('collect.hives', 'hives', ['plugin-loader'])],
      ['shell.exec'],
    )

    expect(modules).toHaveLength(1)
    expect(modules[0].covered).toBe(false)
    expect(modules[0].missing).toEqual(['plugin-loader'])
  })

  it('loads a module that declares nothing anywhere', () => {
    const modules = loadableModules([descriptor('custom.thing', 'custom', [])], [])

    expect(modules).toHaveLength(1)
    expect(modules[0].covered).toBe(true)
  })
})
