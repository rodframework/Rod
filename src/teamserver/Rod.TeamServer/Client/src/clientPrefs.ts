import { useEffect, useState } from 'react'

// Browser-local console preferences: presentation state the UI owns alone.
// Nothing here reaches the server -- a browser that never opens Settings
// keeps the defaults, and two browsers on the same operator account can
// disagree. The knobs: how often presence-style surfaces re-read while
// their tab is visible (build progress keeps its own faster cadence on
// purpose -- it is task progress, not presence), and the table density
// every listing inherits.

const POLL_INTERVAL_KEY = 'rod.poll-interval-seconds'
const EVENT = 'rod-prefs-changed'

export const DEFAULT_POLL_INTERVAL_SECONDS = 5
const MIN_POLL_INTERVAL_SECONDS = 2
const MAX_POLL_INTERVAL_SECONDS = 60

function clamp(seconds: number): number {
  return Math.min(MAX_POLL_INTERVAL_SECONDS, Math.max(MIN_POLL_INTERVAL_SECONDS, seconds))
}

export function readPollIntervalSeconds(): number {
  const raw = window.localStorage.getItem(POLL_INTERVAL_KEY)
  if (raw === null) return DEFAULT_POLL_INTERVAL_SECONDS
  const parsed = Number(raw)
  if (!Number.isFinite(parsed)) return DEFAULT_POLL_INTERVAL_SECONDS
  return clamp(parsed)
}

// Returns the clamped value that was actually stored, so the caller can
// echo back what took effect.
export function writePollIntervalSeconds(seconds: number): number {
  const clamped = clamp(seconds)
  window.localStorage.setItem(POLL_INTERVAL_KEY, String(clamped))
  // The same window-event pattern the roster and unauthorized notices use:
  // every mounted poller hears it and re-arms its timer on the spot.
  window.dispatchEvent(new Event(EVENT))
  return clamped
}

// The cadence every presence-style poll reads, live: a save in Settings
// re-arms running timers without a reload.
export function usePollIntervalMs(): number {
  const [seconds, setSeconds] = useState(readPollIntervalSeconds)
  useEffect(() => {
    const onChange = () => setSeconds(readPollIntervalSeconds())
    window.addEventListener(EVENT, onChange)
    return () => window.removeEventListener(EVENT, onChange)
  }, [])
  return seconds * 1000
}

// The table density (ADR-013): comfortable is the reading default,
// compact is the scanning posture -- one toggle, browser-local, applied
// by the shell as a data attribute every table inherits. No server
// round-trip: two browsers on the same operator account can disagree.

const DENSITY_KEY = 'rod.table-density'

export type TableDensity = 'comfortable' | 'compact'

export function readTableDensity(): TableDensity {
  return window.localStorage.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable'
}

export function writeTableDensity(density: TableDensity): void {
  window.localStorage.setItem(DENSITY_KEY, density)
  window.dispatchEvent(new Event(EVENT))
}

export function useTableDensity(): [TableDensity, (density: TableDensity) => void] {
  const [density, setDensity] = useState(readTableDensity)
  useEffect(() => {
    const onChange = () => setDensity(readTableDensity())
    window.addEventListener(EVENT, onChange)
    return () => window.removeEventListener(EVENT, onChange)
  }, [])
  return [density, writeTableDensity]
}
