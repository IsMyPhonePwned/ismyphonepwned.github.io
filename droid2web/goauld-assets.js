/**
 * Bundled arm_goauld android-arm64 binaries (fetched once, cached).
 */

const BASE = new URL('./goauld-bin/android-arm64/', import.meta.url);

let injectorPromise = null;
let agentPromise = null;
let metaPromise = null;

async function fetchBytes(name) {
  const url = new URL(name, BASE).href;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load ${name}: HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

export function goauldBinBaseUrl() {
  return BASE.href;
}

export async function getBundledInjector() {
  if (!injectorPromise) {
    injectorPromise = fetchBytes('goauld-injector').catch((e) => {
      injectorPromise = null;
      throw e;
    });
  }
  return injectorPromise;
}

export async function getBundledAgent() {
  if (!agentPromise) {
    agentPromise = fetchBytes('libgoauld_agent.so').catch((e) => {
      agentPromise = null;
      throw e;
    });
  }
  return agentPromise;
}

export async function getBundledGoauldMeta() {
  if (!metaPromise) {
    metaPromise = (async () => {
      try {
        const res = await fetch(new URL('VERSION.txt', BASE).href);
        if (!res.ok) return { version: 'bundled' };
        return { version: (await res.text()).trim() || 'bundled' };
      } catch {
        return { version: 'bundled' };
      }
    })();
  }
  return metaPromise;
}

/**
 * Prefer a user-picked file; otherwise use the bundled binary.
 * @param {HTMLInputElement|null} inputEl
 * @param {'injector'|'agent'} kind
 */
export async function resolveGoauldBinary(inputEl, kind) {
  const f = inputEl?.files?.[0];
  if (f) return new Uint8Array(await f.arrayBuffer());
  if (kind === 'injector') return getBundledInjector();
  if (kind === 'agent') return getBundledAgent();
  throw new Error(`unknown goauld binary kind: ${kind}`);
}
