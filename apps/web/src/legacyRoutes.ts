/**
 * Legacy hash normalization (binding doc §10 — preserve/redirect current
 * route forms). Applied once in `main.tsx` before the router renders.
 *
 *   #home                       → #/applications
 *   #instances                  → #/applications
 *   #instance/<id>              → #/app/<id>
 *   #conversation/<id>          → #/app/<id>/conversation
 *   #advanced/<id>              → #/app/<id>/settings
 *   #workbench/<id>             → #/app/<id>/workbench
 *   #advanced                   → #/settings
 *   #app/<id>[/*]               → #/app/<id>[/*]
 *
 * Already-normal hashes (`#/…`), unknown hashes, and the empty hash pass
 * through unchanged so the router's own NotFound handling stays in charge.
 */

/** Legacy bare routes → their normalized targets. */
const LEGACY_BARE_ROUTES: Readonly<Record<string, string>> = {
  home: '/applications',
  instances: '/applications',
  catalog: '/catalog',
  approvals: '/approvals',
  settings: '/settings',
  advanced: '/settings',
  platform: '/applications',
}

/**
 * Legacy application-scoped route prefixes → current application subpaths.
 * These are exact single-identity aliases: accepting arbitrary trailing
 * segments would invent routes that were never part of the compatibility
 * contract.
 */
const LEGACY_INSTANCE_ROUTES: Readonly<Record<string, string>> = {
  instance: '',
  conversation: '/conversation',
  advanced: '/settings',
  workbench: '/workbench',
}

export function normalizeLegacyHash(hash: string): string {
  if (!hash || hash === '#' || hash.startsWith('#/')) return hash

  // Strip the leading '#'; keep any query string attached to the hash.
  const body = hash.slice(1)
  const queryIndex = body.indexOf('?')
  const path = queryIndex === -1 ? body : body.slice(0, queryIndex)
  const query = queryIndex === -1 ? '' : body.slice(queryIndex)
  if (!path) return hash

  // #app/<id>[/*] — insert the missing slash, preserve subpaths + query.
  if (path === 'app' || path.startsWith('app/')) {
    return `#/${path}${query}`
  }

  const separator = path.indexOf('/')
  if (separator !== -1) {
    const prefix = path.slice(0, separator)
    const instanceId = path.slice(separator + 1)
    const destination = LEGACY_INSTANCE_ROUTES[prefix]
    if (destination !== undefined && instanceId && !instanceId.includes('/')) {
      return `#/app/${instanceId}${destination}${query}`
    }
  }

  const target = LEGACY_BARE_ROUTES[path]
  if (target) return `#${target}${query}`

  return hash
}
