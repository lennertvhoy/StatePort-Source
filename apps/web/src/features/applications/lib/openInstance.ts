/**
 * Open an application workspace in a new browser window (hash-routed).
 * Shared by the instance context menu and the overview header; lives outside
 * component modules so fast-refresh boundaries stay component-only.
 */
export function openInstanceInNewWindow(instanceId: string): void {
  const base = window.location.href.split('#')[0]
  window.open(`${base}#/app/${instanceId}`, '_blank', 'noopener')
}
