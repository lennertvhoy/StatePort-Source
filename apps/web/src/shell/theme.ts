/**
 * Theme resolution (consumed by ThemeEngine and its tests). Lives outside the
 * component module so fast-refresh boundaries stay component-only.
 */

/** Resolve the effective theme attribute. */
export function resolveTheme(input: {
  theme: 'system' | 'light' | 'dark' | 'high_contrast'
  highContrast: boolean
  prefersDark: boolean
}): 'light' | 'dark' | 'hc-light' | 'hc-dark' {
  const baseDark =
    input.theme === 'dark' ||
    (input.theme === 'system' && input.prefersDark) ||
    (input.theme === 'high_contrast' && input.prefersDark)
  const hc = input.highContrast || input.theme === 'high_contrast'
  return hc ? (baseDark ? 'hc-dark' : 'hc-light') : baseDark ? 'dark' : 'light'
}
