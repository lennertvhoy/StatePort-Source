/**
 * Tailwind wired to the StatePort token CSS (src/styles/tokens.css).
 *
 * Semantic utilities only — every color/spacing/type utility resolves to a
 * design token. The shadcn `src/components/ui/*` aliases (--background,
 * --primary, …) are preserved but point at the same tokens.
 *
 * Alpha modifiers (e.g. `bg-primary/10`) work via CSS relative color syntax.
 */

/** Wrap a token var so Tailwind can apply /<alpha> modifiers. */
const v = (name) => `rgb(from var(${name}) r g b / <alpha-value>)`

const status = (name) => ({
  DEFAULT: v(`--status-${name}-text`),
  bg: v(`--status-${name}-bg`),
  border: v(`--status-${name}-border`),
})

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ['class', '[data-theme="dark"]'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    // Design breakpoints (design.md §9.8) — aligned to the validation viewports.
    screens: {
      sm: '480px',
      md: '768px',
      lg: '1024px',
      xl: '1200px',
      '2xl': '1440px',
    },
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      black: '#000000',
      white: '#ffffff',

      // ── Semantic surface tokens ──────────────────────────────────────────
      app: v('--bg-app'),
      surface: {
        DEFAULT: v('--bg-surface'),
        2: v('--bg-surface-2'),
      },
      sunken: v('--bg-sunken'),
      hover: v('--bg-hover'),
      active: v('--bg-active'),
      scrim: 'var(--scrim)',

      // ── Semantic text tokens ─────────────────────────────────────────────
      foreground: {
        DEFAULT: v('--text-primary'),
        secondary: v('--text-secondary'),
        tertiary: v('--text-tertiary'),
        disabled: v('--text-disabled'),
        inverse: v('--text-inverse'),
      },

      // ── Accent ───────────────────────────────────────────────────────────
      accent: {
        DEFAULT: v('--accent'),
        hover: v('--accent-hover'),
        soft: {
          DEFAULT: v('--accent-soft-bg'),
          text: v('--accent-soft-text'),
        },
      },
      focus: v('--focus-ring'),

      // ── Semantic status layer (§3.3): text-status-*, bg-status-*-bg, border-status-*-border
      status: {
        success: status('success'),
        neutral: status('neutral'),
        attention: status('attention'),
        waiting: status('waiting'),
        blocked: status('blocked'),
        danger: status('danger'),
        informational: status('informational'),
      },

      // ── shadcn aliases (kept working; all resolve to tokens) ─────────────
      background: v('--bg-surface'),
      border: v('--border-default'),
      input: v('--border-strong'),
      ring: v('--focus-ring'),
      primary: {
        DEFAULT: v('--accent'),
        foreground: v('--text-inverse'),
      },
      secondary: {
        DEFAULT: v('--bg-active'),
        foreground: v('--text-primary'),
      },
      destructive: {
        DEFAULT: v('--status-danger-text'),
        foreground: v('--text-inverse'),
      },
      muted: {
        DEFAULT: v('--bg-surface-2'),
        foreground: v('--text-secondary'),
      },
      popover: {
        DEFAULT: v('--bg-surface'),
        foreground: v('--text-primary'),
      },
      card: {
        DEFAULT: v('--bg-surface'),
        foreground: v('--text-primary'),
      },
      sidebar: {
        DEFAULT: v('--bg-sidebar'),
        foreground: v('--text-primary'),
        primary: v('--accent'),
        'primary-foreground': v('--text-inverse'),
        accent: v('--bg-hover'),
        'accent-foreground': v('--text-primary'),
        border: v('--border-default'),
        ring: v('--focus-ring'),
      },
    },
    extend: {
      fontFamily: {
        sans: ['var(--font-ui)'],
        mono: ['var(--font-mono)'],
      },
      fontSize: {
        '2xl': ['var(--text-2xl)', { lineHeight: 'var(--text-2xl-lh)', fontWeight: '600', letterSpacing: '-0.01em' }],
        xl: ['var(--text-xl)', { lineHeight: 'var(--text-xl-lh)', fontWeight: '600', letterSpacing: '-0.01em' }],
        lg: ['var(--text-lg)', { lineHeight: 'var(--text-lg-lh)', fontWeight: '600' }],
        md: ['var(--text-md)', 'var(--text-md-lh)'],
        base: ['var(--text-md)', 'var(--text-md-lh)'],
        sm: ['var(--text-sm)', 'var(--text-sm-lh)'],
        xs: ['var(--text-xs)', 'var(--text-xs-lh)'],
        code: ['var(--text-code)', 'var(--text-code-lh)'],
      },
      spacing: {
        topbar: 'var(--topbar-h)',
        statusbar: 'var(--statusbar-h)',
        row: 'var(--row-h)',
        'row-dense': 'var(--row-dense-h)',
        control: 'var(--control-h)',
        'control-sm': 'var(--control-sm-h)',
        'nav-row': 'var(--nav-row-h)',
      },
      borderRadius: {
        xl: 'calc(var(--radius) + 4px)',
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
        xs: 'var(--radius-xs)',
        round: 'var(--radius-round)',
      },
      boxShadow: {
        1: 'var(--shadow-1)',
        2: 'var(--shadow-2)',
        sm: 'var(--shadow-1)',
        DEFAULT: 'var(--shadow-1)',
        md: 'var(--shadow-2)',
        lg: 'var(--shadow-2)',
        xl: 'var(--shadow-2)',
        '2xl': 'var(--shadow-2)',
      },
      transitionDuration: {
        instant: 'var(--dur-instant)',
        fast: 'var(--dur-fast)',
        med: 'var(--dur-med)',
        layout: 'var(--dur-layout)',
      },
      transitionTimingFunction: {
        standard: 'var(--ease-standard)',
        enter: 'var(--ease-enter)',
        exit: 'var(--ease-exit)',
      },
      zIndex: {
        ribbon: '30',
        overlay: '50',
        drawer: '60',
        palette: '70',
        toast: '80',
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
        'caret-blink': {
          '0%,70%,100%': { opacity: '1' },
          '20%,50%': { opacity: '0' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down var(--dur-med) var(--ease-standard)',
        'accordion-up': 'accordion-up var(--dur-med) var(--ease-standard)',
        'caret-blink': 'caret-blink 1.25s ease-out infinite',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
