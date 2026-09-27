/** @type {import('tailwindcss').Config} */
// Colours come from CSS variables (src/index.css) so the high-contrast mode can swap them.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ground: v("ground"),
        panel: v("panel"),
        sunken: v("sunken"),
        line: v("line"),
        "line-strong": v("line-strong"),
        ink: v("ink"),
        "ink-2": v("ink-2"),
        "ink-3": v("ink-3"),
        chrome: v("chrome"),
        "chrome-2": v("chrome-2"),
        "chrome-ink": v("chrome-ink"),
        "chrome-muted": v("chrome-muted"),
        signal: v("signal"),
        "signal-soft": v("signal-soft"),
        sev: {
          critical: v("sev-critical"), high: v("sev-high"), medium: v("sev-medium"), low: v("sev-low"),
          info: v("sev-info"),
        },
        ok: v("ok"),
        warn: v("warn"),
        ml: v("ml"),
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', '"Segoe UI"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "Consolas", "monospace"],
      },
      fontSize: {
        // 1.2 modular scale anchored at 14px body
        xs: ["0.75rem", "1.1rem"],
        sm: ["0.8125rem", "1.25rem"],
        base: ["0.875rem", "1.4rem"],
        lg: ["1.05rem", "1.5rem"],
        xl: ["1.26rem", "1.6rem"],
        "2xl": ["1.512rem", "1.8rem"],
        "3xl": ["2.1rem", "2.3rem"],
      },
      borderRadius: { DEFAULT: "4px", sm: "2px" },
    },
  },
  plugins: [],
}
