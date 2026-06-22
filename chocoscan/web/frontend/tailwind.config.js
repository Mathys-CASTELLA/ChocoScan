/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        choco: {
          bg:           "#09090b",   // zinc-950
          surface:      "#18181b",   // zinc-900
          surface2:     "#27272a",   // zinc-800
          border:       "#3f3f46",   // zinc-700
          accent:       "#6366f1",   // indigo-500 — sobre et lisible
          "accent-dim": "#4f46e5",   // indigo-600
          muted:        "#71717a",   // zinc-500
          text:         "#f4f4f5",   // zinc-100
          "text-dim":   "#a1a1aa",   // zinc-400
        },
        severity: {
          critical: "#f87171",   // red-400 — moins agressif que 500
          high:     "#fb923c",   // orange-400
          medium:   "#facc15",   // yellow-400
          low:      "#60a5fa",   // blue-400
          unknown:  "#71717a",   // zinc-500
        }
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      animation: {
        "fade-in":  "fadeIn 0.2s ease-out",
        "slide-up": "slideUp 0.2s ease-out",
      },
      keyframes: {
        fadeIn:  { "0%": { opacity: "0" },                              "100%": { opacity: "1" } },
        slideUp: { "0%": { opacity: "0", transform: "translateY(6px)" }, "100%": { opacity: "1", transform: "translateY(0)" } },
      },
    },
  },
  plugins: [],
}
