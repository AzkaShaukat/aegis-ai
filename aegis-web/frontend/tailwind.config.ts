import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Aegis brand palette — dark cyber theme
        aegis: {
          bg:        '#0d1117',   // main background
          surface:   '#161b22',   // cards, sidebar
          border:    '#21262d',   // borders
          muted:     '#8b949e',   // secondary text
          accent:    '#58a6ff',   // primary blue (links, focus)
          'accent-hover': '#79c0ff',
          success:   '#3fb950',
          warning:   '#d29922',
          danger:    '#f85149',
          critical:  '#ff6e6e',
        },
        risk: {
          safe:     '#3fb950',
          low:      '#d29922',
          medium:   '#e3b341',
          high:     '#f85149',
          critical: '#ff0000',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['SFMono-Regular', 'Consolas', 'Liberation Mono', 'Menlo', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in':    'fadeIn 0.2s ease-in',
        'slide-up':   'slideUp 0.3s ease-out',
        'blink':      'blink 1s step-end infinite',
      },
      keyframes: {
        fadeIn:  { from: { opacity: '0' }, to: { opacity: '1' } },
        slideUp: { from: { opacity: '0', transform: 'translateY(8px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        blink:   { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0' } },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
} satisfies Config
