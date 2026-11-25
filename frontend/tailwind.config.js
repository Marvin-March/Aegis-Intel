/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          'Inter',
          'Noto Sans SC',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'PingFang SC',
          'Hiragino Sans GB',
          'Microsoft YaHei',
          'sans-serif',
        ],
        mono: [
          'JetBrains Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace',
        ],
      },
      colors: {
        // Aegis Intel — Obsidian Precision Theme (Linear / Vercel / Raycast inspired)
        soc: {
          bg: 'var(--bg-canvas)',
          sidebar: 'var(--bg-sidebar)',
          panel: 'var(--bg-surface)',
          elevated: 'var(--bg-elevated)',
          hover: 'var(--bg-hover)',
          border: 'var(--border-subtle)',
          'border-default': 'var(--border-default)',
          'border-strong': 'var(--border-strong)',
          primary: 'var(--accent-primary)',
          'primary-hover': 'var(--accent-primary-hover)',
          indigo: 'var(--accent-secondary)',
          success: 'var(--status-success)',
          warning: 'var(--status-warning)',
          danger: 'var(--status-danger)',
          info: 'var(--status-info)',
          text: {
            primary: 'var(--text-primary)',
            secondary: 'var(--text-secondary)',
            muted: 'var(--text-muted)',
          },
        },
        sev: {
          critical: '#f43f5e',
          high: '#fb923c',
          medium: '#facc15',
          low: '#38bdf8',
        },
        domain: {
          cve: '#f43f5e',
          article: '#38bdf8',
          paper: '#a78bfa',
          daily: '#34d399',
        },
      },
      boxShadow: {
        'panel-sm': 'inset 0 1px 0 0 rgba(255, 255, 255, 0.05), 0 1px 3px rgba(0, 0, 0, 0.4)',
        'panel-md': 'inset 0 1px 0 0 rgba(255, 255, 255, 0.07), 0 12px 32px -12px rgba(0, 0, 0, 0.7)',
        'focus-cyan': '0 0 0 1px rgba(56, 189, 248, 0.45), 0 0 0 4px rgba(56, 189, 248, 0.12)',
      },
    },
  },
  plugins: [],
};
