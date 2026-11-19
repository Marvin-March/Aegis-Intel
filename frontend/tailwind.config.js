/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // 荧光科技风：深空底 + 电光青主色 + 霓虹语义色
        soc: {
          bg: '#05070e',
          panel: '#0a1020',
          hover: '#101a30',
          border: '#17233d',
          primary: '#22d3ee',
          success: '#34d399',
          warning: '#fbbf24',
          danger: '#f87171',
          text: {
            primary: '#e8f1fb',
            secondary: '#9fb2c8',
            muted: '#5d7089',
          },
        },
      },
    },
  },
  plugins: [],
};
