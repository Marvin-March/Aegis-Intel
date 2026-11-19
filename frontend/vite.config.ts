import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    // vendor 拆分：框架与图标独立 chunk，利于缓存与首屏并行
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-icons': ['lucide-react'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      // api.py（127.0.0.1:8000）四端点；形态 B 开发联调用
      '/ask': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/search': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/related': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
