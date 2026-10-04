import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../ui',        // 产物进 ui/（pkapp.toml [dist].dir，applocal 静态分支直接服务）
    emptyOutDir: true,
  },
  server: {
    // 前端独立调试（npm run dev）时转发到 pkapp dev 服务（默认 8765）
    proxy: {
      '/api': 'http://127.0.0.1:8765',
      '/login': 'http://127.0.0.1:8765',
      '/logout': 'http://127.0.0.1:8765',
      '/auth': 'http://127.0.0.1:8765',
      '/healthz': 'http://127.0.0.1:8765',
    },
  },
})
