import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// CTIOPS_API_PORT / CTIOPS_WEB_PORT let several dev servers run side by side.
const apiPort = process.env.CTIOPS_API_PORT ?? '8000'
const webPort = Number(process.env.CTIOPS_WEB_PORT ?? 5173)

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: webPort,
    strictPort: true,
    proxy: { '/api': `http://127.0.0.1:${apiPort}` },
  },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 1200 },
})
