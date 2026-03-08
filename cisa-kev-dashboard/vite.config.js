import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/KEV-Analysis/',  // ← MUST match your GitHub repo name
})
