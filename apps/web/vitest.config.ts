import { availableParallelism } from 'node:os'
import path from 'path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const maxWorkers = Math.max(1, Math.min(2, availableParallelism()))

// Unit/integration tests for the client boundary, stores, and (later) components.
// jsdom environment + a shared setup file; globals stay off — tests import from
// 'vitest' explicitly so strict tsconfig `types` does not need widening.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    pool: 'forks',
    isolate: true,
    maxWorkers,
    maxConcurrency: 2,
    bail: 1,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    css: false,
    restoreMocks: true,
    unstubEnvs: true,
  },
})
