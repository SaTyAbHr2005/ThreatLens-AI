import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  // The landing bundles ../backend/catalog/eval_results.json, so its numbers show before the API wakes up.
  server: { port: 5173, fs: { allow: ['..'] } },
  build: {
    rollupOptions: {
      output: {
        manualChunks: (id) =>
          id.includes('node_modules/three') ? 'three' : /node_modules\/(gsap|@gsap|lenis)/.test(id) ? 'motion' : undefined,
      },
    },
  },
});
