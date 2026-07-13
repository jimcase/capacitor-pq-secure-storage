import { defineConfig } from 'vite';

// base './' so the built assets load from the Capacitor webview (file:// on device)
export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
