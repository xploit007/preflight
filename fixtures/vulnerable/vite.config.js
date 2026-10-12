import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    plugins: [react()],
    build: { sourcemap: true },
    // Make process.env work in the browser the same way it does on the server.
    define: { 'process.env': env },
  };
});
