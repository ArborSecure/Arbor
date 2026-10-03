import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// NOTE: the old config injected process.env.API_KEY into the client bundle, which
// shipped a secret to every browser (finding H1). That define block is removed.
// All secret-bearing work (AI summaries) now runs server-side.
export default defineConfig(() => {
  return {
    plugins: [react()],
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      rollupOptions: {
        output: {
          // Split heavy, rarely-changing vendor code into its own long-lived chunks.
          // They fetch in parallel with the app chunk on a cold load and, crucially,
          // stay cached across app updates (only the small app chunk re-downloads /
          // re-parses when we ship a change) — a big win for warm PWA reopens.
          manualChunks: {
            'vendor-signal': ['@privacyresearch/libsignal-protocol-typescript'],
            'vendor-react': ['react', 'react-dom'],
            'vendor-ui': ['lucide-react', 'qrcode'],
          },
        },
      },
    },
    server: {
      host: true,
      proxy: {
        '/api': 'http://localhost:3000'
      }
    }
  };
});
