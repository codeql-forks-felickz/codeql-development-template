import { defineConfig } from 'vite';

const insecureProxy = {
  target: 'https://localhost:7095',
  secure: false // $ Alert
};

export default defineConfig(({ mode }) => ({
  server: {
    proxy: {
      '/api': insecureProxy,
      '/other': {
        target: 'https://localhost:7096',
        secure: mode !== 'development'
      }
    }
  }
}));
