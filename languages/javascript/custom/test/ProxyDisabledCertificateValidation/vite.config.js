import { defineConfig } from 'vite';

const target = 'https://localhost:7095';

export default defineConfig({
  server: {
    proxy: {
      '^/weatherforecast': {
        target,
        secure: false // $ Alert
      },
      '/api': {
        target,
        secure: true
      },
      '/default': {
        target
      },
      '/short': 'http://localhost:8080'
    }
  },
  preview: {
    proxy: {
      '/preview': {
        target,
        secure: false // $ Alert
      }
    }
  }
});
