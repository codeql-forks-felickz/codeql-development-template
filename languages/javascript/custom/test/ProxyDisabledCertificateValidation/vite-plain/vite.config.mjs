export default {
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:7095',
        secure: false // $ Alert
      },
      '/safe': {
        target: 'https://localhost:7096',
        secure: true
      }
    }
  }
};
