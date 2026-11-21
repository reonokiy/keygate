import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  base: './',
  plugins: [tailwindcss(), svelte({ configFile: false })],
  build: {
    cssCodeSplit: false,
    modulePreload: false,
    rolldownOptions: {
      output: {
        codeSplitting: false,
        entryFileNames: 'app.js',
        assetFileNames: '[name][extname]',
      },
    },
  },
});
