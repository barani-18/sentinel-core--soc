import path from "path";
import { fileURLToPath } from "url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  plugins: [
    react({
      // This is the CRITICAL fix for "React is not defined"
      jsxRuntime: 'automatic',
    }), 
    tailwindcss()
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },s
});
import { defineConfig } from 'vite'

export default defineConfig({
  // If your site is at the root of the domain, base should be '/'
  base: '/', 
  build: {
    outDir: 'dist',
  },
})
