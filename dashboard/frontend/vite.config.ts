import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const localApi = { "/api": "http://127.0.0.1:8090" };

export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: localApi,
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
    proxy: localApi,
  },
});
