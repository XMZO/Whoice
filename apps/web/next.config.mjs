import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  // next dev would otherwise write AGENTS.md / CLAUDE.md into the app when it
  // detects an AI coding agent.
  agentRules: false,
  reactStrictMode: true,
  // The Docker image ships only the files the server traces as needed
  // (.next/standalone) instead of the whole node_modules tree.
  output: "standalone",
  // Trace from the monorepo root so pnpm's workspace node_modules resolve.
  outputFileTracingRoot: join(appDir, "..", ".."),
};

export default nextConfig;
