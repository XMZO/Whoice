import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [, , command = "dev", ...args] = process.argv;
const scriptDir = dirname(fileURLToPath(import.meta.url));
const nextBin = join(scriptDir, "..", "node_modules", "next", "dist", "bin", "next");

const hasPortArg = args.some((arg, index) => {
  return arg === "-p" || arg === "--port" || arg.startsWith("--port=") || args[index - 1] === "-p" || args[index - 1] === "--port";
});

const port = process.env.WHOICE_WEB_PORT || process.env.PORT || "18081";
const finalArgs = [nextBin, command, ...args];
if ((command === "dev" || command === "start") && !hasPortArg) {
  finalArgs.push("-p", port);
}

const child = spawn(process.execPath, finalArgs, {
  cwd: join(scriptDir, ".."),
  env: process.env,
  stdio: "inherit",
});

// Forward stop signals: as PID 1 in the container this wrapper would
// otherwise ignore SIGTERM and Docker waits 10s before killing it.
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
