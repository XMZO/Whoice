export function getServerAPIBase() {
  return process.env.WHOICE_WEB_API_BASE || process.env.NEXT_PUBLIC_WHOICE_API_BASE || "http://localhost:8080";
}

