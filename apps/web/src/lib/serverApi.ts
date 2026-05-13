export function getServerAPIBase() {
  return process.env.WHOICE_WEB_API_BASE || process.env.NEXT_PUBLIC_WHOICE_API_BASE || (process.env.NODE_ENV === "production" ? "http://lookup-api:8080" : "http://localhost:8080");
}
