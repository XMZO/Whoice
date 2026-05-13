const STATIC_CACHE = "whoice-static-v3";
const OLD_CACHES = ["whoice-shell-v1", "whoice-static-v2"];
const STATIC_ASSETS = ["/", "/docs", "/status", "/manifest.webmanifest", "/icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(STATIC_CACHE).then((cache) => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => OLD_CACHES.includes(name) || (name.startsWith("whoice-") && name !== STATIC_CACHE))
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/lookup") || url.pathname.startsWith("/api/og")) return;
  if (!STATIC_ASSETS.includes(url.pathname)) return;
  event.respondWith(
    caches.match(request).then((cached) => cached || fetch(request))
  );
});
