// Whoice no longer uses a service worker. Earlier versions cached "/", "/docs"
// and "/status" cache-first, so browsers kept showing the pre-redesign pages.
// This replacement (a changed file, so browsers install it on their next
// visit) deletes those caches, unregisters itself and reloads open tabs; it
// never intercepts requests.
self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(names.filter((name) => name.startsWith("whoice-")).map((name) => caches.delete(name)));
      await self.registration.unregister();
      const windows = await self.clients.matchAll({ type: "window" });
      await Promise.all(windows.map((client) => client.navigate(client.url).catch(() => undefined)));
    })(),
  );
});
