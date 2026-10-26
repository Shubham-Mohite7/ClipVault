const CACHE_NAME = "clipvault-shell-v31";
const VAULT_CACHE_NAME = "clipvault-vault-data-v1";
const MAX_OFFLINE_VAULT_RESPONSES = 24;
const SHELL_URLS = [
  "/",
  "/privacy.html",
  "/terms.html",
  "/favicon.svg",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/apple-touch-icon.png",
  "/chat-crypto.js",
  "/chat.js",
  "/vendor/jsQR.js",
  "/snippets-animation.svg",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_URLS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names
        .filter((name) => name.startsWith("clipvault-shell-") && name !== CACHE_NAME)
        .map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

async function cacheSuccessfulResponse(cache, request, response) {
  if (!response.ok || response.type === "opaque") return;
  try {
    if (cache.name === VAULT_CACHE_NAME) await cache.delete(request);
    await cache.put(request, response.clone());
    if (cache.name === VAULT_CACHE_NAME) {
      const requests = await cache.keys();
      for (const oldRequest of requests.slice(0, Math.max(0, requests.length - MAX_OFFLINE_VAULT_RESPONSES))) {
        await cache.delete(oldRequest);
      }
    }
  } catch {
    // Storage pressure must not prevent an online response from reaching the app.
  }
}

async function offlineVaultResponse(request) {
  const cache = await caches.open(VAULT_CACHE_NAME);
  const cached = await cache.match(request);
  if (cached) {
    const headers = new Headers(cached.headers);
    headers.set("X-ClipVault-Offline", "true");
    return new Response(cached.body, {
      status: cached.status,
      statusText: cached.statusText,
      headers,
    });
  }
  return new Response(JSON.stringify({
    error: "This vault has no saved offline copy on this device. Connect to the internet and open it once first.",
  }), {
    status: 503,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "X-ClipVault-Offline": "true",
    },
  });
}

async function networkFirstVaultData(request) {
  const cache = await caches.open(VAULT_CACHE_NAME);
  try {
    const response = await fetch(request);
    await cacheSuccessfulResponse(cache, request, response);
    return response;
  } catch {
    return offlineVaultResponse(request);
  }
}

function staleWhileRevalidate(event, request) {
  const cachePromise = caches.open(CACHE_NAME);
  const refreshPromise = fetch(request).then(async (response) => {
    const cache = await cachePromise;
    await cacheSuccessfulResponse(cache, request, response);
    return response;
  }).catch(() => null);
  event.waitUntil(refreshPromise.then(() => undefined));

  return cachePromise.then(async (cache) => {
    const cached = await cache.match(request);
    if (cached) return cached;
    return (await refreshPromise) || Response.error();
  });
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) {
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    const offlineVaultPath = /^\/api\/vaults\/(?:[a-z]{3}-\d{3}|\d{5})\/(?:check|snippets)$/i;
    if (offlineVaultPath.test(url.pathname)) {
      event.respondWith(networkFirstVaultData(request));
    }
    return;
  }

  if (url.pathname.startsWith("/_vercel/")) return;

  if (request.mode === "navigate") {
    if (url.search) return;
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(async () => (await caches.match(request)) || caches.match("/")),
    );
    return;
  }

  event.respondWith(staleWhileRevalidate(event, request));
});
