const statusEl = document.querySelector("#updateStatus");
const retryButton = document.querySelector("#retryButton");

function setStatus(message) {
  statusEl.textContent = message;
}

function appTargetUrl() {
  const params = new URLSearchParams(window.location.search);
  const requested = params.get("to");
  const target = requested ? new URL(requested, window.location.href) : new URL("./", window.location.href);
  if (target.origin !== window.location.origin) {
    throw new Error("update target must stay on this origin");
  }
  target.searchParams.set("force_update", Date.now().toString(36));
  return target;
}

async function unregisterServiceWorkers() {
  if (!("serviceWorker" in navigator)) {
    return 0;
  }
  const registrations = await navigator.serviceWorker.getRegistrations();
  await Promise.all(registrations.map((registration) => registration.unregister()));
  return registrations.length;
}

async function clearAppCaches() {
  if (!("caches" in window)) {
    return 0;
  }
  const names = await caches.keys();
  const appCaches = names.filter((name) => name.startsWith("approval-approve-"));
  await Promise.all(appCaches.map((name) => caches.delete(name)));
  return appCaches.length;
}

async function forceUpdate() {
  retryButton.hidden = true;
  setStatus("Removing service workers...");
  const serviceWorkerCount = await unregisterServiceWorkers();
  setStatus("Clearing cached app files...");
  const cacheCount = await clearAppCaches();
  setStatus(`Cleared ${serviceWorkerCount} service workers and ${cacheCount} caches. Reloading...`);
  window.location.replace(appTargetUrl());
}

retryButton.addEventListener("click", () => {
  forceUpdate().catch((error) => {
    setStatus(`Update failed: ${error.message}`);
    retryButton.hidden = false;
  });
});

forceUpdate().catch((error) => {
  setStatus(`Update failed: ${error.message}`);
  retryButton.hidden = false;
});
