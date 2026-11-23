// Tells the server when the app crashes on this device, so an admin can find out without being told.
import { session } from './api.js';

const sent = new Set();

function report(error, fallback) {
  const message = String(error?.message || fallback || error || '').slice(0, 500);
  // One report per distinct problem per visit, and nothing while signed out or offline.
  if (!message || sent.has(message) || sent.size >= 10 || !session.token || !navigator.onLine) return;
  sent.add(message);
  fetch('/api/errors', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.token}` },
    body: JSON.stringify({ message, stack: String(error?.stack || '').slice(0, 4000), version: __APP_VERSION__, page: location.hash.slice(1).split('?')[0] || 'log' }),
  }).catch(() => {});
}

export function startErrorReports() {
  window.addEventListener('error', (e) => report(e.error, e.message));
  window.addEventListener('unhandledrejection', (e) => report(e.reason));
}
