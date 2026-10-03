
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { LocaleProvider } from './services/LocaleContext';
import './index.css';

/**
 * Error boundary: a render crash used to unmount the whole tree — a black
 * screen with zero information. Now it shows the actual error + stack (so it
 * can be screenshotted/reported) and offers reload / cache-reset.
 */
class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null; info: string }> {
  state = { error: null as Error | null, info: '' };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: React.ErrorInfo) { this.setState({ info: info.componentStack || '' }); }
  render() {
    if (!this.state.error) return this.props.children;
    const detail = `${this.state.error.message}\n${this.state.error.stack || ''}\n${this.state.info}`;
    return (
      <div style={{ minHeight: '100dvh', background: '#0a0a0a', color: '#e4e4e7', padding: '2rem 1.5rem', fontFamily: 'monospace', paddingTop: 'calc(env(safe-area-inset-top, 0px) + 2rem)' }}>
        <div style={{ color: '#f87171', fontWeight: 900, textTransform: 'uppercase', letterSpacing: '0.2em', fontSize: 11, marginBottom: 12 }}>Arbor hit an error</div>
        <div style={{ fontSize: 12, color: '#a1a1aa', marginBottom: 16 }}>Your data is safe — this is a display crash. Screenshot this box and report it.</div>
        <pre style={{ whiteSpace: 'pre-wrap', fontSize: 10, background: '#18181b', border: '1px solid #27272a', borderRadius: 12, padding: 12, maxHeight: '50dvh', overflow: 'auto' }}>{detail}</pre>
        <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
          <button onClick={() => window.location.reload()} style={{ background: '#10b981', color: '#000', fontWeight: 900, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.15em', padding: '10px 16px', borderRadius: 10, border: 0 }}>Reload</button>
          <button onClick={async () => { try { const ks = await caches.keys(); await Promise.all(ks.map(k => caches.delete(k))); const rs = await navigator.serviceWorker?.getRegistrations?.(); await Promise.all((rs || []).map(r => r.unregister())); } catch {} window.location.reload(); }}
            style={{ background: '#27272a', color: '#e4e4e7', fontWeight: 900, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.15em', padding: '10px 16px', borderRadius: 10, border: 0 }}>Reset cache & reload</button>
        </div>
      </div>
    );
  }
}

// Capture the PWA install event as early as possible. `beforeinstallprompt`
// fires once, at load — usually before the user reaches the Identity Hub where
// we surface the "Add to Home Screen" prompt — so we stash the event on window
// and let the InstallPrompt component trigger installation on demand. (CSP
// blocks inline scripts, so this lives here in the module rather than index.html.)
(window as any).__deferredInstall = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  (window as any).__deferredInstall = e;
  window.dispatchEvent(new Event('arbor:installready'));
});
window.addEventListener('appinstalled', () => { (window as any).__deferredInstall = null; });

// Register Service Worker for PWA support. Long-lived mobile PWAs can otherwise
// sit on a stale cached bundle for a very long time (a rarely-closed home-screen
// tab), which showed up as "groups don't exist on mobile" — an old bundle whose
// refresh logic dropped group data. So: force an update check on load and each
// time the app regains focus, and when a NEW service worker takes control,
// reload ONCE to run the fresh code (but never on the very first install).
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    const hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.register('/sw.js').then(reg => {
      try { reg.update(); } catch {}
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') { try { reg.update(); } catch {} }
      });
    }).catch(err => {
      console.log('ServiceWorker registration failed: ', err);
    });
    let reloaded = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (reloaded || !hadController) return; // skip the initial-install claim
      reloaded = true;
      window.location.reload();
    });
  });
}

// One-time "re-add to home screen" notice. The marketing page (/) forwards
// installed-PWA (standalone) launches to /launch?migrated=1 after the app moved
// off '/'. Show a dismissible banner explaining how to re-add so the icon points
// straight at /launch. The old icon keeps working via the redirect, so this is
// best-effort cleanup, not a requirement. Self-contained DOM (not a React node) so
// it's independent of the app's render tree; CSP-safe because it's module code.
(function relaunchNotice() {
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.get('migrated') !== '1') return;
    // strip the flag so a manual refresh doesn't re-trigger
    try {
      params.delete('migrated');
      const qs = params.toString();
      window.history.replaceState({}, '', window.location.pathname + (qs ? '?' + qs : '') + (window.location.hash || ''));
    } catch {}
    if (localStorage.getItem('arbor-relaunch-dismissed') === '1') return;
    const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
    const steps = isIOS
      ? 'open arborsecure.app in Safari, tap the Share icon, then “Add to Home Screen”.'
      : 'open arborsecure.app in your browser, open the menu (⋮), then “Install app” / “Add to Home Screen”.';
    const show = () => {
      if (document.getElementById('arbor-relaunch-notice')) return;
      const wrap = document.createElement('div');
      wrap.id = 'arbor-relaunch-notice';
      wrap.setAttribute('role', 'dialog');
      wrap.style.cssText = 'position:fixed;left:12px;right:12px;bottom:calc(env(safe-area-inset-bottom,0px) + 12px);z-index:2147483647;background:#101010;border:1px solid #262626;border-radius:16px;padding:16px 16px 14px;box-shadow:0 20px 60px -10px rgba(0,0,0,.7);font-family:system-ui,-apple-system,\'Segoe UI\',Roboto,sans-serif;color:#e4e4e7;max-width:520px;margin:0 auto';
      wrap.innerHTML =
        '<div style="font-weight:800;font-size:14px;color:#fff;margin-bottom:6px">Arbor moved to a new home-screen address</div>' +
        '<div style="font-size:13px;line-height:1.6;color:#a1a1aa;margin-bottom:12px">Your current icon still works. To keep it working long-term, re-add Arbor: ' + steps + '</div>' +
        '<div style="display:flex;justify-content:flex-end"><button id="arbor-relaunch-ok" style="background:#10b981;color:#04120c;border:none;border-radius:10px;padding:9px 16px;font-size:12px;font-weight:800;cursor:pointer">Got it</button></div>';
      document.body.appendChild(wrap);
      const ok = document.getElementById('arbor-relaunch-ok');
      if (ok) ok.addEventListener('click', () => { try { localStorage.setItem('arbor-relaunch-dismissed', '1'); } catch {} wrap.remove(); });
    };
    if (document.body) show(); else window.addEventListener('DOMContentLoaded', show);
  } catch {}
})();

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

// iOS Safari will pan the whole document when a touch-drag starts on a
// non-scrollable element (e.g. the tab headers), even with body overflow:hidden.
// Allow the gesture only when it originates inside something actually
// scrollable; otherwise prevent it so the app never "comes down" as a unit.
document.addEventListener('touchmove', (e) => {
  if (e.touches && e.touches.length > 1) return; // pinch/zoom gestures pass through
  let el = e.target as HTMLElement | null;
  while (el && el !== document.body) {
    const style = getComputedStyle(el);
    if (style.touchAction === 'none') return; // interactive canvas (tree pan/zoom)
    const oy = style.overflowY;
    if ((oy === 'auto' || oy === 'scroll') && el.scrollHeight > el.clientHeight) return; // inside a real scroller
    el = el.parentElement;
  }
  if (e.cancelable) e.preventDefault();
}, { passive: false });

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <ErrorBoundary><LocaleProvider><App /></LocaleProvider></ErrorBoundary>
  </React.StrictMode>
);
