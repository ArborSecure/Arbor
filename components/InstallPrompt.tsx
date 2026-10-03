import React, { useEffect, useState } from 'react';
import { X, Share, Plus, Smartphone } from 'lucide-react';

// Is the app already running as an installed PWA (Home Screen / standalone
// window) rather than inside a browser tab? Covers Android/desktop (display-mode)
// and iOS Safari (navigator.standalone).
export const isStandalone = (): boolean => {
  try {
    return !!(
      window.matchMedia?.('(display-mode: standalone)').matches ||
      window.matchMedia?.('(display-mode: window-controls-overlay)').matches ||
      window.matchMedia?.('(display-mode: fullscreen)').matches ||
      (navigator as any).standalone === true
    );
  } catch { return false; }
};

const isIOS = (): boolean => {
  try {
    const ua = navigator.userAgent || '';
    // iPadOS 13+ reports as "MacIntel" with a touch screen, so detect that too.
    return /iphone|ipad|ipod/i.test(ua) ||
      (navigator.platform === 'MacIntel' && (navigator as any).maxTouchPoints > 1);
  } catch { return false; }
};

const DISMISS_KEY = 'arbor_install_dismissed_at';
const NAG_AFTER_MS = 1000 * 60 * 60 * 24 * 3; // re-offer three days after a dismissal

// A dismissible banner that invites the user to install Arbor to their Home
// Screen. Hidden entirely when already installed. On Android/desktop it uses the
// captured beforeinstallprompt for a one-tap install; on iOS (which has no such
// event) it shows the manual Share -> Add to Home Screen steps.
const InstallPrompt: React.FC = () => {
  const [show, setShow] = useState(false);
  const [hasNative, setHasNative] = useState(false);
  const [iosHelp, setIosHelp] = useState(false);

  useEffect(() => {
    if (isStandalone()) return; // already installed — nothing to prompt
    const dismissedAt = Number(localStorage.getItem(DISMISS_KEY) || 0);
    if (dismissedAt && Date.now() - dismissedAt < NAG_AFTER_MS) return;

    const evaluate = () => {
      if ((window as any).__deferredInstall) { setHasNative(true); setShow(true); }
    };
    evaluate(); // the event may already be stashed from load
    const onReady = () => evaluate();
    window.addEventListener('arbor:installready', onReady);
    // iOS never fires beforeinstallprompt — offer manual instructions instead.
    if (isIOS()) setShow(true);
    const onInstalled = () => { setShow(false); localStorage.setItem(DISMISS_KEY, String(Date.now())); };
    window.addEventListener('appinstalled', onInstalled);
    return () => {
      window.removeEventListener('arbor:installready', onReady);
      window.removeEventListener('appinstalled', onInstalled);
    };
  }, []);

  if (!show) return null;

  const dismiss = () => { setShow(false); localStorage.setItem(DISMISS_KEY, String(Date.now())); };

  const install = async () => {
    const dp = (window as any).__deferredInstall;
    if (dp) {
      try { dp.prompt(); await dp.userChoice; } catch {}
      (window as any).__deferredInstall = null;
      dismiss();
    } else {
      setIosHelp(v => !v); // no native prompt (iOS) — reveal the manual steps
    }
  };

  return (
    <div className="fixed inset-x-0 bottom-0 z-[130] px-3 pb-[calc(env(safe-area-inset-bottom,0px)+10px)] animate-in slide-in-from-bottom-4 duration-300 pointer-events-none">
      <div className="mx-auto max-w-xs bg-[#111]/95 backdrop-blur border border-emerald-500/20 rounded-xl shadow-xl p-2 pl-3 pointer-events-auto">
        <div className="flex items-center gap-2">
          <Smartphone className="w-4 h-4 text-emerald-500 shrink-0" />
          <div className="flex-1 min-w-0 text-[11px] font-semibold text-zinc-200 leading-tight">Add to Home Screen</div>
          <button onClick={install}
            className="shrink-0 text-[10px] font-black uppercase tracking-wider px-2.5 py-1.5 rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all">
            {hasNative ? 'Install' : 'Add'}
          </button>
          <button onClick={dismiss} aria-label="Dismiss" className="shrink-0 p-1 text-zinc-600 hover:text-white transition-colors"><X className="w-3.5 h-3.5" /></button>
        </div>
        {iosHelp && !hasNative && (
          <div className="mt-2 text-[10px] text-zinc-400 leading-relaxed bg-black/40 border border-white/10 rounded-lg p-2 space-y-1">
            <div className="flex items-center gap-1.5"><span className="text-emerald-400 font-black shrink-0">1.</span> Tap <Share className="w-3 h-3 inline text-emerald-400 shrink-0" /> Share in the toolbar.</div>
            <div className="flex items-center gap-1.5"><span className="text-emerald-400 font-black shrink-0">2.</span> Choose <Plus className="w-3 h-3 inline text-emerald-400 shrink-0" /> &ldquo;Add to Home Screen&rdquo;.</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default InstallPrompt;
