import React, { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { X, Camera, Loader2 } from 'lucide-react';

/**
 * In-app QR scanner. Opens the rear camera, decodes QR frames with jsQR (pure JS,
 * works on iOS Safari and Android alike — no BarcodeDetector dependency), and
 * calls onResult with the decoded string the first time a code is found. The
 * caller is responsible for parsing that string (e.g. pulling an invite code out
 * of a URL). The camera stream is always stopped on unmount.
 */
export default function QrScanner({ onResult, onClose }: { onResult: (text: string) => void; onClose: () => void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [status, setStatus] = useState<'starting' | 'scanning' | 'error'>('starting');
  const [error, setError] = useState<string>('');
  // Latest callbacks via ref so the camera effect runs exactly once.
  const cbRef = useRef({ onResult, onClose });
  cbRef.current = { onResult, onClose };

  useEffect(() => {
    let cancelled = false;
    let raf = 0;
    let stream: MediaStream | null = null;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true }) as CanvasRenderingContext2D | null;

    const stop = () => { cancelled = true; if (raf) cancelAnimationFrame(raf); if (stream) stream.getTracks().forEach(t => t.stop()); };

    (async () => {
      if (!navigator.mediaDevices?.getUserMedia) { setStatus('error'); setError('This browser can’t access the camera. Enter the code by hand instead.'); return; }
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
        if (cancelled) { stream.getTracks().forEach(t => t.stop()); return; }
        const v = videoRef.current;
        if (!v) return;
        v.srcObject = stream;
        v.setAttribute('playsinline', 'true'); // iOS: stay inline, don't go fullscreen
        v.muted = true;
        await v.play();
        setStatus('scanning');
        const tick = () => {
          if (cancelled) return;
          if (v.readyState === v.HAVE_ENOUGH_DATA && ctx && v.videoWidth) {
            canvas.width = v.videoWidth; canvas.height = v.videoHeight;
            ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
            try {
              const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
              const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
              if (code && code.data) { stop(); cbRef.current.onResult(code.data); return; }
            } catch { /* frame not ready / cross-origin — keep scanning */ }
          }
          raf = requestAnimationFrame(tick);
        };
        raf = requestAnimationFrame(tick);
      } catch (e: any) {
        setStatus('error');
        setError(
          e?.name === 'NotAllowedError' ? 'Camera permission was denied. Allow camera access, or enter the code by hand.'
            : e?.name === 'NotFoundError' ? 'No camera was found on this device.'
              : 'Could not start the camera. Enter the code by hand instead.'
        );
      }
    })();

    return stop;
  }, []);

  return (
    <div className="fixed inset-0 z-[120] bg-black/90 backdrop-blur-sm flex flex-col items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Scan invite QR code">
      <button
        type="button"
        onClick={() => cbRef.current.onClose()}
        aria-label="Close scanner"
        className="absolute top-4 right-4 w-10 h-10 rounded-full bg-white/10 text-white flex items-center justify-center hover:bg-white/20 active:scale-95 transition-all"
      >
        <X className="w-5 h-5" />
      </button>

      <div className="w-full max-w-xs">
        <div className="flex items-center gap-2 justify-center mb-4 text-emerald-400">
          <Camera className="w-5 h-5" />
          <span className="text-sm font-black uppercase tracking-widest">Scan invite QR</span>
        </div>

        <div className="relative aspect-square w-full rounded-3xl overflow-hidden border border-white/10 bg-black">
          <video ref={videoRef} className="absolute inset-0 w-full h-full object-cover" playsInline muted />
          {/* framing reticle */}
          {status === 'scanning' && (
            <div className="absolute inset-0 pointer-events-none">
              <div className="absolute inset-8 rounded-2xl border-2 border-emerald-400/70 shadow-[0_0_0_9999px_rgba(0,0,0,0.35)]" />
            </div>
          )}
          {status === 'starting' && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-zinc-400">
              <Loader2 className="w-6 h-6 animate-spin" />
              <span className="text-xs">Starting camera…</span>
            </div>
          )}
          {status === 'error' && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-center px-6">
              <Camera className="w-7 h-7 text-zinc-600" />
              <span className="text-xs text-zinc-400 leading-relaxed">{error}</span>
            </div>
          )}
        </div>

        <p className="text-[11px] text-zinc-500 text-center mt-4 leading-relaxed">
          {status === 'error'
            ? 'You can close this and type the invite code instead.'
            : 'Point the camera at the network’s invite QR code.'}
        </p>
        <button
          type="button"
          onClick={() => cbRef.current.onClose()}
          className="mt-4 w-full py-2.5 rounded-xl bg-white/5 text-zinc-300 text-[11px] font-black uppercase tracking-widest hover:bg-white/10 active:scale-95 transition-all"
        >
          {status === 'error' ? 'Enter code manually' : 'Cancel'}
        </button>
      </div>
    </div>
  );
}
