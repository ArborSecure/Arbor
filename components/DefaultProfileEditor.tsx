import React, { useEffect, useRef, useState } from 'react';
import { api } from '../services/api';
import { prepareAvatar } from '../services/mediaService';
import { Image as ImageIcon, Trash2, Shield, Loader2, Check } from 'lucide-react';

/**
 * Account-level DEFAULT profile editor (display name, photo, bio). Whatever is set
 * here pre-fills new networks: the NAME always, the photo + bio only when the person
 * ticks "Use my default photo & bio" for that network (V8 M-8). Each network can
 * still be tailored afterward. Used on the Identity Hub ("Default profile") and
 * as the optional step right after signup. Talks to /api/account/profile.
 *
 * The photo is scrubbed on-device (canvas re-encode) before it ever leaves — the
 * original file's EXIF/GPS/device metadata is never uploaded.
 */
const DefaultProfileEditor: React.FC<{
  onDone?: () => void;          // primary CTA (Save & continue / Done)
  onSkip?: () => void;          // optional "do this later"
  ctaLabel?: string;
  compact?: boolean;
}> = ({ onDone, onSkip, ctaLabel = 'Done', compact = false }) => {
  const [loaded, setLoaded] = useState(false);
  const [name, setName] = useState('');
  const [bio, setBio] = useState('');
  const [avatar, setAvatar] = useState('');       // data URL or ''
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const fileRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    let alive = true;
    api.getAccountProfile()
      .then(p => { if (alive) { setName(p.name || ''); setBio(p.bio || ''); setAvatar(p.avatar || ''); setLoaded(true); } })
      .catch(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  }, []);

  const pickPhoto = async (file?: File | null) => {
    if (!file || busy) return;
    setBusy(true);
    try {
      const scrubbed = await prepareAvatar(file);   // EXIF stripped on-device
      await api.setAccountProfile({ avatar: scrubbed });
      setAvatar(scrubbed);
    } catch (e: any) { alert(e?.message || 'Could not process image.'); }
    finally { setBusy(false); if (fileRef.current) fileRef.current.value = ''; }
  };
  const removePhoto = async () => {
    if (busy) return;
    setBusy(true);
    try { await api.setAccountProfile({ removeAvatar: true }); setAvatar(''); }
    catch (e: any) { alert(e?.message || 'Could not remove photo.'); }
    finally { setBusy(false); }
  };
  const persist = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.setAccountProfile({ name: name.trim() || null, bio: bio.trim() || null });
      setSaved(true);
      onDone?.();
    } catch (e: any) { alert(e?.message || 'Could not save.'); }
    finally { setBusy(false); }
  };

  const initial = (name.trim()[0] || '?').toUpperCase();

  return (
    <div className="space-y-4">
      {!compact && (
        <div className="text-center">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-emerald-500 mb-1">Default profile</div>
          <p className="text-[11px] text-zinc-500 leading-relaxed">
            Set up a <span className="text-emerald-400 font-bold">default profile</span> — you can choose to use it whenever you create or join a network. Totally optional, and you can change it anytime.
          </p>
        </div>
      )}

      <div className="flex items-start gap-4">
        <div className="flex flex-col items-center gap-2 shrink-0">
          {avatar
            ? <img src={avatar} alt="" className="w-16 h-16 rounded-2xl object-cover shrink-0 ring-1 ring-white/10" />
            : <div className="w-16 h-16 rounded-2xl flex items-center justify-center text-white font-black text-xl shrink-0 bg-zinc-700 ring-1 ring-white/10">{initial}</div>}
          <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={e => pickPhoto(e.target.files?.[0])} />
          <div className="flex items-center gap-1.5">
            <button type="button" onClick={() => fileRef.current?.click()} disabled={busy}
              className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/5 text-zinc-200 text-[11px] font-bold hover:bg-white/10 transition-colors disabled:opacity-40">
              <ImageIcon className="w-4 h-4" /> {avatar ? 'Replace' : 'Add photo'}
            </button>
            {avatar && (
              <button type="button" onClick={removePhoto} disabled={busy}
                className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/5 text-red-300 text-[11px] font-bold hover:bg-red-500/15 transition-colors disabled:opacity-40">
                <Trash2 className="w-4 h-4" />
              </button>
            )}
            {busy && <Loader2 className="w-4 h-4 animate-spin text-zinc-500" />}
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start gap-1.5 text-[9px] text-emerald-400/80 mt-1 leading-relaxed">
            <Shield className="w-3 h-3 shrink-0 mt-px" />
            <span>Photo metadata &amp; EXIF (location, device, timestamps) is stripped on your device. Your default profile is encrypted with your password-derived key — only you can read it.</span>
          </div>
        </div>
      </div>

      <div>
        <div className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 px-1">Display name</div>
        <input value={name} maxLength={64} onChange={e => setName(e.target.value)} placeholder="How you'll appear by default"
          className="w-full bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors" />
      </div>

      <div>
        <div className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-1.5 px-1">Bio <span className="text-zinc-700 normal-case">(optional)</span></div>
        <textarea value={bio} maxLength={500} rows={2} onChange={e => setBio(e.target.value)} placeholder="A short line about you (optional)."
          className="w-full bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors resize-none" />
      </div>

      <div className="flex items-center gap-2 pt-1">
        <button type="button" onClick={persist} disabled={busy || !loaded}
          className="flex-1 flex items-center justify-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-black font-black text-[12px] uppercase tracking-widest py-3 rounded-xl transition-colors disabled:opacity-40">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : saved ? <Check className="w-4 h-4" /> : null} {ctaLabel}
        </button>
        {onSkip && (
          <button type="button" onClick={onSkip} disabled={busy}
            className="px-4 py-3 rounded-xl bg-white/5 text-zinc-400 text-[11px] font-bold hover:bg-white/10 transition-colors">
            Do this later
          </button>
        )}
      </div>
    </div>
  );
};

export default DefaultProfileEditor;
