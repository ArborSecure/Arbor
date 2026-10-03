
import React, { useState, useMemo, useRef, useEffect, useLayoutEffect, memo, useCallback } from 'react';
import { AppState, Message, User, Invite } from '../types';
import { isSafeMediaHeader } from '../services/cryptoService';
import { blobToCleanDataUrl, scrubImage, scrubVideo, reencodeAudioDeep, dataUrlToBlobUrl, prepareImageForSend, prepareAvatar } from '../services/mediaService';
import * as appLock from '../services/appLock';
import { CallUIState } from '../services/callService';
import QRCode from 'qrcode';
import { api } from '../services/api';
import LanguagePicker from './LanguagePicker';
import { ICON_COLORS } from './AuthScreen';
import { useT, useLocale } from '../services/LocaleContext';
import * as scheduledStore from '../services/scheduledStore';
import * as sealedLocal from '../services/sealedLocal';
import { 
  Send,
  UserPlus,
  Plus,
  FolderPlus,
  QrCode,
  LogOut,
  Menu as MenuIcon,
  GitBranch,
  Scissors,
  Eye,
  EyeOff,
  Radio,
  Globe,
  AtSign,
  Link2,
  X,
  ArrowUpLeft,
  ArrowDownRight,
  Image as ImageIcon,
  Mic,
  Square,
  Play,
  Pause,
  Loader2,
  ShieldCheck, ShieldAlert,
  Activity,
  Zap,
  ChevronRight,
  ChevronDown,
  ChevronsUpDown,
  ChevronsDownUp,
  Layers,
  Network,
  Users,
  Hash,
  Search,
  Monitor,
  MessageSquare,
  FileLock,
  Flame,
  Clock,
  Bell,
  BookOpen,
  Smartphone,
  Shield,
  Info,
  Pin,
  Copy,
  Check,
  Volume2,
  Video,
  SwitchCamera,
  Reply,
  Smile,
  Pencil,
  Link as LinkIcon,
  Settings,
  Film,
  Trash2,
  Timer,
  AlertTriangle,
  Target,
  Signal,
  Wifi,
  Filter,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Waypoints,
  HelpCircle,
  Eraser,
  Fingerprint,
  Phone,
  PhoneOff,
  PhoneIncoming,
  PhoneOutgoing,
  MicOff,
  CheckCheck,
  CheckSquare, Megaphone, ChevronLeft, MessageCircle, KeyRound
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Account deletion (security review V8 M-7). The privacy policy promised it and
// no path existed. Inline form (never window.prompt — that would show the
// password in the clear): re-enter the password; if the account owns networks
// other people are in, the server lists them and the person must explicitly
// tick "also delete those networks" before it will proceed.
// ---------------------------------------------------------------------------
// Group / link ids: CSPRNG, base-36 (V8 INFO — replaces Math.random ids).
const randToken = (len: number): string => Array.from(crypto.getRandomValues(new Uint8Array(len)), b => (b % 36).toString(36)).join('');

const DeleteAccountPanel: React.FC<{ username: string }> = ({ username }) => {
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [owned, setOwned] = useState<{ id?: string; name?: string; members: number }[] | null>(null);
  const [alsoNetworks, setAlsoNetworks] = useState(false);
  const run = async () => {
    if (!pw || busy) return;
    if (!confirm('Permanently delete your Arbor account? This cannot be undone.')) return;
    setBusy(true); setErr(null);
    try {
      await api.deleteAccount(username, pw, alsoNetworks);
      alert('Your account has been deleted.');
      window.location.reload();
    } catch (e: any) {
      if (e?.body?.code === 'owns-networks') setOwned(e.body.networks || []);
      setErr(e?.status === 403 ? 'That password is not correct.' : (e?.message || 'Could not delete the account.'));
    } finally { setBusy(false); setPw(''); }
  };
  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-red-500/10 text-red-300 text-[10px] font-black uppercase tracking-widest hover:bg-red-500/20 transition-colors">
        <Trash2 className="w-4 h-4" /> Delete my account
      </button>
    );
  }
  return (
    <div className="rounded-xl border border-red-500/30 bg-black/40 p-3 space-y-2.5">
      <div className="text-[11px] font-bold text-red-300">Delete account “{username}”</div>
      <div className="text-[10px] text-zinc-400 leading-relaxed">Removes your account, every identity it holds, your messages on the server, backups, recovery phrase and profile photos. People you invited stay in their networks.</div>
      {owned && owned.length > 0 && (
        <div className="text-[10px] text-amber-300 leading-relaxed">
          You own networks other people are in: {owned.map(n => `${n.name || (n.id && api.trust.selfLabelOf(n.id)?.t) || 'a network'} (${n.members})`).join(', ')}.
          <label className="flex items-center gap-2 mt-1.5 text-red-300 font-bold cursor-pointer">
            <input type="checkbox" checked={alsoNetworks} onChange={e => setAlsoNetworks(e.target.checked)} className="accent-red-500" />
            Also delete these networks for everyone
          </label>
        </div>
      )}
      <input type="password" autoComplete="current-password" placeholder="Your password" value={pw}
        onChange={e => setPw(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') run(); }}
        className="w-full bg-black border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-red-500/50 outline-none" />
      {err && <div className="text-[10px] text-red-400">{err}</div>}
      <div className="flex gap-2">
        <button onClick={() => { setOpen(false); setErr(null); setPw(''); setOwned(null); setAlsoNetworks(false); }}
          className="flex-1 py-2 rounded-lg bg-white/5 text-zinc-300 text-[10px] font-black uppercase tracking-widest">Cancel</button>
        <button onClick={run} disabled={!pw || busy || (!!owned && owned.length > 0 && !alsoNetworks)}
          className="flex-1 py-2 rounded-lg bg-red-600 text-white text-[10px] font-black uppercase tracking-widest disabled:opacity-40">
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : 'Delete forever'}
        </button>
      </div>
    </div>
  );
};

// v72 M4: the password prompt the server asks for before a destructive action
// (deleting a network, pruning a member). One confirmation covers this session for
// 10 minutes on the server.
const ReauthDialog: React.FC<{ username: string | null }> = ({ username }) => {
  const [req, setReq] = useState<{ reason: string; resolve: (ok: boolean) => void } | null>(null);
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!username) return;
    api.onReauthNeeded = (reason) => new Promise<boolean>(resolve => { setPw(''); setErr(null); setReq({ reason, resolve }); });
    return () => { api.onReauthNeeded = null; };
  }, [username]);
  if (!req || !username) return null;
  const close = (ok: boolean) => { req.resolve(ok); setReq(null); setPw(''); setErr(null); };
  const submit = async () => {
    if (!pw || busy) return;
    setBusy(true); setErr(null);
    try { await api.confirmPassword(username, pw); close(true); }
    catch (e: any) { setErr(e?.message || 'Password check failed.'); }
    finally { setBusy(false); }
  };
  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={() => { if (!busy) close(false); }}>
      <div className="w-full max-w-sm bg-[#141414] border border-white/10 rounded-2xl p-5 shadow-2xl space-y-3" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-black uppercase tracking-widest text-white">Confirm with your password</h3>
        <p className="text-xs text-zinc-400 leading-relaxed">{req.reason} Enter your password to continue — you won’t be asked again for the next 10 minutes.</p>
        <input type="password" autoFocus autoComplete="current-password" placeholder="Your password" value={pw}
          onChange={e => setPw(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') submit(); }}
          className="w-full bg-black border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-red-500/50 outline-none" />
        {err && <div className="text-[10px] text-red-400">{err}</div>}
        <div className="flex gap-2">
          <button onClick={() => close(false)} disabled={busy}
            className="flex-1 py-2 rounded-lg bg-white/5 text-zinc-300 text-[10px] font-black uppercase tracking-widest">Cancel</button>
          <button onClick={submit} disabled={!pw || busy}
            className="flex-1 py-2 rounded-lg bg-red-600 text-white text-[10px] font-black uppercase tracking-widest disabled:opacity-40">
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// v71 M6: change password + log out other devices. Inline forms (never
// window.prompt). A password change re-encrypts every key the server holds for
// this account and commits them together with the new password in one step; other
// devices are signed out and re-seal their local data at their next sign-in.
// ---------------------------------------------------------------------------
const ChangePasswordPanel: React.FC<{ username: string }> = ({ username }) => {
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState('');
  const [nw, setNw] = useState('');
  const [nw2, setNw2] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const reset = () => { setCur(''); setNw(''); setNw2(''); };
  const run = async () => {
    if (busy || !cur || !nw) return;
    if (nw !== nw2) { setErr('The new passwords don’t match.'); return; }
    setBusy(true); setErr(null);
    try {
      const r = await api.changePassword(username, cur, nw);
      setDone('Password changed.' + (r.sessionsEnded ? ` ${r.sessionsEnded} other session(s) were signed out.` : '') +
        (r.recoveryCleared ? ' Your recovery phrase held the old password and was removed — set up a new one below.' : '') +
        ' If you use biometric unlock, turn it on again.');
      reset();
    } catch (e: any) {
      setErr(e?.status === 403 ? 'Your current password is incorrect.' : (e?.message || 'Could not change the password.'));
    } finally { setBusy(false); }
  };
  if (!open) {
    return (
      <button onClick={() => { setOpen(true); setDone(null); }}
        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-white/5 text-zinc-200 text-[10px] font-black uppercase tracking-widest hover:bg-white/10 transition-colors">
        <KeyRound className="w-4 h-4" /> Change password
      </button>
    );
  }
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 p-3 space-y-2.5">
      <div className="text-[11px] font-bold text-zinc-200">Change password</div>
      <div className="text-[10px] text-zinc-400 leading-relaxed">Your keys and encrypted backups are re-encrypted under the new password on this device, then saved in one step. Other devices are signed out and pick up the change at their next sign-in. Keep this app open until it finishes.</div>
      {done ? <div className="text-[10px] text-emerald-300 leading-relaxed">{done}</div> : (<>
        <input type="password" autoComplete="current-password" placeholder="Current password" value={cur} onChange={e => setCur(e.target.value)}
          className="w-full bg-black border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500/50 outline-none" />
        <input type="password" autoComplete="new-password" placeholder="New password (several random words)" value={nw} onChange={e => setNw(e.target.value)}
          className="w-full bg-black border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500/50 outline-none" />
        <input type="password" autoComplete="new-password" placeholder="New password again" value={nw2} onChange={e => setNw2(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') run(); }}
          className="w-full bg-black border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500/50 outline-none" />
      </>)}
      {err && <div className="text-[10px] text-red-400">{err}</div>}
      <div className="flex gap-2">
        <button onClick={() => { setOpen(false); setErr(null); reset(); }}
          className="flex-1 py-2 rounded-lg bg-white/5 text-zinc-300 text-[10px] font-black uppercase tracking-widest">{done ? 'Close' : 'Cancel'}</button>
        {!done && (
          <button onClick={run} disabled={!cur || !nw || !nw2 || busy}
            className="flex-1 py-2 rounded-lg bg-emerald-600 text-white text-[10px] font-black uppercase tracking-widest disabled:opacity-40">
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : 'Change password'}
          </button>
        )}
      </div>
    </div>
  );
};

const OtherSessionsPanel: React.FC<{ username: string }> = ({ username }) => {
  const [count, setCount] = useState<number | null>(null);
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => { api.getSettings().then(s => setCount(typeof (s as any).otherSessions === 'number' ? (s as any).otherSessions : null)).catch(() => {}); }, []);
  const run = async () => {
    if (!pw || busy) return;
    setBusy(true); setMsg(null);
    try {
      const n = await api.revokeOtherSessions(username, pw);
      setMsg(n ? `Signed out ${n} other session(s).` : 'There were no other sessions.');
      setCount(0); setOpen(false);
    } catch (e: any) {
      setMsg(e?.status === 403 ? 'That password is not correct.' : (e?.message || 'Could not sign out other sessions.'));
    } finally { setBusy(false); setPw(''); }
  };
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 p-3 space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[11px] font-bold text-zinc-200">Other signed-in sessions</div>
        <div className="text-[11px] font-black text-zinc-400 tabular-nums">{count === null ? '…' : count}</div>
      </div>
      {open ? (<>
        <input type="password" autoComplete="current-password" placeholder="Your password" value={pw}
          onChange={e => setPw(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') run(); }}
          className="w-full bg-black border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-emerald-500/50 outline-none" />
        <div className="flex gap-2">
          <button onClick={() => { setOpen(false); setPw(''); }} className="flex-1 py-2 rounded-lg bg-white/5 text-zinc-300 text-[10px] font-black uppercase tracking-widest">Cancel</button>
          <button onClick={run} disabled={!pw || busy} className="flex-1 py-2 rounded-lg bg-emerald-600 text-white text-[10px] font-black uppercase tracking-widest disabled:opacity-40">
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : 'Sign them out'}
          </button>
        </div>
      </>) : (
        <button onClick={() => { setOpen(true); setMsg(null); }} disabled={count === 0}
          className="w-full py-2 rounded-lg bg-white/5 text-zinc-200 text-[10px] font-black uppercase tracking-widest hover:bg-white/10 disabled:opacity-40">
          Log out other devices
        </button>
      )}
      {msg && <div className="text-[10px] text-zinc-400">{msg}</div>}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Network Profile — avatars.
// Avatars load lazily, keyed by the node's server-stamped avatarAt version, so a
// big tree's photos never bloat the context payload or slow startup. Two cache
// tiers: an in-memory Map for the session, and IndexedDB so a photo shown once is
// INSTANT on the next cold start (no re-fetch). The colored initial shows only
// until the (usually cached) image resolves. Keyed by `${pid}:${avatarAt}`, so a
// changed photo is a brand-new key and stale versions are simply never read.
// ---------------------------------------------------------------------------
const avatarMem = new Map<string, string>();               // `${publicId}:${avatarAt}` -> data URL
const avatarInflight = new Map<string, Promise<string | null>>();

const AV_DB = 'arbor-avatars', AV_STORE = 'av';
let _avDb: Promise<IDBDatabase | null> | null = null;
function avDb(): Promise<IDBDatabase | null> {
  if (_avDb) return _avDb;
  _avDb = new Promise((resolve) => {
    try {
      const req = indexedDB.open(AV_DB, 1);
      req.onupgradeneeded = () => { try { if (!req.result.objectStoreNames.contains(AV_STORE)) req.result.createObjectStore(AV_STORE); } catch {} };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch { resolve(null); }
  });
  return _avDb;
}
function avGet(key: string): Promise<string | null> {
  return avDb().then(db => db ? new Promise<string | null>((resolve) => {
    try { const r = db.transaction(AV_STORE, 'readonly').objectStore(AV_STORE).get(key);
      r.onsuccess = () => resolve(typeof r.result === 'string' ? r.result : null);
      r.onerror = () => resolve(null);
    } catch { resolve(null); }
  }) : null);
}
function avPut(key: string, val: string): void {
  avDb().then(db => { if (!db) return; try { db.transaction(AV_STORE, 'readwrite').objectStore(AV_STORE).put(val, key); } catch {} });
}
/** Store an avatar we already hold locally (e.g. right after uploading it) so the
 *  preview is instant and it survives reloads without a round trip. */
function seedAvatar(pid: string, at: number | undefined, dataUrl: string): void {
  if (!at) return;
  const key = `${pid}:${at}`;
  avatarMem.set(key, dataUrl);
  avPut(key, dataUrl);
}
function loadAvatar(viewerNodeId: string, pid: string, at?: number): Promise<string | null> {
  if (!at) return Promise.resolve(null);
  const key = `${pid}:${at}`;
  const hit = avatarMem.get(key);
  if (hit) return Promise.resolve(hit);
  const flying = avatarInflight.get(key);
  if (flying) return flying;
  const p = (async () => {
    const cached = await avGet(key).catch(() => null);   // persistent tier (survives reloads)
    if (cached) { avatarMem.set(key, cached); return cached; }
    const url = await api.fetchAvatar(viewerNodeId, pid).catch(() => null);  // network
    if (url) { avatarMem.set(key, url); avPut(key, url); }
    return url;
  })().finally(() => avatarInflight.delete(key));
  avatarInflight.set(key, p);
  return p;
}


// A rounded avatar: the node's profile photo (lazy-loaded + cached) or, when there
// is none, the familiar colored initial. `viewerNodeId` is the current node's
// public id — the server checks that this viewer may see the target node.
const Avatar: React.FC<{
  pid: string; name?: string; color?: string; avatarAt?: number;
  viewerNodeId?: string; size?: number; className?: string; circle?: boolean;
}> = ({ pid, name, color, avatarAt, viewerNodeId, size = 44, className = '', circle = false }) => {
  const radius = circle ? '50%' : Math.round(size * 0.28);
  const [url, setUrl] = useState<string | null>(() => (avatarAt ? (avatarMem.get(`${pid}:${avatarAt}`) || null) : null));
  useEffect(() => {
    let alive = true;
    if (avatarAt && viewerNodeId) {
      const cached = avatarMem.get(`${pid}:${avatarAt}`);
      if (cached) { setUrl(cached); return; }
      setUrl(null);
      loadAvatar(viewerNodeId, pid, avatarAt).then(u => { if (alive) setUrl(u); });
    } else { setUrl(null); }
    return () => { alive = false; };
  }, [pid, avatarAt, viewerNodeId]);
  const initial = (name?.trim()?.[0] || '?').toUpperCase();
  if (url) {
    return <img src={url} alt="" className={`object-cover shrink-0 ${className}`} style={{ width: size, height: size, borderRadius: radius }} />;
  }
  return (
    <div className={`flex items-center justify-center text-white font-black shrink-0 ${className}`}
      style={{ width: size, height: size, borderRadius: radius, backgroundColor: color || '#3f3f46', fontSize: Math.round(size * 0.42) }}>
      {initial}
    </div>
  );
};

// Profile info view for a user you can see: photo, name, full name-change history,
// bio — and, from a network tree or Direct Links, a button to add them to your
// personal hub (a symmetric contact request). Opened by the ⓘ button next to a
// name. Metadata is fetched on demand (kept out of the tree payload).
const ProfileSheet: React.FC<{
  viewerNodeId: string; targetPid: string;
  targetName?: string; targetColor?: string; targetAvatarAt?: number;
  canAddToHub?: boolean; onClose: () => void; onHubConnect?: (pid: string) => Promise<string>;
}> = ({ viewerNodeId, targetPid, targetName, targetColor, targetAvatarAt, canAddToHub, onClose, onHubConnect }) => {
  const [prof, setProf] = useState<{ name: string; color: string; bio: string; avatarAt: number; nameHistory: { name: string; at: number }[]; verified?: boolean } | null>(null);
  const [loading, setLoading] = useState(true);
  const [vouchBusy, setVouchBusy] = useState(false);
  const [vouchMsg, setVouchMsg] = useState<string | null>(null);
  // V8 phase 2: a verified member may confirm an active member that no signed
  // certificate vouches for yet (e.g. someone who joined through an old link).
  const canVouch = !!prof && prof.verified === false && api.trust.canVouch(viewerNodeId, targetPid);
  const vouch = async () => {
    if (vouchBusy) return;
    if (!confirm('Confirm this person as a member? Only do this if you know they really belong here — it vouches for their current safety number.')) return;
    setVouchBusy(true); setVouchMsg(null);
    try { await api.trust.vouchById(viewerNodeId, targetPid); setVouchMsg('Confirmed. Members will see them as verified after their next refresh.'); setProf(p => p ? { ...p, verified: true } : p); }
    catch (e: any) { setVouchMsg(e?.message || 'Could not confirm.'); }
    finally { setVouchBusy(false); }
  };
  const [hubBusy, setHubBusy] = useState(false);
  const [hubMsg, setHubMsg] = useState<string | null>(null);
  useEffect(() => {
    let alive = true; setLoading(true);
    api.fetchProfile(viewerNodeId, targetPid)
      .then(p => { if (alive) { setProf(p); setLoading(false); } })
      .catch(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [viewerNodeId, targetPid]);
  const name = prof?.name || targetName || 'Member';
  const avatarAt = prof?.avatarAt ?? targetAvatarAt;
  const history = (prof?.nameHistory || []).slice().reverse(); // most recent change first
  const fmt = (ms: number) => { try { return new Date(ms).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return ''; } };
  const addToHub = async () => {
    if (!onHubConnect || hubBusy) return;
    setHubBusy(true); setHubMsg(null);
    try {
      const status = await onHubConnect(targetPid);
      setHubMsg(
        status === 'connected' ? 'You’re already connected in your hub.'
        : status === 'pending' ? 'A request is already pending.'
        : 'Contact request sent — they’ll appear in your Personal Chats once they accept.');
    } catch (e: any) { setHubMsg(e?.message || 'Could not send request.'); }
    finally { setHubBusy(false); }
  };
  return (
    <div className="fixed inset-0 z-[85] bg-black/70 backdrop-blur-sm flex items-end md:items-center justify-center p-0 md:p-6 animate-in fade-in" onClick={onClose}>
      <div className="w-full md:max-w-md bg-[#0d0d0d] border border-white/10 rounded-t-3xl md:rounded-3xl p-6 max-h-[85dvh] overflow-y-auto no-scrollbar"
        onClick={e => e.stopPropagation()} style={{ paddingBottom: 'calc(env(safe-area-inset-bottom,0px) + 1.5rem)' }}>
        <div className="flex justify-between items-start mb-4">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600">Profile</div>
          <button onClick={onClose} className="p-1.5 -m-1.5 text-zinc-500 hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <div className="flex flex-col items-center text-center gap-3">
          <Avatar pid={targetPid} name={name} color={prof?.color || targetColor} avatarAt={avatarAt} viewerNodeId={viewerNodeId} size={88} />
          <div className="text-lg font-bold text-white break-words">{name}</div>
          {prof && prof.verified !== undefined && (
            <div className={`text-[10px] font-black uppercase tracking-widest ${prof.verified ? 'text-emerald-400/80' : 'text-amber-400/90'}`}
              title={prof.verified ? 'A signed invite or vouch from this network’s owner chain names this person and their key.' : 'No signed invite or vouch names this person yet. Messages you send won’t be encrypted to them until someone confirms them.'}>
              {prof.verified ? 'Verified member' : 'Membership not verified'}
            </div>
          )}
          {canVouch && (
            <button onClick={vouch} disabled={vouchBusy} className="text-[10px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 disabled:opacity-50">
              {vouchBusy ? '…' : 'Confirm member'}
            </button>
          )}
          {vouchMsg && <div className="text-[11px] text-zinc-400">{vouchMsg}</div>}
        </div>
        {loading ? (
          <div className="flex justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-zinc-600" /></div>
        ) : (
          <div className="mt-5 space-y-5">
            {prof?.bio && (
              <div>
                <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 mb-1.5">Bio</div>
                <div className="text-sm text-zinc-300 leading-relaxed whitespace-pre-wrap break-words">{prof.bio}</div>
              </div>
            )}
            <div>
              <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 mb-1.5">Name history</div>
              {history.length === 0 ? (
                <div className="text-[12px] text-zinc-500">No name changes — {name} has always gone by this name here.</div>
              ) : (
                <ul className="space-y-1.5">
                  <li className="flex items-center gap-2 text-[13px]"><span className="text-white font-semibold break-words">{name}</span><span className="text-[9px] text-emerald-400/70 uppercase tracking-wide shrink-0">current</span></li>
                  {history.map((h, i) => (
                    <li key={i} className="flex items-center justify-between gap-2 text-[13px] text-zinc-400">
                      <span className="truncate">was <span className="text-zinc-300">{h.name}</span></span>
                      <span className="text-[10px] text-zinc-600 shrink-0">until {fmt(h.at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            {canAddToHub && onHubConnect && (
              <div className="pt-1">
                <button onClick={addToHub} disabled={hubBusy}
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-emerald-500 text-black text-[12px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-50">
                  {hubBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />} Add to my personal hub
                </button>
                {hubMsg && <div className="text-[11px] text-zinc-400 mt-2 text-center leading-relaxed">{hubMsg}</div>}
                <div className="text-[10px] text-zinc-600 mt-2 text-center leading-relaxed">Connects you and {name} as private contacts in your Personal Chats.</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

interface DashboardProps {
  state: AppState;
  onLogout: () => void;
  onSwitchIdentity: (userId: string) => void;
  onSendMessage: (payload: { text?: string, imageUrl?: string, audioUrl?: string, videoUrl?: string, expiresAt?: number, replyTo?: { mid: string; name: string; text: string }, editsMid?: string, audioPeaks?: number[], audioDurMs?: number }, type: Message['type'], targetBranchId?: string, targets?: string[], targetCircle?: 'UP' | 'DOWN', targetUserId?: string, ackRequested?: boolean, targetGroup?: string, mentions?: { users?: string[]; viaGroup?: string[] }) => void;
  onPrune: (userId: string) => void;
  onTogglePermissions: (userId: string, perms: any) => void;
  onUpdateTreeSettings?: (changes: { treeName?: string; treeNameVisible?: boolean; monitorEnabled?: boolean; referralOpen?: boolean; globalChat?: boolean; autoAcceptInvites?: boolean }) => Promise<void>;
  typingPeers?: Record<string, { name: string; at: number }>;
  onReact?: (mid: string, emoji: string) => void;
  onTyping?: (toNodeId: string, state: 'start' | 'stop') => void;
  notifPermission: NotificationPermission;
  onEnableNotifications: () => Promise<NotificationPermission>; // toggles on/off
  pushEnabled: boolean;
  billingAlert: boolean;
  onDismissBillingAlert: () => void;
  callState: CallUIState;
  callActions: {
    start: (targets: { id: string; name: string }[]) => Promise<void>;
    accept: () => Promise<void>;
    decline: () => Promise<void>;
    hangup: () => Promise<void>;
    toggleMute: () => void;
    toggleVideo: () => Promise<void>;
    switchCamera: () => Promise<void>;
    getDiag: () => string;
  };
  onPanicWipe: () => Promise<void>;
  joinRequests: import('../types').JoinRequest[];
  onRespondJoin: (targetUserId: string, accept: boolean) => Promise<void>;
  onAcknowledge: (mid: string) => Promise<void>;
  onDeleteTree: () => Promise<void>;
  onDeleteForMe: (mids: string[]) => Promise<void>;
  onDeleteForAll: (mids: string[]) => Promise<void>;
  onSetGroups?: (ownerNodeId?: string, assignments?: Record<string, string | string[] | null>, labels?: Record<string, string | null>, parents?: Record<string, string | null>, links?: Record<string, { groups?: string[]; name?: string; archived?: boolean } | null>, visitors?: Record<string, string[] | null>) => Promise<void>;
  onMoveNode?: (nodeId: string, targetOwnerId: string, targetGroupId: string | null) => Promise<void>;
  onUpdateColor?: (color: string) => Promise<void>;
  // Network Profile: change my display name (kept with history), set/clear my bio
  // and profile photo, and add a user I can see to my personal hub.
  onUpdateName?: (name: string) => Promise<void>;
  onUpdateProfile?: (changes: { bio?: string | null; avatar?: string; removeAvatar?: boolean }) => Promise<{ bio: string; avatarAt: number } | void>;
  onHubConnect?: (targetPublicId: string) => Promise<string>;
}

// Convert a decrypted data: URL into a blob: URL for the lifetime of this element.
// This keeps the multi-MB base64 OUT of the DOM (huge perf win — React no longer
// diffs megabyte attribute strings) while guaranteeing the URL stays valid for as
// long as the component is mounted and is revoked exactly once on unmount. The
// previous shared LRU cache could revoke a URL still in use, which showed as a
// broken image ("Secure Asset" alt text).
function useBlobUrl(dataUrl: string): { src: string | null; failed: boolean } {
  const [state, setState] = useState<{ src: string | null; failed: boolean }>({ src: null, failed: false });
  useEffect(() => {
    if (!dataUrl) { setState({ src: null, failed: false }); return; }
    let created: string | null = null;
    let cancelled = false;
    // Defer the decode one microtask so a burst of newly-mounted media bubbles
    // doesn't decode several MB synchronously in the same frame (which is what
    // made the chat stutter right after images arrived).
    Promise.resolve().then(() => {
      if (cancelled) return;
      try {
        created = dataUrlToBlobUrl(dataUrl);
        if (!cancelled) setState({ src: created, failed: false });
        else if (created) { try { URL.revokeObjectURL(created); } catch {} }
      } catch (e) {
        try { console.warn('[media] blob decode failed:', e); } catch {}
        if (!cancelled) setState({ src: null, failed: true }); // visible failure, not an eternal spinner
      }
    });
    return () => {
      cancelled = true;
      if (created) { try { URL.revokeObjectURL(created); } catch {} }
    };
    // Re-run only if the underlying data actually changes.
  }, [dataUrl]);
  return state;
}

// Uniform visible-failure card: a media element must NEVER fail invisibly.
const MediaFailCard = ({ label }: { label: string }) => (
  <div className="w-64 h-24 bg-black/40 rounded-xl border border-white/5 flex flex-col items-center justify-center gap-2">
    <FileLock className="w-6 h-6 text-zinc-700" />
    <span className="text-[9px] font-black uppercase text-zinc-600 tracking-widest text-center px-3">{label}</span>
  </div>
);

// Lazily fetch + decrypt an out-of-band attachment, only once it's near the
// viewport, then render it through the existing secure media components. This is
// what makes a chat with dozens of images stay smooth: nothing is fetched,
// decrypted, or decoded until you actually scroll to it, and each blob loads
// independently instead of all at once inside one giant message.
const LazyAttachment = memo(({ att }: { att: import('../types').AttachmentRef }) => {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el || visible) return;
    // Start fetching a little before it scrolls into view.
    const io = new IntersectionObserver((entries) => {
      if (entries.some(e => e.isIntersecting)) { setVisible(true); io.disconnect(); }
    }, { rootMargin: '400px' });
    io.observe(el);
    return () => io.disconnect();
  }, [visible]);

  useEffect(() => {
    if (!visible) return;
    let cancelled = false;
    api.fetchAttachment(att)
      .then(url => { if (!cancelled) setDataUrl(url); })
      .catch(e => { try { console.warn('[attachment] fetch/decrypt failed:', e); } catch {} if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, [visible, att.id]);

  if (failed) return <MediaFailCard label={`${att.kind} failed to load`} />;
  if (!dataUrl) {
    return (
      <div ref={ref} className="w-48 h-32 bg-black/40 rounded-xl border border-white/5 flex items-center justify-center">
        <Loader2 className="w-5 h-5 text-zinc-700 animate-spin" />
      </div>
    );
  }
  if (att.kind === 'image') return <SecureImage url={dataUrl} />;
  if (att.kind === 'video') return <SecureVideo url={dataUrl} />;
  return <VoicePlayer url={dataUrl} peaks={att.peaks} durMs={att.durMs} />;
});

const SecureImage = memo(({ url }: { url: string }) => {
    // Hooks run UNCONDITIONALLY and FIRST (Rules of Hooks). Only a cheap header
    // check gates rendering — the multi-MB base64 body was already validated once
    // at ingest, so we never scan it again here.
    const headerOk = isSafeMediaHeader(url, 'image');
    const { src, failed } = useBlobUrl(headerOk ? url : '');
    const [imgError, setImgError] = useState(false);
    if (!headerOk) return <MediaFailCard label="Asset blocked" />;
    if (failed) return <MediaFailCard label="Image failed to decode" />;
    if (imgError) return <MediaFailCard label="Image failed to display" />;
    if (!src) {
        return <div className="w-48 h-32 bg-black/40 rounded-xl border border-white/5 flex items-center justify-center"><Loader2 className="w-5 h-5 text-zinc-700 animate-spin" /></div>;
    }
    return (
        <div className="max-w-xs md:max-w-md overflow-hidden rounded-xl border border-white/5 shadow-2xl">
            <img src={src} alt="Secure image" loading="lazy" decoding="async" className="w-full h-auto object-contain"
                onError={() => { try { console.warn('[media] <img> failed to display blob URL (check CSP img-src for blob:)'); } catch {} setImgError(true); }} />
        </div>
    );
});

const SecureVideo = memo(({ url }: { url: string }) => {
    const [failed, setFailed] = useState(false);
    const headerOk = isSafeMediaHeader(url, 'video');
    const { src, failed: decodeFailed } = useBlobUrl(headerOk ? url : '');
    if (!headerOk) return <MediaFailCard label="Asset blocked" />;
    if (decodeFailed) return <MediaFailCard label="Video failed to decode" />;
    if (!src) {
        return <div className="w-48 h-32 bg-black/40 rounded-xl border border-white/5 flex items-center justify-center"><Loader2 className="w-5 h-5 text-zinc-700 animate-spin" /></div>;
    }
    if (failed) {
        // Honest fallback: usually an HEVC ("High Efficiency") recording on a device
        // without an HEVC decoder. The bytes are intact — offer them for download.
        return (
            <div className="w-64 bg-black/40 rounded-xl border border-white/5 flex flex-col items-center justify-center gap-2 p-4">
                <FileLock className="w-6 h-6 text-zinc-700" />
                <span className="text-[9px] font-black uppercase text-zinc-600 tracking-widest text-center">{useT()('media.videoUnsupported')}</span>
                <a href={src} download="arbor-video.mp4" className="text-[10px] font-black uppercase tracking-widest text-emerald-400 underline underline-offset-2">{useT()('media.downloadInstead')}</a>
                <span className="text-[8px] text-zinc-700 text-center normal-case">Tip: iPhone → Settings → Camera → Formats → "Most Compatible" records universally playable video.</span>
            </div>
        );
    }
    return (
        <div className="max-w-xs md:max-w-md overflow-hidden rounded-xl border border-white/5 shadow-2xl">
            <video src={src} controls playsInline preload="metadata" onError={() => setFailed(true)} className="w-full h-auto" />
        </div>
    );
});

const getChildren = (userId: string, allUsers: User[]) => allUsers.filter(u => u.invitedBy === userId);

// A member may belong to ONE group (stored as a string, legacy) or MULTIPLE
// (string[]); null/absent = ungrouped. Read every membership through gidsOf so
// both shapes work identically — this MIRRORS the server's gidsOf, so the tree,
// the chat tabs, and the group editor all agree on who is in what. Membership is
// display/filing only here; the server is the sole authority on who can decrypt.
const gidsOf = (v: unknown): string[] => v == null ? []
  : Array.isArray(v) ? (v as unknown[]).filter((x): x is string => typeof x === 'string' && !!x)
  : (typeof v === 'string' && v ? [v] : []);
// Linked cross-group chats (and groups I'm visiting) that are their own
// conversation tab for this user. A message tagged to one belongs only there —
// never in Ancestors or a regular group chat. Archived links have no tab.
const linkChatIds = (me: User, users: User[]): Set<string> => {
  const ids = new Set<string>();
  const add = (o: any) => { for (const [k, v] of Object.entries(o || {})) if (!(v as any)?.archived) ids.add(k); };
  add((me as any).groupLinks);
  add((users.find(u => u.id === me.invitedBy) as any)?.myLinks);
  add((me as any).crossLinks);
  for (const v of ((me as any).visiting || [])) if (v && v.g) ids.add(v.g);
  return ids;
};

// A group node's one-line summary: how many people live under it ("below") and how
// many are only VISITING (members whose home group is elsewhere). Shared by every
// surface — Network Tree, Announcements, Monitor Hub — so they read identically.
const groupCountLabel = (below: number, visitors: number): string => {
  if (!below && !visitors) return 'Empty branch';
  const parts: string[] = [];
  if (below) parts.push(`${below} below`);
  if (visitors) parts.push(`${visitors} visiting`);
  return parts.join(' · ');
};

// Per-network "screen on start" preference — which tab a network opens to. Stored
// per node id so it's read SYNCHRONOUSLY at mount (the initial activeTab), meaning
// the correct tab is the first thing painted — no flash of a default then a switch.
const readStartTab = (nodeId?: string): string | null => { if (!nodeId) return null; try { return localStorage.getItem(`arbor_starttab_${nodeId}`); } catch { return null; } };
const writeStartTab = (nodeId: string, tab: string) => { try { localStorage.setItem(`arbor_starttab_${nodeId}`, tab); } catch {} };

// Repeatable "are you sure" gate for a dangerous, cross-compartment action. Each
// action passes its OWN storageKey so its warning count is tracked independently
// (never shared with other dangerous actions). Warns up to 3 times, then offers to
// stop warning for THAT action. Returns true to proceed, false to abort.
const dangerConfirm = (storageKey: string, body: string): boolean => {
  let n = 0; try { n = parseInt(localStorage.getItem(storageKey) || '0', 10) || 0; } catch {}
  if (n >= 99) return true; // opted out of this specific warning
  const ok = window.confirm(`${body}\n\nAre you sure whatever you're doing is worth it?\n\nThis message will display for the next three occurrences, where you can then choose to opt out.`);
  if (!ok) return false;
  const next = n + 1;
  try { localStorage.setItem(storageKey, String(next)); } catch {}
  if (next >= 3) {
    const optOut = window.confirm('That was the third warning. Turn OFF this warning for this action?\n\nOK = don’t warn me again.   Cancel = keep warning me.');
    try { localStorage.setItem(storageKey, optOut ? '99' : '3'); } catch {}
  }
  return true;
};

// Live, volume-sensitive input meter shown WHILE recording a voice note. Reads
// the analyser (tapping the mic stream) on its own rAF and keeps a rolling window
// of levels, so bars scroll right→left with your voice. Isolated in its own
// component so 60fps updates re-render only this strip, never the whole composer.
const REC_BARS = 32;
const RecordingMeter: React.FC<{ analyser: React.MutableRefObject<AnalyserNode | null> }> = ({ analyser }) => {
  const [levels, setLevels] = useState<number[]>(() => new Array(REC_BARS).fill(0));
  useEffect(() => {
    let raf = 0; let data: Uint8Array | null = null;
    const tick = () => {
      const an = analyser.current;
      if (an) {
        if (!data || data.length !== an.fftSize) data = new Uint8Array(an.fftSize);
        an.getByteTimeDomainData(data as any);
        let sum = 0, peak = 0;
        for (let i = 0; i < data.length; i++) { const v = Math.abs((data[i] - 128) / 128); sum += v * v; if (v > peak) peak = v; }
        const rms = Math.sqrt(sum / data.length);
        // Blend RMS + instantaneous peak, heavy gain, and a lift curve so ordinary
        // speech visibly drives the bars near full height.
        const level = Math.min(1, Math.pow(Math.max(rms * 3.6, peak * 1.6), 0.7));
        setLevels(prev => { const next = prev.slice(1); next.push(level); return next; });
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [analyser]);
  return (
    <div className="flex-1 min-w-0 flex items-center gap-[2px] h-9 px-2 overflow-hidden" aria-label="recording level">
      {levels.map((l, i) => (
        <span key={i} className="flex-1 rounded-full bg-red-500/80 self-center" style={{ height: `${Math.max(8, l * 100)}%`, minWidth: 2, transition: 'height 70ms linear' }} />
      ))}
    </div>
  );
};

// Renders a compact waveform from decoded PCM. Bars are precomputed peaks so the
// component stays cheap during playback (only the progress overlay animates).
const Waveform: React.FC<{ peaks: number[]; progress: number; onSeek: (frac: number) => void }> = ({ peaks, progress, onSeek }) => {
  const ref = useRef<HTMLDivElement>(null);
  const seek = (clientX: number) => {
    const el = ref.current; if (!el) return;
    const r = el.getBoundingClientRect();
    onSeek(Math.max(0, Math.min(1, (clientX - r.left) / r.width)));
  };
  return (
    <div ref={ref} className="relative flex items-center gap-[2px] h-10 flex-1 min-w-0 cursor-pointer"
      onClick={e => seek(e.clientX)}
      onTouchStart={e => { if (e.touches[0]) seek(e.touches[0].clientX); }}>
      {peaks.map((p, i) => {
        const played = i / peaks.length < progress;
        return <div key={i} className="flex-1 rounded-full transition-colors self-center" style={{ height: `${Math.max(4, p * 100)}%`, backgroundColor: played ? 'rgb(16,185,129)' : 'rgba(255,255,255,0.18)' }} />;
      })}
    </div>
  );
};

const VoicePlayer = memo(({ url, peaks: presetPeaks, durMs }: { url: string; peaks?: number[]; durMs?: number }) => {
  const headerOk = isSafeMediaHeader(url, 'audio');
  const { src, failed: decodeFailed } = useBlobUrl(headerOk ? url : '');
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [playing, setPlaying] = useState(false);
  const [progress, setProgress] = useState(0);
  // True length captured at record time; MediaRecorder blobs report a wrong/Infinity
  // duration, so prefer this for the stamp and progress. 0 = fall back to the element.
  const knownDur = durMs && durMs > 0 && isFinite(durMs) ? durMs / 1000 : 0;
  const [duration, setDuration] = useState(0);
  const totalDur = knownDur || duration;
  const [cur, setCur] = useState(0);
  const [rate, setRate] = useState(1);
  // Prefer the amplitude envelope captured at record time (always present & correct);
  // fall back to decoding the audio for peaks only when none was sent.
  const hasPreset = Array.isArray(presetPeaks) && presetPeaks.length > 1;
  const [peaks, setPeaks] = useState<number[]>(hasPreset ? presetPeaks!.map(v => Math.max(0, Math.min(1, Number(v) || 0))) : []);

  // Decode the audio once to extract ~40 waveform peaks. Pure on-device Web Audio.
  useEffect(() => {
    let cancelled = false;
    if (hasPreset) return; // envelope already supplied by the sender
    if (!src) return;
    (async () => {
      try {
        const resp = await fetch(src); const buf = await resp.arrayBuffer();
        const AC = (window.AudioContext || (window as any).webkitAudioContext);
        const ctx = new AC();
        const audio = await ctx.decodeAudioData(buf.slice(0));
        const raw = audio.getChannelData(0);
        const N = 44, block = Math.floor(raw.length / N) || 1; const out: number[] = [];
        let max = 0.0001;
        for (let i = 0; i < N; i++) {
          // PEAK (loudest sample) per block, not the average — averaging flattened
          // every bar to nearly the same height. Peaks keep the real dynamics.
          let peak = 0; const start = i * block; const end = Math.min(raw.length, start + block);
          for (let j = start; j < end; j += 2) { const a = Math.abs(raw[j] || 0); if (a > peak) peak = a; }
          out.push(peak); if (peak > max) max = peak;
        }
        // Normalize to a FRACTION of the max so the louder parts clip to full height
        // (bold), then an expansion curve (>1) drives quiet parts short — so the
        // difference between loud and quiet is very pronounced, not a flat ribbon.
        const norm = max * 0.62;
        if (!cancelled) setPeaks(out.map(v => Math.pow(Math.min(1, v / norm), 1.4)));
        ctx.close();
      } catch { if (!cancelled) setPeaks(Array.from({ length: 40 }, () => 0.3)); }
    })();
    return () => { cancelled = true; };
  }, [src]);

  const toggle = () => {
    const a = audioRef.current; if (!a) return;
    if (a.paused) { a.play(); setPlaying(true); } else { a.pause(); setPlaying(false); }
  };
  const cycleRate = () => {
    const next = rate === 1 ? 1.5 : rate === 1.5 ? 2 : 1;
    setRate(next); if (audioRef.current) audioRef.current.playbackRate = next;
  };
  const fmt = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;

  if (decodeFailed) return <MediaFailCard label="Voice message failed to decode" />;
  if (!headerOk) {
    return (
      <div className="flex items-center gap-2 bg-black/40 px-3 py-2.5 rounded-2xl border border-white/5">
        <FileLock className="w-4 h-4 text-zinc-700" />
        <span className="text-[9px] font-black uppercase text-zinc-600 tracking-widest">{useT()('media.audioBlocked')}</span>
      </div>
    );
  }
  return (
    <div className="bg-black/40 px-2.5 py-2 rounded-2xl border border-white/5 min-w-[220px] max-w-full space-y-1.5">
      <div className="flex items-center gap-2.5">
        {src ? (
          <>
            <audio ref={audioRef} src={src} preload="metadata" playsInline
              onLoadedMetadata={e => {
                const a = e.target as HTMLAudioElement; const d = a.duration;
                if (isFinite(d) && d > 0) { if (!knownDur) setDuration(d); }
                // MediaRecorder blobs report Infinity/NaN: nudge the element to the end
                // so it learns the real duration and fires 'ended' properly. The stamp
                // meanwhile uses knownDur, so the user never sees the bogus value.
                else { try { a.currentTime = 1e101; } catch {} }
              }}
              onDurationChange={e => {
                const a = e.target as HTMLAudioElement;
                if (isFinite(a.duration) && a.duration > 0) {
                  if (a.currentTime > 1e6) { try { a.currentTime = 0; } catch {} } // undo the nudge-seek
                  if (!knownDur) setDuration(a.duration);
                }
              }}
              onTimeUpdate={e => { const a = e.target as HTMLAudioElement; if (a.currentTime > 1e6) return; setCur(a.currentTime); const d = knownDur || (isFinite(a.duration) ? a.duration : 0); if (d) setProgress(Math.min(1, a.currentTime / d)); }}
              onPlay={() => setPlaying(true)}
              onPause={() => setPlaying(false)}
              onEnded={() => { setPlaying(false); setProgress(1); }} />
            <button onClick={toggle} className="shrink-0 w-9 h-9 rounded-full bg-emerald-500 text-black flex items-center justify-center hover:bg-emerald-400 transition-colors">
              {playing ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4 ml-0.5" />}
            </button>
            {peaks.length > 0
              ? <Waveform peaks={peaks} progress={progress} onSeek={frac => { const a = audioRef.current; const d = totalDur; if (a && d) { a.currentTime = frac * d; setProgress(frac); } }} />
              : <div className="flex-1 h-8 flex items-center"><Loader2 className="w-4 h-4 text-zinc-700 animate-spin" /></div>}
            <button onClick={cycleRate} title="Playback speed" className="shrink-0 text-[10px] font-black text-zinc-400 hover:text-emerald-400 transition-colors w-8 text-center tabular-nums">{rate}×</button>
          </>
        ) : <Loader2 className="w-4 h-4 text-zinc-700 animate-spin" />}
      </div>
      <div className="flex items-center justify-between px-1">
        <span className="text-[9px] font-mono text-zinc-600 tabular-nums">{fmt(cur)} / {fmt(totalDur)}</span>
      </div>
    </div>
  );
});

// Privacy-safe link handling. We do NOT fetch remote metadata (that would leak
// the reader's IP and read-timing to the linked site and any tracker). Instead
// we render a lightweight card from the URL itself — domain + path — and let the
// user choose to open it. URLs are linkified inline; each distinct URL also gets
// one compact card below the text.
const URL_RE = /\bhttps?:\/\/[^\s<>"']+/gi;
const extractUrls = (text?: string): string[] => {
  if (!text) return [];
  const found = text.match(URL_RE) || [];
  // De-dupe, cap at 3 cards, strip trailing punctuation.
  const clean = found.map(u => u.replace(/[.,;:!?)\]]+$/, ''));
  return Array.from(new Set(clean)).slice(0, 3);
};

const LinkPreview: React.FC<{ url: string; dark?: boolean }> = ({ url, dark }) => {
  let host = url, path = '';
  try { const u = new URL(url); host = u.hostname.replace(/^www\./, ''); path = u.pathname === '/' ? '' : u.pathname; } catch {}
  return (
    <a href={url} target="_blank" rel="noopener noreferrer nofollow"
      onClick={e => e.stopPropagation()}
      className={`flex items-center gap-2.5 mt-1.5 px-2.5 py-2 rounded-xl border transition-colors ${dark ? 'bg-black/5 border-black/10 hover:bg-black/10' : 'bg-black/20 border-white/10 hover:bg-black/30'}`}>
      <div className={`shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${dark ? 'bg-black/10' : 'bg-white/5'}`}>
        <LinkIcon className={`w-4 h-4 ${dark ? 'text-emerald-700' : 'text-emerald-400'}`} />
      </div>
      <div className="min-w-0">
        <div className={`text-[11px] font-bold truncate ${dark ? 'text-black/70' : 'text-zinc-200'}`}>{host}</div>
        {path && <div className={`text-[10px] truncate ${dark ? 'text-black/40' : 'text-zinc-500'}`}>{path}</div>}
      </div>
    </a>
  );
};

// Must match the server's REACTION_SET exactly.
const REACTION_EMOJI = ['👍', '❤️', '😂', '😮', '😢', '🙏', '🔥', '✅'];

// datetime-local expects "YYYY-MM-DDTHH:MM" in LOCAL time (no timezone suffix).
const toLocalInputValue = (d: Date) => {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};
// Quick presets: 3600000 = +1h; -1 = tonight 8pm; -2 = tomorrow 9am.
const presetDate = (val: number): Date => {
  const d = new Date();
  if (val === -1) { d.setHours(20, 0, 0, 0); if (d.getTime() < Date.now()) d.setDate(d.getDate() + 1); }
  else if (val === -2) { d.setDate(d.getDate() + 1); d.setHours(9, 0, 0, 0); }
  else { return new Date(Date.now() + val); }
  return d;
};

// Render message text with @mentions highlighted. A token highlights when the
// name right after '@' matches a known mentionable (group or person). It gets a
// STRONGER "you" highlight when it targets the viewer (their own alias, or a
// group they belong to). Highlighting is 100% client-side from the decrypted
// text — the server never sees who was mentioned in the words themselves.
function renderTextWithMentions(text: string, mentionNames?: Set<string>, selfNames?: Set<string>): React.ReactNode {
  if (!text || !mentionNames || mentionNames.size === 0 || text.indexOf('@') < 0) return text;
  const names = [...mentionNames].sort((a, b) => b.length - a.length); // longest-first for multi-word names
  const lower = text.toLowerCase();
  const out: React.ReactNode[] = []; let buf = ''; let i = 0; let k = 0;
  while (i < text.length) {
    if (text[i] === '@' && (i === 0 || /\s/.test(text[i - 1]))) {
      const rest = lower.slice(i + 1);
      const hit = names.find(n => n && rest.startsWith(n) && (rest.length === n.length || /[\s.,!?;:'")\]]/.test(rest[n.length])));
      if (hit) {
        if (buf) { out.push(buf); buf = ''; }
        const raw = text.slice(i, i + 1 + hit.length);
        const isSelf = !!selfNames && selfNames.has(hit);
        out.push(<span key={`m${k++}`} className={isSelf ? 'bg-emerald-500 text-black font-bold rounded px-1' : 'text-emerald-500 font-semibold'}>{raw}</span>);
        i += 1 + hit.length; continue;
      }
    }
    buf += text[i]; i++;
  }
  if (buf) out.push(buf);
  return out;
}

const MessageItem = memo(({ message, isMe, sender, isInviterTag, grouped, groupedNext, selecting, selected, onToggleSelect, onLongPress, onReply, onAcknowledge, onJumpTo, onReact, onVerifyIdentity, myId, mentionNames, selfNames, animate }: { message: Message, isMe: boolean, sender?: User, isInviterTag: boolean, grouped?: boolean, groupedNext?: boolean, selecting?: boolean, selected?: boolean, onToggleSelect?: (id: string) => void, onLongPress?: (id: string) => void, onReply?: (m: Message) => void, onAcknowledge?: (mid: string) => void, onJumpTo?: (mid: string) => void, onReact?: (mid: string, emoji: string) => void, onVerifyIdentity?: (senderId: string) => void, myId?: string, mentionNames?: Set<string>, selfNames?: Set<string>, animate?: boolean }) => {
    const { locale, t } = useLocale();
    const [reactOpen, setReactOpen] = useState(false);
    const pressTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
    const startPress = () => { if (selecting) return; pressTimer.current = setTimeout(() => { onLongPress?.(message.id); }, 450); };
    const cancelPress = () => { if (pressTimer.current) { clearTimeout(pressTimer.current); pressTimer.current = null; } };
    const mid = message.id;
    const acks = message.acks || [];
    const iAcked = false; // recipient-side ack state is derived by parent via disabling
    // ── Swipe-to-reply (iMessage-style): drag any bubble toward the center to
    // reply. Own messages (right side) swipe LEFT, others swipe RIGHT. The drag
    // must be clearly horizontal (|dx| > 2·|dy|) so vertical scrolling wins by
    // default, and the swipe cancels the long-press timer so the two gestures
    // never both fire.
    // reply. Own messages (right side) swipe LEFT, others swipe RIGHT.
    //
    // Gesture-lock state machine to kill the mobile jitter: the FIRST few pixels
    // of movement decide, once, whether this touch is a vertical scroll or a
    // horizontal reply-swipe. After that the decision is locked for the rest of
    // the touch — no more per-move flip-flopping between scroll and swipe (the
    // old code re-evaluated every move, so a curved drag would stutter). While
    // locked to 'scroll' we never call preventDefault, so the list scrolls
    // natively; while locked to 'swipe' we track the finger with rubber-banding
    // past the trigger and spring back on release.
    const swipe = useRef<{ x0: number; y0: number; lock: 'none' | 'scroll' | 'swipe' | 'react' }>({ x0: 0, y0: 0, lock: 'none' });
    const [swipeDx, setSwipeDx] = useState(0);
    const swipeFired = useRef(false);
    const SWIPE_TRIGGER = 52;
    const DECIDE_PX = 10; // movement before we commit to scroll vs. swipe

    const onSwipeStart = (e: React.TouchEvent) => {
        if (selecting || !onReply || e.touches.length !== 1) { swipe.current.lock = 'scroll'; return; }
        const t = e.touches[0];
        swipe.current = { x0: t.clientX, y0: t.clientY, lock: 'none' };
        swipeFired.current = false;
    };
    const onSwipeMove = (e: React.TouchEvent) => {
        const s = swipe.current;
        if (s.lock === 'scroll' || swipeFired.current || !e.touches[0]) return;
        const dx = e.touches[0].clientX - s.x0;
        const dy = e.touches[0].clientY - s.y0;

        // Phase 1 — decide once. Commit to whichever axis clearly wins.
        if (s.lock === 'none') {
            if (Math.abs(dx) < DECIDE_PX && Math.abs(dy) < DECIDE_PX) return; // not enough movement yet
            const horizontal = Math.abs(dx) > Math.abs(dy) * 1.4;
            // Reply-swipe: others swipe right; your OWN messages now ALSO reply on
            // a right-swipe (the natural direction). React moved to left-swipe.
            if (horizontal && dx > 0) {
                s.lock = 'swipe';
                cancelPress();
            // React-swipe: your OWN messages swiped LEFT open the reaction picker.
            } else if (horizontal && isMe && dx < 0 && onReact) {
                s.lock = 'react';
                cancelPress();
            } else {
                s.lock = 'scroll';
                return;
            }
        }

        // React-swipe (left on own message): open the reaction picker past a threshold.
        if (s.lock === 'react') {
            const toward = Math.max(0, -dx);
            const rubber = toward <= SWIPE_TRIGGER ? toward : SWIPE_TRIGGER + (toward - SWIPE_TRIGGER) * 0.3;
            setSwipeDx(-Math.min(rubber, SWIPE_TRIGGER + 24)); // negative marks react direction for the affordance
            if (toward >= SWIPE_TRIGGER && !swipeFired.current) {
                swipeFired.current = true;
                try { (navigator as any).vibrate?.(12); } catch {}
                setReactOpen(true);
                setSwipeDx(0);
                swipe.current.lock = 'scroll';
            }
            return;
        }

        // Phase 2 — locked to reply-swipe: track the finger rightward with
        // rubber-banding once past the trigger so it feels springy, not stuck.
        const toward = Math.max(0, dx);
        const rubber = toward <= SWIPE_TRIGGER ? toward : SWIPE_TRIGGER + (toward - SWIPE_TRIGGER) * 0.3;
        setSwipeDx(Math.min(rubber, SWIPE_TRIGGER + 24));

        if (toward >= SWIPE_TRIGGER && !swipeFired.current) {
            swipeFired.current = true;
            try { (navigator as any).vibrate?.(12); } catch {}
            onReply?.(message);
            // Spring back immediately; the reply bar is now open.
            setSwipeDx(0);
            swipe.current.lock = 'scroll';
        }
    };
    const onSwipeEnd = () => { swipe.current.lock = 'none'; setSwipeDx(0); };
    // Call-log entries render as a centered, non-interactive system row.
    if (message.callLog) {
        const cl = message.callLog;
        const fmtDur = (s?: number) => {
            if (!s) return '';
            const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
            return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}` : `${m}:${String(sec).padStart(2, '0')}`;
        };
        const missed = cl.outcome === 'missed' || cl.outcome === 'declined' || cl.outcome === 'no_answer';
        const label = cl.outcome === 'completed'
            ? `${cl.direction === 'outgoing' ? t('call.outgoing') : t('call.incoming')}${cl.video ? ' 📹' : ''} · ${fmtDur(cl.durationSec)}`
            : cl.outcome === 'declined' ? t('call.declined')
            : cl.direction === 'outgoing' ? t('call.noAnswer')
            : t('call.missed');
        const time = new Date(message.timestamp).toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
        const parts = cl.participants && cl.participants.length > 1 ? cl.participants : null;
        return (
            <div className="flex justify-center my-1.5 animate-in fade-in">
                <div
                    onPointerDown={startPress} onPointerUp={cancelPress} onPointerLeave={cancelPress} onPointerCancel={cancelPress}
                    onContextMenu={e => { e.preventDefault(); onLongPress?.(message.id); }}
                    className={`inline-flex flex-col gap-1 px-4 py-2.5 rounded-2xl border select-none cursor-pointer ${missed ? 'border-red-500/25 bg-red-500/5' : 'border-white/10 bg-white/[0.03]'}`}>
                    <div className="flex items-center gap-2">
                        {/* Caller marked on the left with a call icon */}
                        <div className={`flex items-center justify-center w-6 h-6 rounded-full ${missed ? 'bg-red-500/15' : 'bg-emerald-500/15'}`}>
                            {missed
                                ? <PhoneOff className="w-3 h-3 text-red-400 shrink-0" />
                                : cl.video ? <Video className="w-3 h-3 text-emerald-400 shrink-0" /> : <Phone className="w-3 h-3 text-emerald-400 shrink-0" />}
                        </div>
                        <div className="flex flex-col">
                            <span className={`text-[11px] font-bold ${missed ? 'text-red-300' : 'text-zinc-300'}`}>
                                {cl.callerName ? `${cl.callerName} started a ${cl.video ? 'video ' : ''}call` : label}
                            </span>
                            <span className="text-[9px] font-medium text-zinc-500">
                                {label}{cl.durationSec ? '' : ''} · <span className="font-mono">{time}</span>
                            </span>
                        </div>
                    </div>
                    {/* Everyone who joined */}
                    {parts && (
                        <div className="flex flex-wrap gap-1 pl-8">
                            {parts.map((p, i) => (
                                <span key={i} className="text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded-full bg-white/[0.05] text-zinc-400 border border-white/5">
                                    {p.name}
                                </span>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        );
    }
    // Sequential-merge geometry: fuse consecutive same-sender bubbles into one
    // block. Flatten the edge that touches a neighbor (top when this continues a
    // run, bottom when another continues from it) and keep the run's outer
    // corners round. The squared "tail" corner stays only on the run's FIRST
    // bubble, matching the previous single-bubble look for ungrouped messages.
    const R = 20, P = 6, TAIL = 2; // rounded / nested point / send-tail point
    const gFirst = !grouped && groupedNext, gMid = grouped && groupedNext, gLast = grouped && !groupedNext;
    let rTL = R, rTR = R, rBR = R, rBL = R;
    if (isMe) { // points on the right
      if (gFirst) rBR = P; else if (gMid) { rTR = P; rBR = P; } else if (gLast) { rTR = P; rBR = TAIL; } else rBR = TAIL;
    } else { // mirrored: points on the left
      if (gFirst) rBL = P; else if (gMid) { rTL = P; rBL = P; } else if (gLast) { rTL = P; rBL = TAIL; } else rBL = TAIL;
    }
    const bubbleRadius = `${rTL}px ${rTR}px ${rBR}px ${rBL}px`;
    // Real curved tail on the last bubble of a run (and standalone), matching side.
    const showTail = !message.keyChanged && (gLast || (!grouped && !groupedNext));
    const bubBg = isMe ? '#ffffff' : '#1c1c1e';
    const tailClass = showTail ? `msg-tail msg-tail-${isMe ? 'r' : 'l'}` : '';
    return (
        <div
            id={`msg-${message.id}`}
            data-mid={message.id}
            className={`relative flex ${isMe ? 'justify-end' : 'justify-start'} ${grouped ? '!mt-[3px]' : ''} ${animate ? (isMe ? 'msg-in-mine' : 'msg-in-other') : ''} transition-colors ${selecting ? 'cursor-pointer' : ''} ${selected ? 'bg-emerald-500/10 -mx-4 px-4 rounded-lg' : ''}`}
            onClick={selecting && onToggleSelect ? () => onToggleSelect(message.id) : undefined}
            onPointerDown={startPress} onPointerUp={cancelPress} onPointerLeave={cancelPress} onPointerCancel={cancelPress} onContextMenu={e => { if (!selecting) { e.preventDefault(); onLongPress?.(message.id); } }}
            onTouchStart={onSwipeStart} onTouchMove={onSwipeMove} onTouchEnd={onSwipeEnd} onTouchCancel={onSwipeEnd}
            style={{ touchAction: 'pan-y' }}>
            {/* Reply glyph on the left, revealed as the bubble slides right */}
            {swipeDx > 8 && (
                <div className="absolute top-1/2 -translate-y-1/2 left-0 flex items-center justify-center w-8 h-8 rounded-full bg-emerald-500/15"
                     style={{ opacity: Math.min(swipeDx / SWIPE_TRIGGER, 1), transform: `translateY(-50%) scale(${0.7 + 0.3 * Math.min(swipeDx / SWIPE_TRIGGER, 1)})` }}>
                    <Reply className="w-4 h-4 text-emerald-400" />
                </div>
            )}
            {/* React glyph on the right, revealed when swiping your own message left */}
            {swipeDx < -8 && (
                <div className="absolute top-1/2 -translate-y-1/2 right-0 flex items-center justify-center w-8 h-8 rounded-full bg-amber-500/15"
                     style={{ opacity: Math.min(-swipeDx / SWIPE_TRIGGER, 1), transform: `translateY(-50%) scale(${0.7 + 0.3 * Math.min(-swipeDx / SWIPE_TRIGGER, 1)})` }}>
                    <Smile className="w-4 h-4 text-amber-400" />
                </div>
            )}
            {selecting && (
                <div className="flex items-center pr-2">
                    <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center transition-colors ${selected ? 'bg-emerald-500 border-emerald-500' : 'border-zinc-600'}`}>
                        {selected && <Check className="w-3 h-3 text-black" />}
                    </div>
                </div>
            )}
            <div className={`max-w-[85%] md:max-w-[70%] flex flex-col ${isMe ? 'items-end' : 'items-start'}`}
                 style={swipeDx !== 0 ? { transform: `translateX(${swipeDx}px)`, transition: 'none' } : { transition: 'transform 200ms cubic-bezier(0.22, 1, 0.36, 1)' }}>
                <div className={`flex items-center gap-1.5 mb-1 px-2 ${grouped ? 'hidden' : ''}`}>
                    {sender && <Avatar pid={sender.id} name={sender.name} color={sender.color} avatarAt={(sender as any).avatarAt} viewerNodeId={myId} size={18} circle />}
                    <span className={`text-[10px] font-black uppercase tracking-tight ${isMe ? 'text-emerald-400' : 'text-zinc-600'}`}>
                        {sender?.name} {isInviterTag && <span className="text-emerald-500 ml-1 font-black uppercase tracking-tighter">(Inviter)</span>}
                        {sender?.nameClash && !isMe && (
                          // V8 L-8: another visible member has a look-alike name — a nudge
                          // to check the profile / safety number before trusting it.
                          <span title="Another member has a look-alike name — check their profile before trusting it"
                            className="ml-1 text-amber-400 font-black" aria-label="Look-alike name warning">⚠</span>
                        )}
                    </span>
                    <span className="text-[9px] text-zinc-500 font-mono">{new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    {isMe && (
                      message.sending
                        ? <Clock className="w-3 h-3 text-zinc-500" aria-label="Sending" />
                        : message.readAt
                          ? <CheckCheck className="w-3 h-3 text-emerald-400" aria-label="Read" />
                          : <Check className="w-3 h-3 text-zinc-500" aria-label="Delivered" />
                    )}
                    {!isMe && (
                      message.keyChanged
                        ? <AlertTriangle className="w-2.5 h-2.5 text-red-500" />
                        : message.verified
                          ? <ShieldCheck className="w-2.5 h-2.5 text-emerald-500" />
                          : null
                    )}
                    {!selecting && onReply && (
                      <button onClick={(e) => { e.stopPropagation(); onReply(message); }}
                        className="text-zinc-600 hover:text-emerald-400 transition-colors" aria-label="Reply">
                        <Reply className="w-3 h-3" />
                      </button>
                    )}
                    {!selecting && onReact && mid && !message.callLog && (
                      <div className="relative">
                        <button onClick={(e) => { e.stopPropagation(); setReactOpen(o => !o); }}
                          className="text-zinc-600 hover:text-amber-400 transition-colors" aria-label="React">
                          <Smile className="w-3 h-3" />
                        </button>
                        {reactOpen && (
                          <div className={`absolute z-40 -top-10 ${isMe ? 'right-0' : 'left-0'} flex items-center gap-0.5 bg-[#1a1a1a] border border-white/10 rounded-full px-1.5 py-1 shadow-2xl animate-in fade-in zoom-in-95 duration-150`}
                               onClick={e => e.stopPropagation()}>
                            {REACTION_EMOJI.map(em => (
                              <button key={em} onClick={() => { onReact(mid, em); setReactOpen(false); }}
                                className="text-sm hover:scale-125 transition-transform px-0.5">{em}</button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                </div>
                {message.type === 'BROADCAST' && !isMe && (
                    <div className="mb-1 px-2 flex items-center gap-1.5 text-[8px] font-black uppercase tracking-widest text-emerald-500/80">
                        <Radio className="w-2.5 h-2.5" />
                        {t('msg.announcementFromLevel', { level: typeof message.senderLevel === 'number' ? message.senderLevel : '—' })}
                    </div>
                )}
                <div style={{ borderRadius: bubbleRadius, ...(showTail ? { ['--bub' as any]: bubBg } : {}) }} className={`
                    px-4 py-1.5 text-[14px] leading-relaxed shadow-lg relative break-words space-y-2 ${tailClass}
                    ${message.keyChanged ? 'border border-red-500/40 bg-red-500/5 text-red-100' : (isMe ? 'bg-white text-black shadow-emerald-500/10' : 'bg-[#1c1c1e] text-zinc-100 shadow-lg shadow-black/30')}
                `}>
                    {message.keyChanged && (
                        <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); if (!isMe) onVerifyIdentity?.(message.senderId); }}
                            className="w-full flex items-center justify-between gap-1.5 text-[9px] font-black uppercase tracking-widest text-red-400 border-b border-red-500/20 pb-1.5 mb-1 hover:text-red-300 transition-colors">
                            <span className="flex items-center gap-1.5"><AlertTriangle className="w-3 h-3" /> Identity changed — verify safety number</span>
                            {!isMe && <span className="text-[8px] px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30">Verify →</span>}
                        </button>
                    )}
                    {message.editRefused && (
                        // v71 M1: an edit that was NOT applied (key changed / not bound);
                        // the original message is unchanged.
                        <div className="text-[9px] font-black uppercase tracking-widest text-amber-400 border-b border-amber-500/20 pb-1.5 mb-1">Edit not applied — original kept</div>
                    )}
                    {message.replyTo && (
                        <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); if (message.replyTo) onJumpTo?.(message.replyTo.mid); }}
                            className={`w-full text-left border-l-2 pl-2.5 py-1 mb-1 rounded-r transition-colors ${isMe ? 'border-emerald-600/50 bg-black/5 hover:bg-black/10' : 'border-emerald-500/40 bg-black/20 hover:bg-black/30'}`}>
                            <div className={`text-[9px] font-black uppercase tracking-wide ${isMe ? 'text-emerald-700' : 'text-emerald-400'}`}>
                                {message.replyTo.name}
                                {/* v71 L7: the quoted message isn't on this device, so name + text are only the sender's claim */}
                                {message.replyTo.unverified && <span className={`ml-1.5 normal-case font-bold ${isMe ? 'text-black/40' : 'text-zinc-500'}`}>· quote not on this device</span>}
                            </div>
                            <div className={`text-[11px] line-clamp-2 break-words ${isMe ? 'text-black/50' : 'text-zinc-400'}`}>{message.replyTo.text}</div>
                        </button>
                    )}
                    {message.imageUrl && <SecureImage url={message.imageUrl} />}
                    {message.audioUrl && <VoicePlayer url={message.audioUrl} />}
                    {message.videoUrl && <SecureVideo url={message.videoUrl} />}
                    {message.attachments?.map((att, i) => <LazyAttachment key={att.id + i} att={att} />)}
                    {message.text && <div className="whitespace-pre-wrap">{renderTextWithMentions(message.text, mentionNames, selfNames)}</div>}
                    {extractUrls(message.text).map((u, i) => <LinkPreview key={i} url={u} dark={isMe} />)}
                    {message.edited && (
                        <div className={`text-[8px] font-bold uppercase tracking-widest ${isMe ? 'text-black/35' : 'text-zinc-600'}`}>{t('msg.edited')}</div>
                    )}
                    {message.expiresAt && (
                        <div className={`flex items-center gap-1 text-[8px] font-black uppercase tracking-widest ${isMe ? 'text-black/40' : 'text-zinc-500'}`}>
                            <Timer className="w-2.5 h-2.5" /> {t('msg.disappears')}
                        </div>
                    )}
                </div>
                {/* Reaction pills — aggregated counts; tapping toggles yours. */}
                {message.reactions && Object.keys(message.reactions).length > 0 && (
                    <div className={`mt-1 flex flex-wrap gap-1 px-1 ${isMe ? 'justify-end' : 'justify-start'}`}>
                        {Object.entries(message.reactions).map(([em, people]) => {
                            const mine = !!myId && people.some(p => p.id === myId);
                            return (
                                <button key={em}
                                    onClick={(e) => { e.stopPropagation(); if (mid && onReact) onReact(mid, em); }}
                                    title={people.map(p => p.name).join(', ')}
                                    className={`flex items-center gap-1 px-1.5 py-0.5 rounded-full border text-[11px] transition-colors ${mine ? 'bg-emerald-500/15 border-emerald-500/40' : 'bg-white/[0.04] border-white/10 hover:border-white/20'}`}>
                                    <span>{em}</span>
                                    <span className={`text-[9px] font-bold ${mine ? 'text-emerald-400' : 'text-zinc-500'}`}>{people.length}</span>
                                </button>
                            );
                        })}
                    </div>
                )}
                {/* Broadcast acknowledgment */}
                {message.ackRequested && (
                  isMe ? (
                    <div className="mt-1 px-2 flex items-center gap-1.5 text-[9px] text-zinc-500">
                      <CheckCheck className="w-3 h-3 text-emerald-500" />
                      {acks.length > 0
                        ? <span>{t('msg.ackedBy', { names: acks.map(a => a.name).join(', ') })}</span>
                        : <span>{t('msg.awaitingAck')}</span>}
                    </div>
                  ) : onAcknowledge && mid ? (
                    <button onClick={(e) => { e.stopPropagation(); onAcknowledge(mid); }}
                      className="mt-1 px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 text-[9px] font-black uppercase tracking-widest hover:bg-emerald-500/20 transition-colors flex items-center gap-1.5">
                      <Check className="w-3 h-3" /> {t('msg.acknowledge')}
                    </button>
                  ) : null
                )}
            </div>
        </div>
    );
}, (prev, next) => {
    const a = prev.message, b = next.message;
    return a.id === b.id
        && a.readAt === b.readAt
        && a.sending === b.sending
        && a.verified === b.verified
        && a.keyChanged === b.keyChanged
        && a.expiresAt === b.expiresAt
        && a.editedAt === b.editedAt
        && a.ackRequested === b.ackRequested
        && a.senderLevel === b.senderLevel
        && a.text === b.text
        && a.imageUrl === b.imageUrl
        && (a.acks?.map(x => x.id).join(',') === b.acks?.map(x => x.id).join(','))
        && (JSON.stringify(a.reactions || {}) === JSON.stringify(b.reactions || {}))
        && (a.attachments?.map(x => x.id).join(',') === b.attachments?.map(x => x.id).join(','))
        && a.audioUrl === b.audioUrl
        && a.videoUrl === b.videoUrl
        && prev.isMe === next.isMe
        && prev.grouped === next.grouped
        && prev.groupedNext === next.groupedNext
        && prev.isInviterTag === next.isInviterTag
        && prev.sender?.name === next.sender?.name
        && (prev.sender as any)?.avatarAt === (next.sender as any)?.avatarAt
        && prev.selecting === next.selecting
        && prev.selected === next.selected
        && prev.animate === next.animate;
});
interface TreeData { user: User; children: TreeData[]; }

const PAD = 80, R = 30, H_GAP = 172, V_GAP = 150;
const NODE_W = 132, NODE_H = 52;

function layoutTree(root: TreeData) {
  const placed: { user: User; x: number; y: number }[] = [];
  let leaf = 0;
  const assign = (node: TreeData, depth: number): number => {
    let x: number;
    if (node.children.length === 0) { x = leaf * H_GAP; leaf += 1; }
    else {
      const xs = node.children.map(c => assign(c, depth + 1));
      x = (xs[0] + xs[xs.length - 1]) / 2;
    }
    placed.push({ user: node.user, x, y: depth * V_GAP });
    return x;
  };
  assign(root, 0);
  const pos = new Map(placed.map(p => [p.user.id, p]));
  const edges: { x1: number; y1: number; x2: number; y2: number; parentId: string; childId: string }[] = [];
  const walk = (node: TreeData) => {
    const p = pos.get(node.user.id)!;
    node.children.forEach(c => { const cp = pos.get(c.user.id)!; edges.push({ x1: p.x, y1: p.y, x2: cp.x, y2: cp.y, parentId: node.user.id, childId: c.user.id }); walk(c); });
  };
  walk(root);
  const xs = placed.map(p => p.x);
  const minX = Math.min(0, ...xs), maxX = Math.max(0, ...xs);
  const maxY = Math.max(0, ...placed.map(p => p.y));
  const offX = PAD - minX;
  return {
    nodes: placed.map(p => ({ user: p.user, cx: p.x + offX, cy: p.y + PAD })),
    edges: edges.map(e => ({ ...e, x1: e.x1 + offX, y1: e.y1 + PAD, x2: e.x2 + offX, y2: e.y2 + PAD })),
    width: (maxX - minX) + 2 * PAD, height: maxY + 2 * PAD,
  };
}

// Cross-level links join two groups on DIFFERENT tree levels. Rather than
// drawing connector wires across the tree (which read as cluttered no matter
// how they were routed), each link gets its OWN color and every group it
// touches shows a small link symbol in that color next to its name — the same
// color on two nodes means they are linked.
const XLINK_COLORS = ['#f43f5e', '#a855f7', '#22d3ee', '#f59e0b', '#84cc16', '#ec4899', '#60a5fa', '#fb923c'];
// Color for the i-th cross-level link. The first 8 use the hand-picked palette;
// beyond that we generate well-separated hues with the golden angle (137.5°) so
// we NEVER run out and adjacent links stay visually distinct — a network could
// in principle have dozens of cross-level links.
const xlinkColor = (i: number): string => i < XLINK_COLORS.length ? XLINK_COLORS[i] : `hsl(${((i * 137.508) % 360).toFixed(0)}, 72%, 62%)`;
// Names longer than this get hard-capped with an ellipsis inside a node; shorter
// ones simply wrap. Keeps a pathological name from ballooning a node box.
const NODE_NAME_CAP = 28;
const capName = (s: string | undefined): string => { const t = s || ''; return t.length > NODE_NAME_CAP ? t.slice(0, NODE_NAME_CAP - 1).trimEnd() + '…' : t; };

// Row/Toggle/Section are MODULE-scope on purpose. They were previously defined
// inside SettingsView/HowToView, which recreates the component TYPE every
// render — React then unmounts and remounts every row/toggle subtree on each
// state change. On mobile that manifested as dropped taps, toggle flicker, and
// inputs losing focus mid-typing. Hoisting gives them stable identity.
const SettingsRow: React.FC<{ title: string; desc: string; children: React.ReactNode }> = ({ title, desc, children }) => (
  <div className="flex items-start justify-between gap-4 p-4 rounded-2xl bg-[#111] border border-white/5">
    <div className="flex-1 min-w-0">
      <div className="text-sm font-bold text-white">{title}</div>
      <div className="text-[11px] text-zinc-500 leading-relaxed mt-0.5">{desc}</div>
    </div>
    <div className="shrink-0">{children}</div>
  </div>
);
const SettingsToggle: React.FC<{ on: boolean; onClick: () => void; disabled?: boolean }> = ({ on, onClick, disabled }) => (
  <button onClick={onClick} disabled={disabled}
    className={`w-11 h-6 rounded-full transition-colors relative ${on ? 'bg-emerald-500' : 'bg-zinc-700'} ${disabled ? 'opacity-50' : ''}`}>
    <div className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all ${on ? 'left-[22px]' : 'left-0.5'}`} />
  </button>
);

const SettingsView: React.FC<{
  receiptsOn: boolean; onToggleReceipts: (on: boolean) => void; settingsBusy: boolean;
  recoveryStatus: boolean | null;
  accountUsername?: string | null;
  onSetupRecovery?: (password: string) => Promise<string>;
  pushEnabled: boolean; onToggleNotifications: () => Promise<NotificationPermission>; notifPermission: NotificationPermission;
  notifyPref?: 'all' | 'mentions' | 'alias'; onNotifyPref?: (p: 'all' | 'mentions' | 'alias') => void;
  isRootUser: boolean; onPanicWipe: () => Promise<void>; onDeleteTree: () => Promise<void>;
  currentUser?: User; users: User[];
  dmMode?: boolean; hubMode?: boolean;
  networkNameVisible?: boolean;
  onUpdateTreeSettings?: (changes: { treeName?: string; treeNameVisible?: boolean; monitorEnabled?: boolean; referralOpen?: boolean; globalChat?: boolean; autoAcceptInvites?: boolean }) => Promise<void>;
  onUpdateColor?: (color: string) => Promise<void>;
  onUpdateName?: (name: string) => Promise<void>;
  onUpdateProfile?: (changes: { bio?: string | null; avatar?: string; removeAvatar?: boolean }) => Promise<{ bio: string; avatarAt: number } | void>;
  startTab: string; startTabOptions: { id: string; label: string }[]; onStartTab: (id: string) => void;
}> = ({ receiptsOn, onToggleReceipts, settingsBusy, recoveryStatus, accountUsername, onSetupRecovery, pushEnabled, onToggleNotifications, notifPermission, notifyPref = 'all', onNotifyPref, isRootUser, onPanicWipe, onDeleteTree, currentUser, users, dmMode, hubMode, networkNameVisible, onUpdateTreeSettings, onUpdateColor, onUpdateName, onUpdateProfile, startTab, startTabOptions, onStartTab }) => {
  const t = useT();
  const memberCount = users.filter(u => !u.pending).length;
  // Root-only network name + visibility editing.
  const [nameDraft, setNameDraft] = useState(currentUser?.treeName || '');
  const [nameBusy, setNameBusy] = useState(false);
  const [nameSaved, setNameSaved] = useState(false);
  const [visBusy, setVisBusy] = useState(false);
  useEffect(() => { setNameDraft(currentUser?.treeName || ''); }, [currentUser?.treeName]);
  const saveName = async () => {
    if (!onUpdateTreeSettings || nameBusy) return;
    const v = nameDraft.trim();
    if (!v || v === currentUser?.treeName) return;
    setNameBusy(true);
    try { await onUpdateTreeSettings({ treeName: v }); setNameSaved(true); setTimeout(() => setNameSaved(false), 2000); }
    catch (e: any) { alert(e?.message || 'Could not rename.'); }
    finally { setNameBusy(false); }
  };
  const toggleVis = async () => {
    if (!onUpdateTreeSettings || visBusy) return;
    setVisBusy(true);
    try { await onUpdateTreeSettings({ treeNameVisible: !networkNameVisible }); }
    catch (e: any) { alert(e?.message || 'Could not update visibility.'); }
    finally { setVisBusy(false); }
  };
  const [monBusy, setMonBusy] = useState(false);
  const monitorOn = currentUser?.monitorEnabled !== false;
  const toggleMon = async () => {
    if (!onUpdateTreeSettings || monBusy) return;
    setMonBusy(true);
    try { await onUpdateTreeSettings({ monitorEnabled: !monitorOn }); }
    catch (e: any) { alert(e?.message || 'Could not update monitoring.'); }
    finally { setMonBusy(false); }
  };
  // Direct-Only only: let members invite, with every joiner re-parented to root.
  const [refBusy, setRefBusy] = useState(false);
  const referralOn = !!currentUser?.referralOpen;
  const toggleReferral = async () => {
    if (!onUpdateTreeSettings || refBusy) return;
    setRefBusy(true);
    try { await onUpdateTreeSettings({ referralOpen: !referralOn }); }
    catch (e: any) { alert(e?.message || 'Could not update referral mode.'); }
    finally { setRefBusy(false); }
  };
  const [gcBusy, setGcBusy] = useState(false);
  const globalChatOn = !!currentUser?.globalChat;
  const toggleGlobalChat = async () => {
    if (!onUpdateTreeSettings || gcBusy) return;
    setGcBusy(true);
    try { await onUpdateTreeSettings({ globalChat: !globalChatOn }); }
    catch (e: any) { alert(e?.message || 'Could not update global chat.'); }
    finally { setGcBusy(false); }
  };
  const [aaBusy, setAaBusy] = useState(false);
  // currentUser flips instantly (App applies the change before the round trip) and
  // is held sticky against stale reads, so the switch just reads it directly.
  const autoAcceptOn = !!currentUser?.autoAcceptInvites;
  const toggleAutoAccept = async () => {
    if (!onUpdateTreeSettings || aaBusy) return;
    setAaBusy(true);
    try { await onUpdateTreeSettings({ autoAcceptInvites: !autoAcceptOn }); }
    catch (e: any) { alert(e?.message || 'Could not update auto-accept.'); }
    finally { setAaBusy(false); }
  };
  // Icon color (as it appears to everyone who can see this node).
  const [colorBusy, setColorBusy] = useState(false);
  const changeColor = async (c: string) => {
    if (!onUpdateColor || colorBusy || c === currentUser?.color) return;
    setColorBusy(true);
    try { await onUpdateColor(c); }
    catch (e: any) { alert(e?.message || 'Could not update color.'); }
    finally { setColorBusy(false); }
  };
  // ---- Network Profile: display name (+ server-kept history), photo, bio ----
  const hasAvatar = !!(currentUser?.avatarAt);
  const [pName, setPName] = useState(currentUser?.name || '');
  useEffect(() => { setPName(currentUser?.name || ''); }, [currentUser?.name]);
  const [pNameBusy, setPNameBusy] = useState(false);
  const [pNameSaved, setPNameSaved] = useState(false);
  const saveProfileName = async () => {
    const v = pName.trim();
    if (!onUpdateName || pNameBusy || !v || v === currentUser?.name) return;
    setPNameBusy(true);
    try { await onUpdateName(v); setPNameSaved(true); setTimeout(() => setPNameSaved(false), 2000); }
    catch (e: any) { alert(e?.message || 'Could not update name.'); }
    finally { setPNameBusy(false); }
  };
  const [bioDraft, setBioDraft] = useState(currentUser?.bio || '');
  useEffect(() => { setBioDraft(currentUser?.bio || ''); }, [currentUser?.bio]);
  const [bioBusy, setBioBusy] = useState(false);
  const [bioSaved, setBioSaved] = useState(false);
  const saveBio = async () => {
    if (!onUpdateProfile || bioBusy) return;
    const v = bioDraft.trim();
    if (v === (currentUser?.bio || '')) return;
    setBioBusy(true);
    try { await onUpdateProfile({ bio: v || null }); setBioSaved(true); setTimeout(() => setBioSaved(false), 2000); }
    catch (e: any) { alert(e?.message || 'Could not update bio.'); }
    finally { setBioBusy(false); }
  };
  const avatarInputRef = useRef<HTMLInputElement | null>(null);
  const [avatarBusy, setAvatarBusy] = useState(false);
  const pickAvatar = async (file?: File | null) => {
    if (!onUpdateProfile || !file || avatarBusy) return;
    setAvatarBusy(true);
    try {
      // Scrub + downscale on-device (canvas re-encode) BEFORE anything leaves the
      // device, then upload. The original file's bytes never go to the server.
      const scrubbed = await prepareAvatar(file);
      const res = await onUpdateProfile({ avatar: scrubbed });
      // Seed both cache tiers so the preview is instant and survives reloads.
      if (res && (res as any).avatarAt && currentUser) seedAvatar(currentUser.id, (res as any).avatarAt, scrubbed);
    } catch (e: any) { alert(e?.message || 'Could not process image.'); }
    finally { setAvatarBusy(false); if (avatarInputRef.current) avatarInputRef.current.value = ''; }
  };
  const removeAvatarNow = async () => {
    if (!onUpdateProfile || avatarBusy) return;
    setAvatarBusy(true);
    try { await onUpdateProfile({ removeAvatar: true }); }
    catch (e: any) { alert(e?.message || 'Could not remove photo.'); }
    finally { setAvatarBusy(false); }
  };
  // Post-signup recovery phrase setup (requires the current password so the
  // stored blob is guaranteed to contain working credentials).
  const [recOpen, setRecOpen] = useState(false);
  const [recPw, setRecPw] = useState('');
  const [recBusy, setRecBusy] = useState(false);
  const [recErr, setRecErr] = useState<string | null>(null);
  const [recPhrase, setRecPhrase] = useState<string | null>(null);
  const [recCopied, setRecCopied] = useState(false);
  const doSetupRecovery = async () => {
    if (!onSetupRecovery || !recPw || recBusy) return;
    setRecBusy(true); setRecErr(null);
    try { setRecPhrase(await onSetupRecovery(recPw)); setRecPw(''); }
    catch (e: any) { setRecErr(e?.message || 'Setup failed'); }
    finally { setRecBusy(false); }
  };
  return (
    <div className="flex-1 overflow-y-auto p-4 md:p-8 no-scrollbar">
      <div className="max-w-lg mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">{t('settings.title')}</h2>
          <p className="text-[11px] text-zinc-600 uppercase tracking-widest mt-1">{currentUser?.name} · {isRootUser ? t('settings.networkRoot') : t('settings.member')}</p>
        </div>

        {currentUser && (
          <div className="space-y-2">
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">Network Profile</div>
            <div className="p-4 rounded-2xl bg-[#111] border border-white/5 space-y-4">
              {/* Identity row: photo preview + who you are here */}
              <div className="flex items-center gap-3">
                <Avatar pid={currentUser.id} name={currentUser.name} color={currentUser.color} avatarAt={currentUser.avatarAt} viewerNodeId={currentUser.id} size={56} />
                <div className="min-w-0">
                  <div className="text-sm font-bold text-white truncate">{currentUser.name}</div>
                  <div className="text-[10px] text-zinc-500 leading-relaxed">How you appear to everyone who can see you in this network.</div>
                </div>
                {avatarBusy && <Loader2 className="w-4 h-4 animate-spin text-zinc-500 ml-auto shrink-0" />}
              </div>

              {/* Display name (+ history) */}
              {onUpdateName && (
                <div>
                  <div className="text-[11px] font-bold text-white mb-1.5">Display name</div>
                  <div className="flex gap-2">
                    <input value={pName} maxLength={64}
                      onChange={e => setPName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') saveProfileName(); }}
                      className="flex-1 bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors" />
                    <button onClick={saveProfileName} disabled={pNameBusy || !pName.trim() || pName.trim() === currentUser.name}
                      className="px-4 rounded-xl bg-emerald-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-40">
                      {pNameBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : pNameSaved ? <Check className="w-3.5 h-3.5" /> : 'Save'}
                    </button>
                  </div>
                  <div className="text-[10px] text-zinc-600 mt-1.5 leading-relaxed">Your past names are kept and shown on your profile, so contacts can see when you’ve changed it.</div>
                  {currentUser && (currentUser.nameHistory || []).length > 0 && (
                    <button
                      onClick={async () => {
                        if (!confirm('Erase your past names in this network? Your current name stays; the history is deleted from the server.')) return;
                        try { await api.clearNameHistory(currentUser.id); alert('Name history cleared.'); }
                        catch (e: any) { alert(e?.message || 'Could not clear the history.'); }
                      }}
                      className="mt-2 text-[10px] font-bold text-zinc-400 hover:text-red-300 underline underline-offset-2 transition-colors">
                      Clear my name history ({(currentUser.nameHistory || []).length})
                    </button>
                  )}
                </div>
              )}

              {/* Profile photo — EXIF/metadata stripped on-device */}
              {onUpdateProfile && (
                <div>
                  <div className="text-[11px] font-bold text-white mb-1.5">Profile photo</div>
                  <input ref={avatarInputRef} type="file" accept="image/*" className="hidden" onChange={e => pickAvatar(e.target.files?.[0])} />
                  <div className="flex items-center gap-2">
                    <button onClick={() => avatarInputRef.current?.click()} disabled={avatarBusy}
                      className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-white/5 text-zinc-200 text-[11px] font-bold hover:bg-white/10 transition-colors disabled:opacity-40">
                      <ImageIcon className="w-4 h-4" /> {hasAvatar ? 'Replace photo' : 'Upload photo'}
                    </button>
                    {hasAvatar && (
                      <button onClick={removeAvatarNow} disabled={avatarBusy}
                        className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-white/5 text-red-300 text-[11px] font-bold hover:bg-red-500/15 transition-colors disabled:opacity-40">
                        <Trash2 className="w-4 h-4" /> Remove
                      </button>
                    )}
                  </div>
                  <div className="flex items-start gap-1.5 text-[10px] text-emerald-400/80 mt-2 leading-relaxed">
                    <Shield className="w-3.5 h-3.5 shrink-0 mt-px" />
                    <span>All photo metadata &amp; EXIF (location, device, timestamps) is stripped on your device — the original file never leaves it — and the photo is end-to-end encrypted: only members of this network can see it, never the server.</span>
                  </div>
                </div>
              )}

              {/* Bio (optional) */}
              {onUpdateProfile && (
                <div>
                  <div className="text-[11px] font-bold text-white mb-1.5">Bio <span className="text-zinc-600 font-normal normal-case">(optional)</span></div>
                  <textarea value={bioDraft} maxLength={500} rows={3}
                    onChange={e => setBioDraft(e.target.value)}
                    placeholder="A short line about you (optional)."
                    className="w-full bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors resize-none" />
                  <div className="flex items-center justify-between mt-1.5">
                    <span className="text-[10px] text-zinc-600">{bioDraft.length}/500</span>
                    <button onClick={saveBio} disabled={bioBusy || bioDraft.trim() === (currentUser.bio || '')}
                      className="px-4 py-1.5 rounded-lg bg-emerald-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-40">
                      {bioBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : bioSaved ? <Check className="w-3.5 h-3.5" /> : 'Save bio'}
                    </button>
                  </div>
                </div>
              )}

              {/* Icon color — only when there is no photo (a photo replaces the colored icon) */}
              {onUpdateColor && !hasAvatar && (
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <div className="text-[11px] font-bold text-white">Icon color</div>
                    {colorBusy && <Loader2 className="w-3.5 h-3.5 animate-spin text-zinc-500" />}
                  </div>
                  <div className="text-[10px] text-zinc-500 leading-relaxed mb-2">Shown when you don’t have a profile photo.</div>
                  <div className="flex flex-wrap gap-2">
                    {ICON_COLORS.map(c => (
                      <button key={c} type="button" disabled={colorBusy} onClick={() => changeColor(c)} aria-label={`Use color ${c}`}
                        className={`w-7 h-7 rounded-full transition-transform disabled:opacity-60 ${currentUser.color === c ? 'ring-2 ring-white ring-offset-2 ring-offset-[#111] scale-110' : 'hover:scale-110'}`}
                        style={{ backgroundColor: c }} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        <div className="space-y-2">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">Screen on start</div>
          <div className="p-4 rounded-2xl bg-[#111] border border-white/5 space-y-2.5">
            <div className="flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-[11px] font-bold text-white">Open this network to</div>
                <div className="text-[10px] text-zinc-500 leading-relaxed">Which tab appears the moment you open this network on this device.</div>
              </div>
              <select value={startTab} onChange={e => onStartTab(e.target.value)}
                className="shrink-0 bg-black border border-white/10 rounded-lg text-[11px] font-bold text-zinc-200 py-2 px-2 outline-none focus:border-emerald-500/40 max-w-[45%]">
                {startTabOptions.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
              </select>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">{t('settings.language')}</div>
          <div className="p-4 rounded-2xl bg-[#111] border border-white/5 space-y-2.5">
            <LanguagePicker />
            <p className="text-[10px] text-zinc-600 leading-relaxed">{t('settings.languageDesc')}</p>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">{t('settings.privacy')}</div>
          <SettingsRow title={t('settings.readReceipts')} desc={t('settings.readReceiptsDesc')}>
            <SettingsToggle on={receiptsOn} onClick={() => onToggleReceipts(!receiptsOn)} disabled={settingsBusy} />
          </SettingsRow>
          <SettingsRow title={t('settings.notifications')} desc={notifPermission === 'denied' ? t('settings.notificationsBlocked') : t('settings.notificationsDesc')}>
            <SettingsToggle on={pushEnabled} onClick={() => { onToggleNotifications(); }} disabled={notifPermission === 'denied'} />
          </SettingsRow>
          {pushEnabled && onNotifyPref && (
            <div className="px-1 pt-1">
              <div className="text-[10px] font-bold text-zinc-500 mb-1.5">Notify me for</div>
              <div className="grid grid-cols-3 gap-1.5">
                {([['all', 'Everything'], ['mentions', '@alias & @groups'], ['alias', 'Only @alias']] as const).map(([val, label]) => (
                  <button key={val} onClick={() => onNotifyPref(val)}
                    className={`px-2 py-2 rounded-xl text-[10px] font-black uppercase tracking-wide transition-colors ${notifyPref === val ? 'bg-emerald-500 text-black' : 'bg-white/5 text-zinc-400 hover:bg-white/10'}`}>
                    {label}
                  </button>
                ))}
              </div>
              <div className="text-[9px] text-zinc-600 mt-1.5 leading-relaxed">Mentions are matched on the server by opaque recipient ids only — never the message text, which stays end-to-end encrypted. Messages that arrive within a few seconds of each other share one notification.</div>
            </div>
          )}
        </div>

        {isRootUser && !hubMode && (
        <div className="space-y-2">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">{dmMode ? t('settings.oneOnOneSettings') : t('settings.network')}</div>
          <div className="p-4 rounded-2xl bg-[#111] border border-white/5 space-y-3">
            <div>
              <div className="text-[11px] font-bold text-white mb-1.5">{dmMode ? t('settings.oneOnOneName') : t('settings.networkName')}</div>
              <div className="flex gap-2">
                <input value={nameDraft} maxLength={80}
                  onChange={e => setNameDraft(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') saveName(); }}
                  className="flex-1 bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors" />
                <button onClick={saveName} disabled={nameBusy || !nameDraft.trim() || nameDraft.trim() === currentUser?.treeName}
                  className="px-4 rounded-xl bg-emerald-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-40">
                  {nameBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : nameSaved ? t('settings.saved') : t('settings.save')}
                </button>
              </div>
            </div>
          </div>
          <SettingsRow title={t('settings.showNameEveryone')} desc={t('settings.showNameEveryoneDesc')}>
            <SettingsToggle on={!!networkNameVisible} onClick={toggleVis} disabled={visBusy} />
          </SettingsRow>
          {!dmMode && (
            <SettingsRow title="Monitoring" desc="Let members oversee the two levels below them. Turning this off means no one receives copies of new conversations or announcements from below them, and removes the Monitor tab. Messages already received stay with the people who received them.">
              <SettingsToggle on={monitorOn} onClick={toggleMon} disabled={monBusy} />
            </SettingsRow>
          )}
          {dmMode && (
            <SettingsRow title="Referral mode" desc="Let members share their own invite link. Everyone who joins connects 1:1 with you — never with each other — so your roster grows as a flat referral tree. You approve anyone a member brings in.">
              <SettingsToggle on={referralOn} onClick={toggleReferral} disabled={refBusy} />
            </SettingsRow>
          )}
          {!dmMode && !hubMode && (
            <SettingsRow title="Global chat" desc="Open one network-wide channel any member can read and post to — regardless of where they sit in the tree. Everyone in it can see each other’s name, photo and bio. It connects people only there: calls, direct messages and groups keep your network’s walls. Turning it off hides the Global tab for everyone.">
              <SettingsToggle on={globalChatOn} onClick={toggleGlobalChat} disabled={gcBusy} />
            </SettingsRow>
          )}
          {!hubMode && (
            <SettingsRow title="Auto-accept invitations" desc="Automatically admit anyone who joins with a valid invite link, instead of holding them in the approval queue. Off by default — only turn this on if you trust everyone who has your invite link.">
              <SettingsToggle on={autoAcceptOn} onClick={toggleAutoAccept} disabled={aaBusy} />
            </SettingsRow>
          )}
        </div>
        )}

        {accountUsername && (
          <div className="space-y-2">
            <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">Password &amp; sessions</div>
            <div className="p-4 rounded-2xl bg-[#111] border border-white/5 space-y-2.5">
              <ChangePasswordPanel username={accountUsername} />
              <OtherSessionsPanel username={accountUsername} />
            </div>
          </div>
        )}

        <div className="space-y-2">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-zinc-600 px-1">{t('settings.accountRecovery')}</div>
          <div className="p-4 rounded-2xl bg-[#111] border border-white/5">
            {/* recPhrase is checked FIRST: onSetupRecovery flips recoveryStatus to
                true immediately, and the freshly generated phrase must stay on
                screen until the user confirms they've saved it. */}
            {recPhrase ? (
              <div className="space-y-3">
                <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30">
                  <p className="text-[11px] text-red-400 font-bold leading-relaxed">
                    {t('settings.recoveryWarn')}
                  </p>
                </div>
                <div className="grid grid-cols-3 gap-1.5">
                  {recPhrase.split(' ').map((w, i) => (
                    <div key={i} className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-black border border-white/10">
                      <span className="text-[9px] text-zinc-600 font-mono">{i + 1}</span>
                      <span className="text-[11px] text-emerald-400 font-mono">{w}</span>
                    </div>
                  ))}
                </div>
                <button onClick={async () => { try { await navigator.clipboard.writeText(recPhrase); setRecCopied(true); setTimeout(() => setRecCopied(false), 2000); } catch {} }}
                  className="w-full flex items-center justify-center gap-2 text-[10px] font-black uppercase tracking-widest py-2 rounded-lg bg-white/5 text-zinc-300 hover:bg-white/10 transition-colors">
                  {recCopied ? t('common.copied') : t('settings.copyPhrase')}
                </button>
                <button onClick={() => { setRecPhrase(null); setRecOpen(false); }}
                  className="w-full py-2.5 rounded-lg bg-emerald-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors">
                  {t('settings.savedItDone')}
                </button>
              </div>
            ) : recoveryStatus === null ? (
              <div className="text-[11px] text-zinc-600">{t('settings.checkingRecovery')}</div>
            ) : recoveryStatus ? (
              <div className="flex items-center gap-2 text-emerald-400">
                <ShieldCheck className="w-4 h-4" />
                <span className="text-xs font-bold">{t('settings.recoverySet')}</span>
              </div>
            ) : recOpen && onSetupRecovery ? (
              <div className="space-y-2.5">
                <p className="text-[11px] text-zinc-400 leading-relaxed">
                  {t('settings.confirmPwToGenerate', { user: accountUsername || '' })}
                </p>
                <input type="password" placeholder={t('settings.currentPassword')} value={recPw}
                  onChange={e => setRecPw(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') doSetupRecovery(); }}
                  className="w-full bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors" />
                {recErr && <div className="text-red-500 text-[11px] font-bold">{recErr}</div>}
                <div className="flex gap-2">
                  <button onClick={doSetupRecovery} disabled={recBusy || !recPw}
                    className="flex-1 py-2.5 rounded-lg bg-emerald-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-50">
                    {recBusy ? t('settings.verifying') : t('settings.generatePhrase')}
                  </button>
                  <button onClick={() => { setRecOpen(false); setRecPw(''); setRecErr(null); }}
                    className="px-4 py-2.5 rounded-lg bg-white/5 text-zinc-400 text-[10px] font-black uppercase tracking-widest hover:bg-white/10 transition-colors">
                    {t('common.cancel')}
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-start gap-2 text-amber-400">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span className="text-[11px] leading-relaxed">{t('settings.noRecoveryOnFile')}</span>
                </div>
                {onSetupRecovery && (
                  <button onClick={() => setRecOpen(true)}
                    className="w-full py-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 text-[10px] font-black uppercase tracking-widest hover:bg-emerald-500/20 transition-colors">
                    {t('settings.generateRecovery')}
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-[10px] font-black uppercase tracking-[0.2em] text-red-500/70 px-1">{t('settings.dangerZone')}</div>
          <div className="p-4 rounded-2xl bg-red-500/5 border border-red-500/20 space-y-3">
            <button onClick={async () => { if (confirm(t('settings.panicConfirm'))) await onPanicWipe(); }}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-red-500/10 text-red-400 text-[10px] font-black uppercase tracking-widest hover:bg-red-500/20 transition-colors">
              <Trash2 className="w-4 h-4" /> {t('settings.panicWipe')}
            </button>
            {isRootUser && (
              <button onClick={async () => {
                  if (!confirm(t('settings.deleteNetworkConfirm', { count: memberCount === 1 ? t('settings.member_one', { count: memberCount }) : t('settings.member_other', { count: memberCount }) }))) return;
                  if (!confirm(t('settings.deleteNetworkConfirm2'))) return;
                  await onDeleteTree();
                }}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-red-600 text-white text-[10px] font-black uppercase tracking-widest hover:bg-red-500 transition-colors">
                <Trash2 className="w-4 h-4" /> {t('settings.deleteNetwork')}
              </button>
            )}
            {accountUsername && <DeleteAccountPanel username={accountUsername} />}
            <p className="text-[10px] text-red-500 font-bold leading-relaxed text-center">{t('settings.devNotice')}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

// Hoisted for the same stable-identity reason as SettingsRow/SettingsToggle above.
const HowToSection: React.FC<{ icon: any; title: string; children: React.ReactNode; tip?: string }> = ({ icon: Icon, title, children, tip }) => (
    <div className="bg-[#111] border border-white/5 rounded-2xl p-5">
      <div className="flex items-center gap-2.5 mb-2">
        <div className="w-8 h-8 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
          <Icon className="w-4 h-4 text-emerald-400" />
        </div>
        <h3 className="text-sm font-black uppercase tracking-widest text-white">{title}</h3>
      </div>
      <div className="text-[13px] leading-relaxed text-zinc-400 space-y-1.5">{children}</div>
      {tip && (
        <div className="mt-3 flex items-start gap-2 text-[11px] text-emerald-300/80 bg-emerald-500/5 border border-emerald-500/15 rounded-xl px-3 py-2">
          <Zap className="w-3.5 h-3.5 mt-0.5 shrink-0 text-emerald-400" />
          <span>{tip}</span>
        </div>
      )}
    </div>
  );

const HowToView: React.FC<{ dmMode: boolean; hubMode: boolean; hasTrueSight: boolean; isRootUser: boolean; canAnnounce: boolean }> = ({ dmMode, hubMode, hasTrueSight, isRootUser, canAnnounce }) => {
  const t = useT();
  return (
    <div className="flex-1 overflow-y-auto no-scrollbar p-4 md:p-8">
      <div className="max-w-2xl mx-auto space-y-4 pb-12">
        <div className="mb-2">
          <h2 className="text-xl font-bold text-white tracking-tight">{t('howto.title')}</h2>
          <p className="text-[11px] text-zinc-500 uppercase tracking-widest font-medium mt-1">
            Every message is end-to-end encrypted with the Signal protocol
          </p>
        </div>

        <HowToSection icon={Network} title="Three kinds of space">
          <p>Arbor spaces come in three flavors, chosen when the space is created:</p>
          <p className="mt-2"><strong>Network</strong> — a tree for teams, organizations, and communities. Whoever you invite sits directly below you; whoever they invite sits below them. Your position determines who you talk to, what you can see, and what you can monitor.</p>
          <p className="mt-2"><strong>Direct Only</strong> — a structured private roster. Each member talks 1:1 with the root, and members never see or reach each other. By default only the root invites people; with <strong>referral mode</strong> on, any member can invite too, and everyone they bring in connects straight to the root — a flat referral tree.</p>
          <p className="mt-2"><strong>Personal</strong> — not an organization at all: standard messaging. There is no tree and nobody "joins" anybody: your personal hub connects to other people's hubs as equal contacts. Anyone who opens your invite link sends you a contact request; accepting opens a private chat — you appear in their chats and they appear in yours. A contact can never see, reach, or invite anyone into your hub: everyone only ever adds contacts to their own.</p>
          {hubMode && <p className="mt-2 text-emerald-400/80">You're in your Personal Chats — every conversation is a private line between you and one contact.</p>}
          {dmMode && <p className="mt-2 text-emerald-400/80">You're in a Direct-Only space.</p>}
        </HowToSection>

        {!isRootUser && (
          <HowToSection icon={ArrowUpLeft} title={hubMode ? 'Chat' : (dmMode ? 'Inviter' : 'Ancestors')}
            tip="Use the Ancestors tab to reach the person who brought you in — and, in a hierarchical network, your siblings under the same inviter.">
            <p>This is your conversation looking <strong>upward</strong>: the person who invited you{dmMode ? '' : ', plus anyone else they invited (your siblings)'}. Type a message and it goes up to that group. The root has no inviter, so the root has no Ancestors tab.</p>
          </HowToSection>
        )}

        {!((dmMode || hubMode) && !isRootUser) && (
        <HowToSection icon={ArrowDownRight} title={hubMode ? 'Chats' : (dmMode ? 'My Invitees' : 'Descendants')}
          tip={dmMode ? 'Open a specific person from “My Invitees” in the sidebar to focus the conversation on just them.' : 'Open a specific person from “Direct Links” in the sidebar to focus the conversation on just them.'}>
          {hubMode
            ? <p>Your <strong>Chats</strong> tab is a scrollable list of every conversation, newest first, with unread badges. The search bar at the top searches inside <strong>all</strong> of your chats at once (on this device only), and the person-plus button copies your invite link. Tap a chat to open it; every conversation is strictly private between you and that one person.</p>
            : dmMode
            ? <p>Everyone you and your members have brought in talks <strong>1:1 with you</strong>, and never with each other. The <strong>My Invitees</strong> list in the sidebar shows them nested under whoever referred them — tap anyone to open your private conversation with just that person.</p>
            : <p>This is your conversation looking <strong>downward</strong>: the people you invited. Pick a contact under “Direct Links” to talk to one person, or post to the whole group. Replies show up here.</p>}
        </HowToSection>
        )}

        {!dmMode && !hubMode && (
          <HowToSection icon={Radio} title="Announcements"
            tip={canAnnounce
              ? 'Use the tree picker above the composer: “Everyone below me”, or tap specific people — the tapped person and everyone above them receive it; nobody below them does.'
              : 'Everyone receives announcements here. Sending them is a granted right — the network root can enable it for you from the Network Tree.'}>
            <p>Announcements deliver one message to many people at once. Everyone has this tab to <strong>receive</strong>; <strong>sending</strong> requires announcement rights — the root always has them and can grant them to anyone from the Network Tree.</p>
            <p className="mt-2">When sending, choose the reach on the tree picker (it looks just like the Network Tree): <strong>Everyone below me</strong> sends to your whole subtree, or tap specific people — the tapped node lights up together with the chain <strong>above</strong> it, and that lit path is exactly who receives. People <strong>below</strong> a tapped person do not get the announcement. You can also request acknowledgments — each recipient gets an Acknowledge button and you see who confirmed.</p>
          </HowToSection>
        )}

        {!hubMode && (
        <HowToSection icon={Waypoints} title="Network Tree"
          tip="Drag to pan, scroll or pinch to zoom, and tap a bubble to select it. From a selected node you invited, you can prune it.">
          <p>A live map of the network as you’re allowed to see it. Without True Sight you see your inviter, you, and everyone below you. {hasTrueSight ? 'With True Sight you see the whole network from its real root.' : 'With True Sight you’d see the entire network.'} Tap a node you invited to manage it.</p>
        </HowToSection>
        )}

        {!dmMode && !hubMode && (
          <HowToSection icon={Monitor} title="Monitor Hub"
            tip="The hub shows your subtree as a tree — tap someone within 2 levels of you who has invitees of their own.">
            <p>Pick a person below you and view <strong>their descendant circle</strong>: exactly the conversation between them and the people they directly invited — what they see on their own Descendants tab. Never their chat upward with you or their inviter.</p>
            <p className="mt-2"><strong>Monitoring reaches at most 2 levels below you</strong> — nobody, the founder included, can monitor deeper. Example: you invited A, A invited B, B invited C, C invited D. You can monitor A (seeing A↔B) and B (seeing B↔C), but never C or anyone deeper — C's circle is A's and B's to oversee. This isn't just hidden in the interface: messages outside your window are never even encrypted to you. Monitoring is view-only — you can’t send into someone else’s circle.</p>
          </HowToSection>
        )}

        {(isRootUser || hasTrueSight) && !hubMode && (
          <HowToSection icon={Eye} title="True Sight"
            tip="Turn on True Sight for a trusted invitee (tap their node in the Network Tree) so they can see the real network name and the full structure.">
            <p>True Sight reveals the real <strong>network name</strong> in the top-left (instead of “Grid Network”) and the entire network in the Network Tree. The root has it by default and can grant it to others. (Sending announcements is a separate grant.)</p>
          </HowToSection>
        )}

        <HowToSection icon={UserPlus} title="Inviting people"
          tip={(dmMode || hubMode) && !isRootUser
            ? (hubMode ? 'Personal Hub: only the owner has an invite QR.' : 'Direct-Only network: only the network root has an Invite QR — members cannot invite.')
            : (hubMode ? 'Your personal QR is in the sidebar — it’s how anyone reaches you. Rotate it with “New code” any time.' : 'Your Invite QR is in the sidebar. Rotate it with “New code” any time — the old code dies instantly.')}>
          <p>Show the person your <strong>{hubMode ? 'QR' : 'Invite QR'}</strong> from the sidebar (or send them the copied link{hubMode ? ' — the person-plus button in Chats copies it too' : ''}). Scanning it opens Arbor in their phone browser with your invite prefilled — from there they add it to their Home Screen (Share → Add to Home Screen on iPhone; Install App on Android){hubMode ? '' : ' and join in one flow'}.</p>
          {hubMode
            ? <p className="mt-2">Every add is a <strong>contact request</strong>: the person picks a name and it appears under “Contact Requests” in the sidebar. Not a single message flows until you accept. Accepting opens a private chat between just the two of you — they connect to <strong>your</strong> chats from <strong>their own</strong> Personal Chats, they never become part of anything, and they can’t invite anyone through you.</p>
            : <p className="mt-2">Every join is a <strong>request</strong>: the person picks an alias, and you review it under “Join Requests” in the sidebar. Nobody enters your network — or exchanges a single message — until you accept. Decline removes the request entirely.</p>}
          <p className="mt-2">The QR code stays the same until you tap <strong>New code</strong>, which instantly invalidates the old one — rotate it if it ever leaks.</p>
        </HowToSection>

        {!hubMode && (
        <HowToSection icon={Scissors} title="Pruning a branch"
          tip="Prune from the Network Tree: select a node you invited, then Prune to remove it and everyone beneath it.">
          <p>You can remove any branch below you. Pruning a node permanently deletes that node and everyone they invited. It can’t be undone.</p>
        </HowToSection>
        )}

        <HowToSection icon={Mic} title="Voice, photos & video"
          tip="Tap the microphone to record a voice note; tap the image icon to attach a photo or video. They’re encrypted like any other message.">
          <p>In the message bar, the microphone records a voice note (tap again to stop) and the image icon attaches a photo or video. A preview chip appears above the bar before you send. Tap the X on a chip to discard it.</p>
        </HowToSection>

        <HowToSection icon={Reply} title="Replying to a message"
          tip="On your phone, swipe any bubble toward the center of the screen to reply — your own messages swipe left, others swipe right.">
          <p>Tap the reply arrow on a message (or swipe it sideways on mobile, like iMessage) and a preview of that message appears above the composer. Send, and your reply carries a quoted preview of what it answers. Tap the X on the preview to cancel.</p>
        </HowToSection>

        <HowToSection icon={Timer} title="Disappearing messages"
          tip="Set the timer next to the send button (30s–1d) before sending so a message auto-deletes after it’s read.">
          <p>Pick a lifetime from the timer dropdown in the message bar. After the chosen time the message disappears for everyone. Leave it on “Off” for normal messages.</p>
        </HowToSection>

        <HowToSection icon={Eraser} title="Metadata scrubbing"
          tip="The eraser icon in the message bar strips hidden location/device metadata from photos and videos before they’re encrypted and sent. It’s on by default.">
          <p>Photos usually carry hidden EXIF data (GPS location, time, camera model); phone videos embed location in their metadata atoms. The eraser cycles through three levels. <strong>Standard</strong> (green): images are re-encoded so only pixels remain, and videos have their movie-level location/user-data boxes removed losslessly. <strong>Deep</strong> (marked MAX): the video's entire box tree is rebuilt with every metadata box removed at every level — per-track data, vendor/XMP blocks, and slack space included — and voice notes are decoded and re-synthesized as fresh audio so nothing from the original container survives. <strong>Off</strong> (struck through): media is sent exactly as-is. A note above the bar tells you what was stripped. Voice notes recorded in the app never contain location data even without scrubbing.</p>
        </HowToSection>

        <HowToSection icon={Fingerprint} title="App Lock (Face ID / biometrics)"
          tip="Turn on “Enable App Lock” in the sidebar to require Face ID / fingerprint every time Arbor opens.">
          <p>In the sidebar under <strong>Device</strong>, enable App Lock to gate the app behind your phone’s biometrics (Face ID, Touch ID, or Android fingerprint). Disabling it requires passing a biometric check first. Note: this locks the app’s screen — your message keys stay protected by your account password as always.</p>
        </HowToSection>

        <HowToSection icon={Bell} title="Notifications"
          tip="Tap “Enable Notifications” in the sidebar. On iPhone, add Arbor to your Home Screen first (Share → Add to Home Screen); on Android it works in Chrome directly.">
          <p>Push notifications arrive even when the app is closed. iPhone requires iOS 16.4+ and the app installed to the Home Screen; Android works in Chrome with or without installing. If you previously denied permission, re-enable it in your browser/OS settings and tap the button again.</p>
        </HowToSection>

        <HowToSection icon={Phone} title="Encrypted calls"
          tip="Open a chat and tap the phone icon in the top bar. From an invitee's chat it calls just them; from the group tabs it rings everyone in that circle.">
          <p>Calls are voice, end-to-end encrypted, and connect device-to-device — the server only relays sealed signaling it cannot read, so it can never listen in or tamper with the call keys. Group calls connect everyone pairwise and work best with up to about five people. A small number of very restrictive networks may fail to connect (no relay server is used — by design, your audio never touches the server).</p>
        </HowToSection>

        <HowToSection icon={Search} title="Search & read receipts">
          <p>The magnifier in the top bar searches the current conversation — entirely on your device, since the server only ever stores ciphertext. When someone sees your message, a small green double-check appears next to its time. Receipts are optional: turn “Read Receipts” off in the sidebar’s Device section and nothing is sent when you read.</p>
        </HowToSection>

        <HowToSection icon={ShieldCheck} title="Encryption & safety numbers">
          <p>Messages are sealed with the Signal protocol (X3DH + Double Ratchet), so only the intended people can read them. The first time you talk to someone, their identity is trusted and remembered. If it ever changes, you’ll see a red <strong>“identity changed — verify safety number”</strong> warning on their messages — confirm with them out-of-band before trusting it.</p>
        </HowToSection>

        <p className="text-xs text-red-500 font-bold leading-relaxed text-center pt-2 pb-6">Arbor is still in development. Please send bug reports to bugreports@arborsecure.app</p>
      </div>
    </div>
  );
};

const NetworkTreeCanvas: React.FC<{
  root: TreeData;
  isRootUser: boolean;
  dmMode: boolean;
  onPrune: (userId: string) => void;
  onToggleTrueSight: (userId: string, on: boolean) => void;
  onToggleAnnounce: (userId: string, on: boolean) => void;
  canManageGroups?: boolean;
  manageableNodeIds?: Set<string>;
  inviteesOf?: (ownerNodeId: string) => { id: string; name: string; groupIds: string[] }[];
  onCreateGroup?: (ownerNodeId: string, name: string, parentGroupId?: string) => Promise<string>;
  onRenameGroup?: (ownerNodeId: string, groupId: string, name: string) => Promise<void>;
  onDeleteGroup?: (ownerNodeId: string, groupId: string) => Promise<void>;
  onAssignToGroup?: (ownerNodeId: string, childIds: string[], groupId: string | null) => Promise<void>;
  /** Resolves to the group's full invite LINK (code + signed #fragment, V8 phase 2). */
  onGetGroupInvite?: (ownerNodeId: string, groupId: string, rotate?: boolean) => Promise<string>;
  groupsOf?: (ownerNodeId: string) => { groupId: string; name: string }[];
  linksOf?: (ownerNodeId: string) => { id: string; groups?: string[]; name: string; archived: boolean; crossLevel?: boolean }[];
  linkEdges?: { a: string; b: string; name: string; lid: string }[];
  crossLevelEdges?: { a: string; b: string; ao: string; bo: string; name: string; lid: string }[];
  onLinkGroups?: (ownerNodeId: string, groupIds: string[], name?: string) => Promise<string | null>;
  rootNodeId?: string; // the tree root's node id (set only for the root user) — enables cross-level links
  rootCrossLinks?: { id: string; refs: { o: string; g: string }[]; name: string; archived: boolean }[];
  onCreateCrossLink?: (rootNodeId: string, refs: { o: string; g: string }[], name: string) => Promise<string | null>;
  onUpdateCrossLink?: (rootNodeId: string, linkId: string, refs: { o: string; g: string }[], name: string) => Promise<void>;
  onUpdateLink?: (ownerNodeId: string, linkId: string, groupIds: string[]) => Promise<void>;
  onArchiveLink?: (ownerNodeId: string, linkId: string, archived: boolean) => Promise<void>;
  onDeleteLink?: (ownerNodeId: string, linkId: string) => Promise<void>;
  onMoveNode?: (nodeId: string, targetOwnerId: string, targetGroupId: string | null) => Promise<void>;
  // Set the EXACT set of the inviter's groups a member belongs to (multi-group).
  onEditMemberGroups?: (ownerNodeId: string, childPublicId: string, groupIds: string[]) => Promise<void>;
  // Replace the cross-level VISITOR lists on a group owner's node (gid -> public ids).
  onSetGroupVisitors?: (ownerNodeId: string, visitors: Record<string, string[]>) => Promise<void>;
  hasTrueSight?: boolean; // sees the whole tree → may grab any group's join link
  // Open the profile info view for a tapped member (photo, name history, bio, add-to-hub).
  onOpenProfile?: (info: { pid: string; name?: string; color?: string; avatarAt?: number; isMe?: boolean }) => void;
  viewerNodeId?: string; // current node's public id, so member avatars can lazy-load
}> = ({ root, isRootUser, hasTrueSight, dmMode, onPrune, onToggleTrueSight, onToggleAnnounce, canManageGroups, manageableNodeIds, inviteesOf, onCreateGroup, onRenameGroup, onDeleteGroup, onAssignToGroup, onGetGroupInvite, groupsOf, linksOf, linkEdges, crossLevelEdges, onLinkGroups, rootNodeId, rootCrossLinks, onCreateCrossLink, onUpdateCrossLink, onUpdateLink, onArchiveLink, onDeleteLink, onMoveNode, onEditMemberGroups, onSetGroupVisitors, onOpenProfile, viewerNodeId }) => {
  const canManageNode = (id?: string) => !!id && !!manageableNodeIds && manageableNodeIds.has(id);
  // Groups build mode: shows a green ⊕ on YOUR node to add an empty group
  // ("branch"), and group labels are collapsible. Populate a group via its link.
  const [groupMode, setGroupMode] = useState(false);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  // Every group node id in the whole tree (for the expand/collapse-ALL toggle).
  const allGroupIds = useMemo(() => {
    const s = new Set<string>();
    const walk = (n: TreeData) => { if ((n.user as any).isGroup) s.add(n.user.id); n.children.forEach(walk); };
    walk(root);
    return [...s];
  }, [root]);
  const allExpanded = allGroupIds.length > 0 && allGroupIds.every(id => !collapsed.has(id));
  const toggleAllGroups = () => setCollapsed(() => allExpanded ? new Set(allGroupIds) : new Set());
  // Groups start COLLAPSED so the tree reads as PEOPLE first, not a wall of group
  // boxes. Each group is auto-collapsed once, the first time it appears; after
  // that the user's own expand/collapse wins (a group they opened stays open —
  // we never re-collapse one we've already seeded). Ids are stable (grp:owner:gid).
  const seededGroups = useRef<Set<string>>(new Set());
  // useLayoutEffect (not useEffect): apply the auto-collapse BEFORE paint, so the
  // very first layout the user sees — and the auto-centering below — is the
  // collapsed one, not a wide flash that then re-centers off to one side.
  useLayoutEffect(() => {
    const fresh: string[] = [];
    const walk = (n: TreeData) => { if ((n.user as any).isGroup && !seededGroups.current.has(n.user.id)) fresh.push(n.user.id); n.children.forEach(walk); };
    walk(root);
    if (fresh.length) { fresh.forEach(id => seededGroups.current.add(id)); setCollapsed(prev => { const nx = new Set(prev); fresh.forEach(id => nx.add(id)); return nx; }); }
  }, [root]);
  // Prune collapsed groups' children before layout so collapsing actually hides them.
  const displayRoot = useMemo(() => {
    const prune = (n: TreeData): TreeData => {
      const isGroup = !!(n.user as any).isGroup;
      if (isGroup && collapsed.has(n.user.id)) return { user: n.user, children: [] };
      return { user: n.user, children: n.children.map(prune) };
    };
    return prune(root);
  }, [root, collapsed]);
  const layout = useMemo(() => layoutTree(displayRoot), [displayRoot]);
  // Map EVERY node in the full tree to its nearest VISIBLE ancestor's laid-out
  // position. Cross-level link endpoints are often deep/collapsed; this lets a
  // wire still terminate at whatever ancestor IS on screen (a collapsed group
  // pill, an owner, …) instead of vanishing. Bottoms out at the always-visible root.
  const nearestVisibleById = useMemo(() => {
    const layoutById = new Map(layout.nodes.map(n => [n.user.id, n]));
    const map = new Map<string, typeof layout.nodes[number] | null>();
    const walk = (n: TreeData, ancVisible: any) => {
      const self = layoutById.get(n.user.id) || null;
      const eff = self || ancVisible;
      map.set(n.user.id, eff);
      for (const c of n.children) walk(c, eff);
    };
    walk(root, null);
    return map;
  }, [root, layout]);
  // Which group nodes take part in a cross-group link (for an on-node badge, so a
  // linked group is obvious even without following the connector line).
  const linkedNodeIds = useMemo(() => { const s = new Set<string>(); for (const e of (linkEdges || [])) { s.add(e.a); s.add(e.b); } return s; }, [linkEdges]);
  // Cross-level links as color-matched SYMBOLS on the nodes (no wires). For each
  // link, its color is stamped as a small link icon next to every group it
  // touches; the same color on two nodes means they're linked. Endpoints deep in
  // a collapsed group resolve to their nearest visible ancestor so the symbol
  // still appears somewhere on screen. Keyed by visible node id.
  const crossLevelBadges = useMemo(() => {
    // Color is stable PER LINK (lid), not per node-pair: a link joining 3+ groups
    // fans out into several edges (one per pair) but is still ONE link — one color,
    // one badge per node. So assign each lid a color once, and dedup badges by lid.
    const colorByLid = new Map<string, string>();
    for (const lk of (crossLevelEdges || [])) if (!colorByLid.has(lk.lid)) colorByLid.set(lk.lid, xlinkColor(colorByLid.size));
    const m = new Map<string, { color: string; name: string; lid: string }[]>();
    (crossLevelEdges || []).forEach((lk) => {
      const a = nearestVisibleById.get(lk.a) || nearestVisibleById.get(lk.ao);
      const b = nearestVisibleById.get(lk.b) || nearestVisibleById.get(lk.bo);
      const color = colorByLid.get(lk.lid)!;
      for (const n of [a, b]) {
        if (!n) continue;
        const arr = m.get(n.user.id) || [];
        if (!arr.some(x => x.lid === lk.lid)) arr.push({ color, name: lk.name, lid: lk.lid });
        m.set(n.user.id, arr);
      }
    });
    return m;
  }, [crossLevelEdges, nearestVisibleById]);
  const [addingGroup, setAddingGroup] = useState(false);
  const [addParent, setAddParent] = useState<string | null>(null); // parent groupId when nesting
  const [addOwner, setAddOwner] = useState<string | null>(null);   // node the group lives on
  const [addName, setAddName] = useState('');
  const [addBusy, setAddBusy] = useState(false);
  const [qrNode, setQrNode] = useState<User | null>(null);
  const [qrData, setQrData] = useState<{ code: string; dataUrl: string; link: string } | null>(null);
  const [qrBusy, setQrBusy] = useState(false);
  const [qrTip, setQrTip] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<User | null>(null);
  const [addMembersTo, setAddMembersTo] = useState<User | null>(null); // group node to add members to
  const [memberSel, setMemberSel] = useState<Set<string>>(new Set());
  const [memberBusy, setMemberBusy] = useState(false);
  // Unified link manager for a selected group: pick which links to edit (or a new
  // one), check/uncheck groups, save/create, and archive → restore/delete.
  const [editLink, setEditLink] = useState<User | null>(null); // group node whose links we're editing
  const [editLid, setEditLid] = useState<string | 'new'>('new'); // selected existing link, or a new one
  const [editSel, setEditSel] = useState<Set<string>>(new Set()); // OTHER groups checked (the anchor group is implicit)
  const [linkBusy, setLinkBusy] = useState(false);
  // Cross-level linking (ROOT only): link groups from ANYWHERE in the tree. xSel
  // holds "ownerPublicId|groupId" keys; the anchor group is implicit.
  const [xMode, setXMode] = useState(false);
  const [xSel, setXSel] = useState<Set<string>>(new Set());
  const [movingNode, setMovingNode] = useState<User | null>(null); // member being moved to another group
  // Per-member group membership editor (multi-select of the member's inviter's
  // groups). A member can belong to several groups at once.
  const [editGroupsNode, setEditGroupsNode] = useState<User | null>(null);
  const [egSel, setEgSel] = useState<Set<string>>(new Set());          // same-inviter group ids
  const [egVisit, setEgVisit] = useState<Set<string>>(new Set());      // "ownerId|gid" cross-level VISITOR memberships
  const [egBusy, setEgBusy] = useState(false);
  const openEditGroups = (node: User) => {
    const cur = (inviteesOf && node.invitedBy ? (inviteesOf(node.invitedBy).find(x => x.id === node.id)?.groupIds) : []) || [];
    setEgSel(new Set(cur));
    // Seed cross-level visitor memberships from every owner's groupVisitors.
    const v = new Set<string>();
    for (const [key, ids] of groupVisitorMap) if (ids.includes(node.id)) v.add(key);
    setEgVisit(v);
    setEditGroupsNode(node);
  };
  const submitEditGroups = async () => {
    if (!onEditMemberGroups || !editGroupsNode || !editGroupsNode.invitedBy || egBusy) return;
    // Work out cross-level VISITOR changes first (recompute each changed group's FULL
    // visitor list, others intact) so we can warn BEFORE anything commits.
    let perOwner = new Map<string, Record<string, string[]>>();
    let addingVisitor = false;
    for (const g of allGroupNodes) {
      if (g.ownerId === editGroupsNode.invitedBy) continue; // same-inviter handled by egSel
      const key = `${g.ownerId}|${g.groupId}`;
      const want = egVisit.has(key);
      const cur = (groupVisitorMap.get(key) || []).includes(editGroupsNode.id);
      if (want === cur) continue;
      if (want) addingVisitor = true;
      const base = (groupVisitorMap.get(key) || []).filter(id => id !== editGroupsNode.id);
      const next = want ? [...base, editGroupsNode.id] : base;
      if (!perOwner.has(g.ownerId)) perOwner.set(g.ownerId, {});
      perOwner.get(g.ownerId)![g.groupId] = next;
    }
    // Adding someone as a visitor across levels is cross-compartment access — warn
    // (its own counter). Declining keeps the same-level group edits but skips visitors.
    if (addingVisitor && !dangerConfirm('arbor_visitor_warned',
      `Adding ${editGroupsNode.name} as a visitor to a group on another branch gives them full access to that group's chat, across compartments.`)) {
      perOwner = new Map();
    }
    setEgBusy(true);
    try {
      await onEditMemberGroups(editGroupsNode.invitedBy, editGroupsNode.id, [...egSel]);
      for (const [ownerId, visitors] of perOwner) {
        if (onSetGroupVisitors) await onSetGroupVisitors(ownerId, visitors);
      }
      setEditGroupsNode(null);
    }
    catch (e: any) { alert(e?.message || 'Could not update groups.'); }
    finally { setEgBusy(false); }
  };
  const [moveBusy, setMoveBusy] = useState(false);
  // Every group in the network (owner + group id + owner name), for the Move picker.
  const allGroupNodes = useMemo(() => {
    const nameById = new Map<string, string>();
    const names = (n: TreeData) => { if (!(n.user as any).isGroup) nameById.set(n.user.id, n.user.name); n.children.forEach(names); };
    names(root);
    const out: { name: string; ownerId: string; groupId: string; ownerName: string }[] = [];
    const walk = (n: TreeData) => { const u: any = n.user; if (u.isGroup) out.push({ name: u.name, ownerId: u.ownerId, groupId: u.groupId, ownerName: nameById.get(u.ownerId) || '' }); n.children.forEach(walk); };
    walk(root);
    return out;
  }, [root]);
  // Current cross-level VISITOR lists across the tree: "ownerId|gid" -> [member id,...].
  // Read from each owner node's exposed groupVisitors (owner/oversight only see it).
  const groupVisitorMap = useMemo(() => {
    const m = new Map<string, string[]>();
    const walk = (n: TreeData) => { const u: any = n.user; if (!u.isGroup && u.groupVisitors) for (const [gid, ids] of Object.entries(u.groupVisitors as Record<string, string[]>)) m.set(`${u.id}|${gid}`, ids as string[]); n.children.forEach(walk); };
    walk(root);
    return m;
  }, [root]);
  // Node ids inside a given member's own subtree (can't move a node into itself).
  const subtreeIdsOf = (nodeId: string): Set<string> => {
    const ids = new Set<string>();
    const find = (n: TreeData): TreeData | null => { if (n.user.id === nodeId) return n; for (const c of n.children) { const r = find(c); if (r) return r; } return null; };
    const start = find(root);
    if (start) { const collect = (n: TreeData) => { if (!(n.user as any).isGroup) ids.add(n.user.id); n.children.forEach(collect); }; collect(start); }
    return ids;
  };
  const submitMove = async (ownerId: string, groupId: string | null) => {
    if (!onMoveNode || !movingNode || moveBusy) return;
    // Moving to ANOTHER branch (a different owner) re-parents the member + subtree
    // across compartments — same danger class as cross-level links, its own counter.
    if (ownerId !== movingNode.invitedBy && !dangerConfirm('arbor_movebranch_warned',
      `Moving ${movingNode.name} to another branch re-parents them AND everyone they invited — it changes who oversees them and which compartment they live in.`)) return;
    setMoveBusy(true);
    try { await onMoveNode(movingNode.id, ownerId, groupId); setMovingNode(null); }
    catch (e: any) { alert(e?.message || 'Could not move this member.'); }
    finally { setMoveBusy(false); }
  };
  // Open the link manager on a group: default to its first existing link, else "new".
  const openEditLinks = (node: User) => {
    const owner = (node as any).ownerId; const myG = (node as any).groupId;
    const mine = (linksOf ? linksOf(owner) : []).filter(l => !l.crossLevel && (l.groups || []).includes(myG));
    const first = mine.find(l => !l.archived) || mine[0];
    setEditLink(node); setXMode(false); setXSel(new Set());
    if (first) { setEditLid(first.id); setEditSel(new Set((first.groups || []).filter(g => g !== myG))); }
    else { setEditLid('new'); setEditSel(new Set()); }
  };
  // Cross-level link create (ROOT): warn up to 3 times, then let the user opt out.
  const submitCrossLink = async () => {
    if (!editLink || !rootNodeId || linkBusy || xSel.size === 0) return;
    // Only an existing CROSS-LEVEL link may be edited here — a same-level link
    // selected before switching modes must never be overwritten (it would lose
    // its chat to the new link).
    const editing = editLid !== 'new' && isCrossLid(editLid);
    const KEY = 'arbor_xlink_warned';
    let warned = 0; try { warned = parseInt(localStorage.getItem(KEY) || '0', 10) || 0; } catch {}
    if (!editing && warned < 3) { // only warn when CREATING a new cross-level link
      const ok = window.confirm('Linking groups across different levels can be extremely dangerous. Are you sure whatever you’re doing is worth it?\n\nThis message will display for the next three occurrences, where you can then choose to opt out.');
      if (!ok) return;
      try { localStorage.setItem(KEY, String(warned + 1)); } catch {}
      if (warned + 1 >= 3) {
        // Third time: offer the opt-out.
        const optOut = window.confirm('That was the third warning. Turn OFF this warning for future cross-level links?\n\nOK = don’t warn me again.   Cancel = keep warning me.');
        try { localStorage.setItem(KEY, optOut ? '99' : '3'); } catch {}
      }
    }
    setLinkBusy(true);
    const anchor = { o: (editLink as any).ownerId as string, g: (editLink as any).groupId as string };
    const refs = [anchor, ...[...xSel].map(k => { const [o, g] = k.split('|'); return { o, g }; })];
    // Dedup + require 2+.
    const seen = new Set<string>(); const uniq = refs.filter(r => { const k = r.o + '|' + r.g; if (seen.has(k)) return false; seen.add(k); return true; });
    if (uniq.length < 2) { setLinkBusy(false); return; }
    const nameFor = (o: string, g: string) => (allGroupNodes.find(x => x.ownerId === o && x.groupId === g)?.name) || g;
    const name = uniq.map(r => nameFor(r.o, r.g)).join(' × ');
    try {
      if (editing && onUpdateCrossLink) await onUpdateCrossLink(rootNodeId, editLid, uniq, name);
      else if (onCreateCrossLink) await onCreateCrossLink(rootNodeId, uniq, name);
      setEditLink(null); setXSel(new Set()); setXMode(false);
    }
    catch (e: any) { alert(e?.message || 'Could not save the cross-level link.'); }
    finally { setLinkBusy(false); }
  };
  // Switch which link (or "new") is being edited, loading its group set. A
  // cross-level link opens in "Across levels" mode with its refs pre-checked.
  const selectEditLink = (lid: string | 'new') => {
    if (!editLink) return;
    const owner = (editLink as any).ownerId; const myG = (editLink as any).groupId;
    if (lid === 'new') { setEditLid('new'); setEditSel(new Set()); setXMode(false); setXSel(new Set()); return; }
    const cl = (rootCrossLinks || []).find(x => x.id === lid);
    if (cl) {
      setEditLid(lid); setXMode(true);
      setXSel(new Set(cl.refs.filter(r => !(r.o === owner && r.g === myG)).map(r => `${r.o}|${r.g}`)));
      return;
    }
    const l = (linksOf ? linksOf(owner) : []).find(x => x.id === lid);
    setEditLid(lid); setXMode(false); setEditSel(new Set((l?.groups || []).filter(g => g !== myG)));
  };
  // Switching Same level / Across levels drops a selected link of the other kind,
  // so a save can only ever create or edit a link of the mode on screen.
  const isCrossLid = (lid: string) => (rootCrossLinks || []).some(l => l.id === lid);
  const switchLinkMode = (cross: boolean) => {
    setXMode(cross);
    if (editLid !== 'new' && isCrossLid(editLid) !== cross) { setEditLid('new'); setEditSel(new Set()); setXSel(new Set()); }
  };
  // Save: create a new link, or replace the selected link's group set.
  const saveEditLink = async () => {
    if (!editLink || linkBusy) return;
    const owner = (editLink as any).ownerId; const myG = (editLink as any).groupId;
    const groupIds = [myG, ...editSel];
    if (groupIds.length < 2) { alert('Pick at least one other group to share a chat with.'); return; }
    // Only an existing SAME-LEVEL link of this owner may be edited here.
    const editing = editLid !== 'new' && (linksOf ? linksOf(owner) : []).some(l => l.id === editLid && !l.crossLevel);
    setLinkBusy(true);
    try {
      if (!editing) await onLinkGroups?.(owner, groupIds);
      else await onUpdateLink?.(owner, editLid, groupIds);
      setEditLink(null);
    } catch (e: any) { alert(e?.message || 'Could not save the link.'); }
    finally { setLinkBusy(false); }
  };
  // Cross-level links live on the ROOT's node; same-level ones on the anchor's owner.
  const linkOwnerId = (lid: string) => ((rootCrossLinks || []).some(l => l.id === lid) ? (rootNodeId || (editLink as any)?.ownerId) : (editLink as any)?.ownerId);
  const archiveEditLink = async (lid: string, archived: boolean) => {
    if (!editLink || linkBusy) return;
    setLinkBusy(true);
    try { await onArchiveLink?.(linkOwnerId(lid), lid, archived); }
    catch (e: any) { alert(e?.message || 'Failed.'); }
    finally { setLinkBusy(false); }
  };
  const deleteEditLink = async (lid: string, name: string) => {
    if (!editLink || linkBusy) return;
    if (!window.confirm(`Permanently delete the “${name}” chat? Its message history is erased and cannot be recovered.`)) return;
    setLinkBusy(true);
    try { await onDeleteLink?.(linkOwnerId(lid), lid); setEditLid('new'); setEditSel(new Set()); setXMode(false); setXSel(new Set()); }
    catch (e: any) { alert(e?.message || 'Failed.'); }
    finally { setLinkBusy(false); }
  };
  const submitMembers = async () => {
    if (!onAssignToGroup || !addMembersTo || memberBusy) return;
    setMemberBusy(true);
    try { await onAssignToGroup((addMembersTo as any).ownerId, [...memberSel], (addMembersTo as any).groupId); setAddMembersTo(null); setMemberSel(new Set()); }
    catch (e: any) { alert(e?.message || 'Could not add members.'); }
    finally { setMemberBusy(false); }
  };
  const submitAdd = async () => {
    if (!onCreateGroup || !addName.trim() || addBusy || !addOwner) return;
    setAddBusy(true);
    try { await onCreateGroup(addOwner, addName.trim(), addParent || undefined); setAddingGroup(false); setAddName(''); setAddParent(null); setAddOwner(null); }
    catch (e: any) { alert(e?.message || 'Could not create group.'); }
    finally { setAddBusy(false); }
  };
  const openQr = async (node: User, rotate = false) => {
    const owner = (node as any).ownerId as string; const gid = (node as any).groupId as string;
    if (!onGetGroupInvite || !owner || !gid) return;
    setQrNode(node); setQrBusy(true); if (!rotate) setQrData(null);
    try {
      const link = await onGetGroupInvite(owner, gid, rotate);
      const code = new URL(link).searchParams.get('invite') || '';
      const dataUrl = await QRCode.toDataURL(link, { width: 480, margin: 2, color: { dark: '#10b981', light: '#00000000' } });
      setQrData({ code, dataUrl, link });
    } catch (e: any) { alert(e?.message || 'Could not load the group link.'); setQrNode(null); }
    finally { setQrBusy(false); }
  };
  const containerRef = useRef<HTMLDivElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(0.85);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const drag = useRef<{ startX: number; startY: number; panX: number; panY: number } | null>(null);
  const pointers = useRef<Map<number, { x: number; y: number }>>(new Map());
  const pinch = useRef<{ dist: number; zoom: number; panX: number; panY: number; aKey: number; bKey: number; aStart: { x: number; y: number }; bStart: { x: number; y: number } } | null>(null);

  const recenter = (z = 0.85) => {
    const cw = containerRef.current?.clientWidth || 800;
    setZoom(z);
    setPan({ x: (cw - layout.width * z) / 2, y: 28 });
  };
  // Auto-center the tree ONLY until the user first interacts (pan, zoom, or toggle
  // a group). This lets the initial layout settle — including the auto-collapse —
  // and land centered, then locks so nothing yanks the view afterwards.
  const userMoved = useRef(false);
  useLayoutEffect(() => {
    if (userMoved.current || !layout.width) return;
    recenter(0.85); // eslint-disable-next-line
  }, [layout.width, layout.height]);
  // Toggling a group re-lays out the tree; keep the TOGGLED node pinned to the
  // same spot on screen so expanding/collapsing reveals/hides its children in
  // place instead of sliding the whole view. We record the node's screen position
  // before the layout changes and re-derive the pan to match it afterwards.
  const pendingAnchor = useRef<{ id: string; sx: number; sy: number } | null>(null);
  useLayoutEffect(() => {
    const a = pendingAnchor.current; if (!a) return;
    pendingAnchor.current = null;
    const n = layout.nodes.find(x => x.user.id === a.id);
    if (n) setPan({ x: a.sx - n.cx * zoom, y: a.sy - n.cy * zoom }); // eslint-disable-next-line
  }, [layout]);
  const toggleGroup = (id: string) => {
    userMoved.current = true;
    const n = layout.nodes.find(x => x.user.id === id);
    if (n) pendingAnchor.current = { id, sx: n.cx * zoom + pan.x, sy: n.cy * zoom + pan.y };
    setCollapsed(prev => { const nx = new Set(prev); nx.has(id) ? nx.delete(id) : nx.add(id); return nx; });
  };

  const clampZoom = (z: number) => Math.min(2.5, Math.max(0.25, z));

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    userMoved.current = true;
    const rect = containerRef.current!.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    const nz = clampZoom(zoom * (e.deltaY < 0 ? 1.12 : 0.89));
    const wx = (px - pan.x) / zoom, wy = (py - pan.y) / zoom;
    setPan({ x: px - wx * nz, y: py - wy * nz });
    setZoom(nz);
  };

  const onPointerDown = (e: React.PointerEvent) => {
    userMoved.current = true;
    (e.target as Element).setPointerCapture?.(e.pointerId);
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pointers.current.size === 2) {
      const [ka, kb] = [...pointers.current.keys()];
      const a = pointers.current.get(ka)!, b = pointers.current.get(kb)!;
      pinch.current = { dist: Math.hypot(a.x - b.x, a.y - b.y), zoom, panX: pan.x, panY: pan.y,
        aKey: ka, bKey: kb, aStart: { ...a }, bStart: { ...b } };
      drag.current = null;
    } else {
      drag.current = { startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y };
    }
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!pointers.current.has(e.pointerId)) return;
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch.current && pointers.current.size === 2) {
      const pc = pinch.current;
      const a = pointers.current.get(pc.aKey)!, b = pointers.current.get(pc.bKey)!;
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      const nz = clampZoom(pc.zoom * (dist / pc.dist));
      // Weighted midpoint: both fingers contribute, but the one moving LESS gets
      // heavier weight so the anchor leans toward the stiller finger without
      // hard-switching (which caused jitter when both fingers moved).
      const aMoved = Math.hypot(a.x - pc.aStart.x, a.y - pc.aStart.y);
      const bMoved = Math.hypot(b.x - pc.bStart.x, b.y - pc.bStart.y);
      const wa = 1 / (aMoved + 8), wb = 1 / (bMoved + 8); // +8 keeps it stable near zero
      const cx = (a.x * wa + b.x * wb) / (wa + wb);
      const cy = (a.y * wa + b.y * wb) / (wa + wb);
      const rect = containerRef.current!.getBoundingClientRect();
      const ax = cx - rect.left, ay = cy - rect.top;
      const wx = (ax - pc.panX) / pc.zoom;
      const wy = (ay - pc.panY) / pc.zoom;
      setPan({ x: ax - wx * nz, y: ay - wy * nz });
      setZoom(nz);
    } else if (drag.current) {
      setPan({ x: drag.current.panX + (e.clientX - drag.current.startX), y: drag.current.panY + (e.clientY - drag.current.startY) });
    }
  };
  const onPointerUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId);
    if (pointers.current.size < 2) pinch.current = null;
    if (pointers.current.size === 0) drag.current = null;
  };

  const selected = selectedId ? layout.nodes.find(n => n.user.id === selectedId)?.user : null;
  const canManage = (u?: User | null) => !!u && !!u.isDescendant;
  const canTrueSight = isRootUser && !dmMode;
  // Optimistic True-Sight state per node. Previously the whole map was cleared on
  // ANY tree refresh — an unrelated refresh landing between the tap and the server
  // truth made the button visibly flip back and forth. Now each override is kept
  // until the server CONFIRMS that exact value (or 15s passes as a failure guard).
  const [tsOverride, setTsOverride] = useState<Map<string, { val: boolean; at: number }>>(new Map());
  const [annOverride, setAnnOverride] = useState<Map<string, { val: boolean; at: number }>>(new Map());
  useEffect(() => {
    setTsOverride(prev => {
      if (prev.size === 0) return prev;
      const now = Date.now();
      const byId = new Map<string, User>();
      const walk = (n: TreeData) => { byId.set(n.user.id, n.user); n.children.forEach(walk); };
      if (root) walk(root);
      let changed = false;
      const next = new Map(prev);
      for (const [id, o] of prev) {
        const u = byId.get(id);
        const confirmed = u && !!u.permissions?.viewTrueLevel === o.val;
        if (confirmed || now - o.at > 15000) { next.delete(id); changed = true; }
      }
      return changed ? next : prev;
    });
  }, [root]);

  return (
    <div className="flex-1 relative overflow-hidden bg-[#0a0a0a]" style={{ touchAction: 'none' }}>
      <div
        ref={containerRef}
        className="absolute inset-0 cursor-grab active:cursor-grabbing"
        style={{ touchAction: 'none' }}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <div className="absolute top-0 left-0 origin-top-left" style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, width: layout.width, height: layout.height }}>
          <svg width={layout.width} height={layout.height} className="absolute top-0 left-0 pointer-events-none">
            <defs>
              <linearGradient id="edgeGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="rgba(16,185,129,0.55)" />
                <stop offset="100%" stopColor="rgba(16,185,129,0.14)" />
              </linearGradient>
              <linearGradient id="edgeGradHot" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="rgba(52,211,153,0.95)" />
                <stop offset="100%" stopColor="rgba(16,185,129,0.45)" />
              </linearGradient>
              <filter id="edgeGlow" x="-40%" y="-40%" width="180%" height="180%">
                <feGaussianBlur stdDeviation="2.4" result="b" />
                <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
              {/* Amber gradient for cross-group LINK arcs (distinct from green tree edges). */}
              <linearGradient id="linkGrad" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="rgba(245,158,11,0.9)" />
                <stop offset="50%" stopColor="rgba(251,191,36,0.95)" />
                <stop offset="100%" stopColor="rgba(245,158,11,0.9)" />
              </linearGradient>
            </defs>
            {layout.edges.map((e, i) => {
              const midY = (e.y1 + e.y2) / 2;
              // Smooth vertical S-curve between parent and child to read as a cascade.
              const d = `M ${e.x1} ${e.y1 + NODE_H / 2} C ${e.x1} ${midY}, ${e.x2} ${midY}, ${e.x2} ${e.y2 - NODE_H / 2}`;
              const hot = selectedId !== null && (e.parentId === selectedId || e.childId === selectedId);
              return (
                <g key={i}>
                  {/* soft under-glow */}
                  <path d={d} fill="none" stroke={hot ? 'rgba(52,211,153,0.35)' : 'rgba(16,185,129,0.10)'} strokeWidth={hot ? 7 : 6} strokeLinecap="round" filter="url(#edgeGlow)" />
                  {/* main link */}
                  <path d={d} fill="none" stroke={hot ? 'url(#edgeGradHot)' : 'url(#edgeGrad)'} strokeWidth={hot ? 3 : 2.25} strokeLinecap="round" />
                  {/* data-flow pulse riding the link */}
                  <path d={d} fill="none" stroke={hot ? 'rgba(167,243,208,0.9)' : 'rgba(110,231,183,0.5)'} strokeWidth={1.4} strokeLinecap="round" strokeDasharray="3 14" className="tree-flow" />
                  {/* junction dots anchoring the line to each node */}
                  <circle cx={e.x1} cy={e.y1 + NODE_H / 2} r={3} fill="#0a0a0a" stroke={hot ? '#34d399' : 'rgba(16,185,129,0.7)'} strokeWidth={1.5} />
                  <circle cx={e.x2} cy={e.y2 - NODE_H / 2} r={3} fill="#0a0a0a" stroke={hot ? '#34d399' : 'rgba(16,185,129,0.7)'} strokeWidth={1.5} />
                </g>
              );
            })}
            {/* Cross-group LINK connectors: a SUBTLE amber curve that dips into the
                gutter BELOW the two linked group nodes, so it never crosses through
                a node box or its label (the node divs render on top of this SVG,
                and the curve stays under the node row). No chip/label rides the
                tree — the link name lives on the node badge + the sidebar tabs. */}
            {(linkEdges || []).map((lk, i) => {
              const a = layout.nodes.find(n => n.user.id === lk.a);
              const b = layout.nodes.find(n => n.user.id === lk.b);
              if (!a || !b) return null;
              // Anchor just under each node's bottom edge. For siblings roughly
              // side-by-side, sag downward into the gutter between rows. For a
              // near-VERTICAL pair (small horizontal gap) that would otherwise read
              // as a straight line — blending with the tree's own parent→child
              // edges — bow the path gently to one side so it's clearly a link.
              const y1 = a.cy + NODE_H / 2, y2 = b.cy + NODE_H / 2;
              const dx = b.cx - a.cx;
              const vertical = Math.abs(dx) < 36;
              let d: string;
              if (vertical) {
                const dy = y2 - y1;
                const lat = 26; // gentle sideways bow
                d = `M ${a.cx} ${y1} C ${a.cx + lat} ${y1 + dy * 0.33}, ${b.cx + lat} ${y2 - dy * 0.33}, ${b.cx} ${y2}`;
              } else {
                const my = Math.max(y1, y2) + Math.min(46, 18 + Math.abs(dx) * 0.08);
                d = `M ${a.cx} ${y1} C ${a.cx} ${my}, ${b.cx} ${my}, ${b.cx} ${y2}`;
              }
              return (
                <g key={`lk${i}`} opacity={0.9}>
                  <path d={d} fill="none" stroke="rgba(245,158,11,0.5)" strokeWidth={1.75} strokeLinecap="round" strokeDasharray="4 5" />
                  <circle cx={a.cx} cy={y1} r={2.5} fill="#f59e0b" />
                  <circle cx={b.cx} cy={y2} r={2.5} fill="#f59e0b" />
                </g>
              );
            })}
            {/* Cross-level links are shown as color-matched symbols on the nodes
                themselves (see crossLevelBadges) — no connector wires. */}
          </svg>
          {layout.nodes.map(n => {
            const u = n.user;
            const isSel = u.id === selectedId;
            const trueSight = !!u.permissions?.viewTrueLevel;
            const isGroup = !!(u as any).isGroup;
            // A "reference" placement: a member shown inside an ADDITIONAL group they
            // belong to (their full node + subtree live in their home group). Drawn
            // as a ghost that jumps to the real node when tapped.
            const isRef = !isGroup && !!(u as any).__ref;
            const isColl = collapsed.has(u.id);
            const memberCount = (u as any).__count ?? 0;
            // A group with nothing under it has nothing to expand — always draw it as a
            // solid, tappable pill so it can still be selected (e.g. to edit its links).
            const isEmptyGroup = isGroup && memberCount === 0 && !((u as any).__visitors);
            const canAddHere = groupMode && !!onCreateGroup && ((!isGroup && canManageNode(u.id)) || (isGroup && canManageNode((u as any).ownerId)));
            const isLinked = isGroup && linkedNodeIds.has(u.id);
            return (
              <div key={u.id} className="absolute flex flex-col items-center" style={{ left: n.cx - NODE_W / 2, top: n.cy - NODE_H / 2, width: NODE_W }}>
                {isLinked && (
                  <span title="This group is linked to another (shared chat)" className="absolute -top-2 -right-1 z-10 w-5 h-5 rounded-full bg-[#1c1608] border border-amber-500/60 flex items-center justify-center shadow-[0_0_8px_rgba(245,158,11,0.35)]">
                    <Link2 className="w-3 h-3 text-amber-400" />
                  </span>
                )}
                {/* Cross-level link symbols — bigger, OUTSIDE the node (a vertical
                    stack just off the left edge). Same color on two nodes = linked. */}
                {crossLevelBadges.get(u.id)?.length ? (
                  <div className="absolute top-1/2 -left-2.5 -translate-y-1/2 -translate-x-full flex flex-col gap-1.5 z-20 pointer-events-none">
                    {crossLevelBadges.get(u.id)!.map((b, ci) => (
                      <span key={ci} title={`Cross-level link: ${b.name}`} className="w-7 h-7 rounded-full bg-[#0c0c0f] flex items-center justify-center pointer-events-auto" style={{ border: `1.5px solid ${b.color}`, boxShadow: `0 0 9px ${b.color}66` }}>
                        <Link2 className="w-4 h-4" style={{ color: b.color }} />
                      </span>
                    ))}
                  </div>
                ) : null}
                <button
                  onPointerDown={(ev) => ev.stopPropagation()}
                  onClick={() => {
                    // A cross-level VISITOR ghost is selectable on its own (so you can
                    // remove them from just that group); a same-branch ref jumps to the
                    // real node.
                    if (isRef && (u as any).__acrossLevels) { setSelectedId(isSel ? null : u.id); return; }
                    setSelectedId(isRef ? ((u as any).__refOf as string) : (isSel ? null : u.id));
                  }}
                  className={`group w-full flex items-center gap-2.5 px-3 rounded-2xl font-bold transition-all border ${
                    isRef
                      // Reference placement: a faint, dashed ghost of the member — no glow,
                      // clearly not their home node. Tapping it jumps to the real one.
                      ? 'bg-transparent border-emerald-500/25 border-dashed opacity-60 hover:opacity-100 hover:border-emerald-400/50'
                      : isGroup
                      ? ((isColl || isEmptyGroup)
                          // Collapsed (or empty) = a solid pill that stands in for its members.
                          ? (isSel
                              ? 'bg-[#141414] border-emerald-300/60 border-dashed shadow-[0_0_16px_rgba(16,185,129,0.4)]'
                              : 'bg-[#0e0e0e] border-emerald-500/30 border-dashed hover:border-emerald-500/50')
                          // Expanded = a light label sitting OVER its members, not a node.
                          : (isSel
                              ? 'bg-emerald-500/5 border-emerald-400/40 border-dashed'
                              : 'bg-transparent border-transparent hover:bg-emerald-500/5'))
                      : (isSel
                          ? 'bg-[#0f1512] border-emerald-300 shadow-[0_0_22px_rgba(16,185,129,0.75)]'
                          : 'bg-[#0f1512] border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.35)] hover:border-emerald-400 hover:shadow-[0_0_18px_rgba(16,185,129,0.6)]')
                  }`}
                  style={{ height: NODE_H }}
                  title={isRef ? `${u.name} — also in this group (tap to go to their node)` : u.name}
                >
                  {isGroup ? (
                    <span
                      onClick={(e) => { e.stopPropagation(); toggleGroup(u.id); }}
                      title={isColl ? 'Expand' : 'Collapse'}
                      className="shrink-0 w-8 h-8 rounded-xl flex items-center justify-center font-black text-sm ring-1 ring-white/10 text-emerald-400 cursor-pointer hover:bg-emerald-500/20" style={{ backgroundColor: 'rgba(16,185,129,0.10)', border: '1px dashed rgba(16,185,129,0.4)' }}>
                      {isColl ? <ChevronRight className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </span>
                  ) : (
                    <Avatar pid={u.id} name={u.name} color={u.color} avatarAt={(u as any).avatarAt} viewerNodeId={viewerNodeId} size={32} className="ring-1 ring-white/10" />
                  )}
                  <span className="min-w-0 flex flex-col items-start leading-tight">
                    <span className={`text-[12px] font-bold w-full flex items-start gap-1 ${isGroup ? 'text-emerald-300' : 'text-white'}`}>
                      {isGroup && <Layers className="w-3 h-3 shrink-0 mt-[3px] text-emerald-400/80" />}
                      <span className="min-w-0 break-words line-clamp-2">{capName(u.name)}</span>
                      {u.role === 'ROOT' && !isGroup && <span className="text-amber-400 shrink-0" title="Root">★</span>}
                    </span>
                    <span className={`${isGroup ? 'text-[9px]' : 'text-[8px]'} font-black uppercase tracking-widest flex items-center gap-1 ${isGroup ? 'text-emerald-500/80' : isRef ? 'text-amber-400/80' : 'text-emerald-500/80'}`}>
                      {isGroup ? groupCountLabel(memberCount, (u as any).__visitors || 0) : isRef ? 'Visitor' : (u.isMe ? 'You' : (typeof u.level === 'number' ? `Lvl ${u.level}` : 'Member'))}
                      {trueSight && !isGroup && !isRef && <Eye className="w-2.5 h-2.5 text-emerald-400" />}
                    </span>
                  </span>
                </button>
                {canAddHere && (
                  <button
                    onPointerDown={(ev) => ev.stopPropagation()}
                    onClick={() => { setAddingGroup(true); setAddName(''); if (isGroup) { setAddOwner((u as any).ownerId); setAddParent((u as any).groupId); } else { setAddOwner(u.id); setAddParent(null); } }}
                    title={isGroup ? 'Add a sub-group inside this group' : 'Add a group under this node'}
                    className="mt-1.5 w-7 h-7 rounded-full bg-emerald-500 text-black flex items-center justify-center shadow-[0_0_10px_rgba(16,185,129,0.6)] hover:bg-emerald-400 active:scale-90 transition-all"
                  >
                    <Plus className="w-4 h-4" strokeWidth={3} />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* zoom controls */}
      <div className="absolute top-3 right-3 flex flex-col gap-1.5 z-20">
        <button onClick={() => { userMoved.current = true; setZoom(z => clampZoom(z * 1.15)); }} className="w-9 h-9 rounded-lg bg-[#151515] border border-white/10 text-zinc-300 hover:text-white hover:border-emerald-500/40 flex items-center justify-center"><ZoomIn className="w-4 h-4" /></button>
        <button onClick={() => { userMoved.current = true; setZoom(z => clampZoom(z * 0.87)); }} className="w-9 h-9 rounded-lg bg-[#151515] border border-white/10 text-zinc-300 hover:text-white hover:border-emerald-500/40 flex items-center justify-center"><ZoomOut className="w-4 h-4" /></button>
        <button onClick={() => recenter(0.85)} title="Recenter" className="w-9 h-9 rounded-lg bg-[#151515] border border-white/10 text-zinc-300 hover:text-white hover:border-emerald-500/40 flex items-center justify-center"><Maximize2 className="w-4 h-4" /></button>
      </div>

      {/* Groups / branches build mode + expand/collapse-all */}
      {(canManageGroups || allGroupIds.length > 0) && (
        <div className="absolute top-3 left-3 z-20 flex flex-col gap-1.5 items-start">
          {canManageGroups && (
            <button
              onClick={() => setGroupMode(v => !v)}
              title="Create empty groups (branches) to lay out your structure, then populate them via their join links"
              className={`flex items-center gap-2 h-9 px-3 rounded-lg border text-[10px] font-black uppercase tracking-widest transition-colors ${groupMode ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400' : 'bg-[#151515] border-white/10 text-zinc-400 hover:text-white hover:border-emerald-500/40'}`}
            >
              <FolderPlus className="w-4 h-4" /> {groupMode ? 'Editing groups' : 'Groups'}
            </button>
          )}
          {allGroupIds.length > 0 && (
            <button
              onClick={toggleAllGroups}
              title={allExpanded ? 'Collapse every group' : 'Expand every group'}
              className="flex items-center gap-2 h-9 px-3 rounded-lg border text-[10px] font-black uppercase tracking-widest transition-colors bg-[#151515] border-white/10 text-zinc-400 hover:text-white hover:border-emerald-500/40"
            >
              {allExpanded ? <ChevronsDownUp className="w-4 h-4" /> : <ChevronsUpDown className="w-4 h-4" />}
              {allExpanded ? 'Collapse all' : 'Expand all'}
            </button>
          )}
          {groupMode && (
            <div className="mt-0.5 max-w-[200px] text-[9px] leading-relaxed text-zinc-500 bg-black/50 border border-white/10 rounded-lg px-2 py-1.5">
              Tap the <span className="text-emerald-400 font-bold">＋</span> on your node to add a group. Open a group for its join link. Groups collapse when tapped.
            </div>
          )}
        </div>
      )}

      {/* selected-node action bar */}
      {selected && (
        <div className="absolute bottom-3 inset-x-2 sm:inset-x-auto sm:left-1/2 sm:-translate-x-1/2 z-20 bg-[#151515] border border-white/10 rounded-2xl shadow-2xl px-3 sm:px-4 py-3 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 sm:gap-4 max-h-[50vh] overflow-y-auto no-scrollbar animate-in fade-in slide-in-from-bottom-2">
          <div className="flex items-center gap-2 justify-between sm:justify-start shrink-0">
            <div className="flex items-center gap-2 min-w-0">
              {(selected as any).isGroup
                ? <div className="w-8 h-8 shrink-0 rounded-lg flex items-center justify-center text-xs font-bold" style={{ backgroundColor: 'rgba(16,185,129,0.12)', color: '#34d399', border: '1px dashed rgba(16,185,129,0.4)' }}><FolderPlus className="w-4 h-4" /></div>
                : <Avatar pid={selected.id} name={selected.name} color={selected.color} avatarAt={(selected as any).avatarAt} viewerNodeId={viewerNodeId} size={32} />}
              <div className="min-w-0">
                <div className="text-sm font-bold text-white truncate">{selected.name}</div>
                <div className="text-[9px] text-zinc-600 uppercase tracking-tighter font-mono">{(selected as any).isGroup ? `Group · ${groupCountLabel((selected as any).__count ?? 0, (selected as any).__visitors ?? 0)}` : (typeof selected.level === 'number' ? `Level ${selected.level}` : (selected.role === 'ROOT' ? 'Root' : 'Member'))}</div>
              </div>
              {!(selected as any).isGroup && onOpenProfile && (
                <button onClick={() => onOpenProfile({ pid: selected.id, name: selected.name, color: selected.color, avatarAt: (selected as any).avatarAt, isMe: !!selected.isMe })}
                  className="p-1.5 rounded-lg text-zinc-500 hover:text-emerald-400 hover:bg-white/5 transition-colors shrink-0" aria-label={`View ${selected.name}'s profile`} title="Profile">
                  <Info className="w-4 h-4" />
                </button>
              )}
            </div>
            {/* Close lives in the header row on mobile, where the bar is stacked. */}
            <button onClick={() => setSelectedId(null)} className="sm:hidden p-1.5 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
          </div>
          {(selected as any).__ref && (selected as any).__acrossLevels ? (
            <div className="flex items-center gap-2 flex-wrap justify-center sm:justify-start">
              <span className="text-[9px] font-black uppercase tracking-widest text-amber-400/70 self-center">Visitor here</span>
              <button onClick={() => setSelectedId((selected as any).__refOf as string)}
                className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-400 hover:text-emerald-400 transition-colors">
                <Waypoints className="w-3.5 h-3.5" /> Go to their node
              </button>
              {onSetGroupVisitors && canManageNode((selected as any).__visOwner) && (
                <button
                  onClick={async () => {
                    const owner = (selected as any).__visOwner as string; const gid = (selected as any).__visGid as string; const uid = (selected as any).__refOf as string;
                    if (!owner || !gid) return;
                    if (!window.confirm(`Remove ${selected!.name} from this group? They stay in the tree — this only ends their visitor access to this one group.`)) return;
                    const next = (groupVisitorMap.get(`${owner}|${gid}`) || []).filter(id => id !== uid);
                    try { await onSetGroupVisitors(owner, { [gid]: next }); setSelectedId(null); } catch (e: any) { alert(e?.message || 'Could not remove.'); }
                  }}
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors">
                  <Scissors className="w-3.5 h-3.5" /> Remove from group
                </button>
              )}
            </div>
          ) : (selected as any).isGroup ? (
            <div className="flex items-center gap-2 flex-wrap justify-center sm:justify-start">
              <button onClick={() => toggleGroup(selected!.id)}
                className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-300 hover:bg-white/10 transition-colors">
                {collapsed.has(selected!.id) ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                {collapsed.has(selected!.id) ? 'Expand' : 'Collapse'}
              </button>
              {/* Join link is grabbable for any group BELOW you (canManageNode covers
                  your subtree) and, with True Sight, for any group in the whole tree. */}
              {!canManageNode((selected as any).ownerId) && hasTrueSight && (
                <button onClick={() => openQr(selected!)} disabled={qrBusy}
                  title="Grab this group's join link (True Sight)"
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 transition-colors disabled:opacity-50">
                  <QrCode className="w-3.5 h-3.5" /> {qrBusy && qrNode?.id === selected!.id ? 'Loading…' : 'Join link'}
                </button>
              )}
              {canManageNode((selected as any).ownerId) ? (<>
                <button onClick={() => openQr(selected!)} disabled={qrBusy}
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25 transition-colors disabled:opacity-50">
                  <QrCode className="w-3.5 h-3.5" /> {qrBusy && qrNode?.id === selected!.id ? 'Loading…' : 'Join link'}
                </button>
                {onAssignToGroup && (
                  <button onClick={() => { setAddMembersTo(selected!); setMemberSel(new Set()); }}
                    className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-400 hover:text-emerald-400 transition-colors">
                    <UserPlus className="w-3.5 h-3.5" /> Add members
                  </button>
                )}
                {onCreateGroup && (
                  <button onClick={() => { setAddingGroup(true); setAddName(''); setAddOwner((selected as any).ownerId); setAddParent((selected as any).groupId); }}
                    className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-400 hover:text-emerald-400 transition-colors">
                    <FolderPlus className="w-3.5 h-3.5" /> Sub-group
                  </button>
                )}
                {onLinkGroups && groupsOf && (() => {
                  const cnt = linksOf ? linksOf((selected as any).ownerId).filter(l => !l.crossLevel && (l.groups || []).includes((selected as any).groupId) && !l.archived).length : 0;
                  return (
                    <button onClick={() => openEditLinks(selected!)}
                      className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-amber-500/10 text-amber-400/90 hover:bg-amber-500/20 hover:text-amber-300 transition-colors">
                      <Link2 className="w-3.5 h-3.5" /> Edit links{cnt > 0 ? ` · ${cnt}` : ''}
                    </button>
                  );
                })()}
                <button onClick={() => { setRenaming(selected!); setAddName(selected!.name); }}
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-400 hover:text-emerald-400 transition-colors">
                  <Pencil className="w-3.5 h-3.5" /> Rename
                </button>
                <button onClick={async () => { if (window.confirm(`Delete the "${selected!.name}" group? Its members stay in the network, just ungrouped.`)) { try { await onDeleteGroup?.((selected as any).ownerId, (selected as any).groupId); setSelectedId(null); } catch (e: any) { alert(e?.message || 'Could not delete group.'); } } }}
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors">
                  <X className="w-3.5 h-3.5" /> Delete group
                </button>
              </>) : (
                <span className="text-[9px] text-zinc-600 uppercase tracking-widest">Managed by its owner</span>
              )}
            </div>
          ) : canManage(selected) ? (
            <div className="flex items-center gap-2 flex-wrap justify-center sm:justify-start">
              {canTrueSight && (() => {
                // Optimistic override so the tap reflects INSTANTLY; server truth
                // (via refresh) replaces it on the next users update.
                const cur = tsOverride.has(selected.id) ? tsOverride.get(selected.id)!.val : !!selected.permissions?.viewTrueLevel;
                return (
                  <button
                    onClick={() => {
                      setTsOverride(prev => new Map(prev).set(selected.id, { val: !cur, at: Date.now() }));
                      onToggleTrueSight(selected.id, !cur);
                    }}
                    className={`px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 transition-colors ${cur ? 'bg-emerald-500/15 text-emerald-400' : 'bg-white/5 text-zinc-400 hover:text-emerald-400'}`}
                  >
                    {cur ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
                    {cur ? 'Revoke True Sight' : 'Grant True Sight'}
                  </button>
                );
              })()}
              {canTrueSight && (() => {
                const cur = annOverride.has(selected.id) ? annOverride.get(selected.id)!.val : !!selected.permissions?.announce;
                return (
                  <button
                    onClick={() => {
                      setAnnOverride(prev => new Map(prev).set(selected.id, { val: !cur, at: Date.now() }));
                      onToggleAnnounce(selected.id, !cur);
                    }}
                    className={`px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 transition-colors ${cur ? 'bg-emerald-500/15 text-emerald-400' : 'bg-white/5 text-zinc-400 hover:text-emerald-400'}`}
                  >
                    <Megaphone className="w-3.5 h-3.5" />
                    {cur ? 'Revoke Announcements' : 'Grant Announcements'}
                  </button>
                );
              })()}
              {onEditMemberGroups && !selected.isMe && selected.role !== 'ROOT' && canManageNode(selected.invitedBy || undefined) && (
                <button
                  onClick={() => openEditGroups(selected!)}
                  title="Choose which of their inviter's groups this member is in — they can be in several at once (including none)"
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-400 hover:text-emerald-400 transition-colors"
                >
                  <Layers className="w-3.5 h-3.5" /> Edit groups
                </button>
              )}
              {onMoveNode && !selected.isMe && selected.role !== 'ROOT' && allGroupNodes.length > 0 && (
                <button
                  onClick={() => setMovingNode(selected!)}
                  title="Move this member AND everyone they invited into another group (re-parents the whole branch)"
                  className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-white/5 text-zinc-400 hover:text-emerald-400 transition-colors"
                >
                  <Layers className="w-3.5 h-3.5" /> Move to group
                </button>
              )}
              <button
                onClick={() => { if (window.confirm(`Prune "${selected.name}" and everyone they invited? This permanently removes that entire branch and cannot be undone.`)) { onPrune(selected.id); setSelectedId(null); } }}
                className="px-3 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors"
              >
                <Scissors className="w-3.5 h-3.5" /> Prune
              </button>
            </div>
          ) : (
            <span className="text-[9px] text-zinc-600 uppercase tracking-widest">{selected.isMe ? 'This is you' : 'Above you — no actions'}</span>
          )}
          <button onClick={() => setSelectedId(null)} className="hidden sm:block p-1.5 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
        </div>
      )}

      {/* Create / rename group ("branch") modal */}
      {(addingGroup || renaming) && (
        <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onPointerDown={(e) => e.stopPropagation()}>
          <div className="w-full max-w-xs bg-[#111] border border-emerald-500/25 rounded-2xl shadow-2xl p-5 space-y-4">
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0"><FolderPlus className="w-5 h-5 text-emerald-500" /></div>
              <div>
                <div className="text-sm font-bold text-white">{renaming ? 'Rename group' : (addParent ? 'New sub-group' : 'New group')}</div>
                <div className="text-[10px] text-zinc-500 truncate max-w-[190px]">{renaming ? 'A label over its members' : (addParent ? `Inside ${layout.nodes.find(n => (n.user as any).groupId === addParent)?.user.name || 'this group'}` : 'An empty branch you can populate via its link')}</div>
              </div>
            </div>
            <input autoFocus value={addName} maxLength={64}
              onChange={e => setAddName(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') { if (renaming) { const v = addName.trim(); if (v) { onRenameGroup?.((renaming as any).ownerId, (renaming as any).groupId, v); setRenaming(null); } } else submitAdd(); }
                if (e.key === 'Escape') { setAddingGroup(false); setRenaming(null); }
              }}
              placeholder="Group name"
              className="w-full bg-black border border-white/10 rounded-xl px-3 py-2.5 text-sm text-white focus:border-emerald-500/50 outline-none transition-colors" />
            <div className="flex gap-2">
              <button onClick={() => { setAddingGroup(false); setRenaming(null); }} className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-white/5 text-zinc-400 hover:bg-white/10 transition-colors">Cancel</button>
              {renaming ? (
                <button onClick={() => { const v = addName.trim(); if (v) { onRenameGroup?.((renaming as any).ownerId, (renaming as any).groupId, v); setRenaming(null); } }}
                  className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all">Save</button>
              ) : (
                <button onClick={submitAdd} disabled={!addName.trim() || addBusy}
                  className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all disabled:opacity-40">
                  {addBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : 'Create'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Group invite QR / link */}
      {qrNode && (
        <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onPointerDown={(e) => e.stopPropagation()}>
          <div className="w-full max-w-xs bg-[#111] border border-emerald-500/25 rounded-2xl shadow-2xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-sm font-bold text-white truncate">{qrNode.name}</div>
              <button onClick={() => { setQrNode(null); setQrData(null); }} className="p-1 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
            </div>
            {qrData ? (
              <>
                <img src={qrData.dataUrl} alt="Group invite QR" className="w-44 mx-auto block rounded-xl bg-[#0a0a0a] border border-white/5" />
                <div className="text-center">
                  <div className="text-[9px] font-black uppercase tracking-widest text-zinc-600">Scan or share to join this group</div>
                  <div className="text-[11px] font-mono font-bold text-emerald-400 tracking-wider mt-0.5 select-all">{qrData.code}</div>
                </div>
                <p className="text-[9px] text-zinc-600 leading-relaxed">Anyone who opens this link joins <span className="text-zinc-400 font-semibold">{qrNode.name}</span> and lands in that group once you approve their request.</p>
                <div className="flex gap-1.5">
                  <button onClick={() => { navigator.clipboard?.writeText(qrData.link).catch(() => {}); setQrTip('Link copied'); setTimeout(() => setQrTip(null), 2000); }}
                    className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-white/5 text-zinc-300 hover:bg-white/10 transition-colors">Copy link</button>
                  <button onClick={() => openQr(qrNode, true)} disabled={qrBusy}
                    className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50">{qrBusy ? '…' : 'New code'}</button>
                </div>
                {qrTip && <div className="text-center text-[9px] font-black uppercase tracking-widest text-emerald-500">{qrTip}</div>}
              </>
            ) : (
              <div className="py-8 flex items-center justify-center"><Loader2 className="w-5 h-5 animate-spin text-emerald-500" /></div>
            )}
          </div>
        </div>
      )}

      {/* Add members to a group: pick from my direct invitees */}
      {addMembersTo && (
        <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onPointerDown={(e) => e.stopPropagation()}>
          <div className="w-full max-w-xs bg-[#111] border border-emerald-500/25 rounded-2xl shadow-2xl p-5 space-y-3 max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between shrink-0">
              <div className="min-w-0">
                <div className="text-sm font-bold text-white truncate">Add to {addMembersTo.name}</div>
                <div className="text-[10px] text-zinc-500">Pick people you invited</div>
              </div>
              <button onClick={() => setAddMembersTo(null)} className="p-1 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
            </div>
            <div className="flex-1 overflow-y-auto no-scrollbar space-y-1 -mx-1 px-1">
              {(() => { const cand = inviteesOf ? inviteesOf((addMembersTo as any).ownerId) : []; return cand.length === 0 ? (
                <div className="text-[10px] text-zinc-600 italic py-4 text-center">No one has joined under this node yet. Share the group’s join link instead.</div>
              ) : cand.map(m => {
                const inThis = m.groupIds.includes((addMembersTo as any).groupId);
                const sel = memberSel.has(m.id);
                return (
                  <button key={m.id} disabled={inThis}
                    onClick={() => setMemberSel(prev => { const nx = new Set(prev); nx.has(m.id) ? nx.delete(m.id) : nx.add(m.id); return nx; })}
                    className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-colors ${inThis ? 'opacity-40' : (sel ? 'bg-emerald-500/15' : 'hover:bg-white/5')}`}>
                    <span className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ${sel || inThis ? 'bg-emerald-500 border-emerald-500' : 'border-white/20'}`}>{(sel || inThis) && <Check className="w-3 h-3 text-black" />}</span>
                    <span className="text-sm text-white truncate flex-1 min-w-0">{m.name}</span>
                    {inThis && <span className="text-[8px] font-black uppercase tracking-widest text-emerald-500/70 shrink-0">In group</span>}
                  </button>
                );
              }); })()}
            </div>
            <div className="flex gap-2 shrink-0">
              <button onClick={() => setAddMembersTo(null)} className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-white/5 text-zinc-400 hover:bg-white/10 transition-colors">Cancel</button>
              <button onClick={submitMembers} disabled={memberSel.size === 0 || memberBusy}
                className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all disabled:opacity-40">
                {memberBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : `Add${memberSel.size ? ` (${memberSel.size})` : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Unified link manager: edit which groups share a chat, create new links,
          and archive → restore/delete — all for the selected group. */}
      {editLink && (() => {
        const owner = (editLink as any).ownerId; const myG = (editLink as any).groupId;
        const myLinks = (linksOf ? linksOf(owner) : []).filter(l => !l.crossLevel && (l.groups || []).includes(myG));
        // Cross-level links (on the root) that include THIS group — editable chips.
        const myCross = (rootCrossLinks || []).filter(l => l.refs.some(r => r.o === owner && r.g === myG));
        const selLink = editLid !== 'new' ? myLinks.find(l => l.id === editLid) : null;
        const selCross = editLid !== 'new' ? myCross.find(l => l.id === editLid) : null;
        const isArchived = !!(selLink?.archived || selCross?.archived);
        const otherGroups = (groupsOf ? groupsOf(owner) : []).filter(g => g.groupId !== myG);
        return (
          <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onPointerDown={(e) => e.stopPropagation()}>
            <div className="w-full max-w-xs bg-[#111] border border-amber-500/25 rounded-2xl shadow-2xl p-5 space-y-3 max-h-[85vh] flex flex-col">
              <div className="flex items-center justify-between shrink-0">
                <div className="min-w-0">
                  <div className="text-sm font-bold text-white truncate flex items-center gap-1.5"><Link2 className="w-3.5 h-3.5 text-amber-400 shrink-0" /> Edit links · {editLink.name}</div>
                  <div className="text-[10px] text-zinc-500">Share a chat across groups</div>
                </div>
                <button onClick={() => setEditLink(null)} className="p-1 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
              </div>

              {/* Which link is being edited (or a new one). Amber = same-level, rose = cross-level. */}
              {(myLinks.length + myCross.length) > 0 && (
                <div className="flex flex-wrap gap-1 shrink-0">
                  {myLinks.map(l => (
                    <button key={l.id} onClick={() => selectEditLink(l.id)}
                      className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wide transition-colors max-w-[140px] truncate ${editLid === l.id ? 'bg-amber-500 text-black' : (l.archived ? 'bg-white/5 text-zinc-500' : 'bg-amber-500/15 text-amber-300')}`}>
                      {l.name}{l.archived ? ' · arch' : ''}
                    </button>
                  ))}
                  {myCross.map(l => (
                    <button key={l.id} onClick={() => selectEditLink(l.id)}
                      className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wide transition-colors max-w-[140px] truncate flex items-center gap-1 ${editLid === l.id ? 'bg-rose-500 text-white' : (l.archived ? 'bg-white/5 text-zinc-500' : 'bg-rose-500/15 text-rose-300')}`}>
                      <Link2 className="w-2.5 h-2.5 shrink-0" />{l.name}{l.archived ? ' · arch' : ''}
                    </button>
                  ))}
                  <button onClick={() => selectEditLink('new')}
                    className={`px-2 py-1 rounded-lg text-[10px] font-bold uppercase tracking-wide transition-colors ${editLid === 'new' ? 'bg-amber-500 text-black' : 'bg-white/5 text-zinc-400 hover:text-white'}`}>＋ New</button>
                </div>
              )}

              {isArchived ? (
                <div className="flex-1 flex flex-col justify-center items-center text-center gap-3 py-6">
                  <div className="text-[11px] text-zinc-400 leading-relaxed px-2">This chat is <span className="text-amber-400 font-bold">archived</span> — read-only. Restore it to reopen, or delete it permanently (its history is erased).</div>
                  <div className="flex gap-2">
                    <button onClick={() => archiveEditLink(editLid as string, false)} disabled={linkBusy}
                      className="px-4 py-2 rounded-xl bg-amber-500 text-black text-[11px] font-black uppercase tracking-widest hover:bg-amber-400 disabled:opacity-40 flex items-center gap-1.5"><Radio className="w-3.5 h-3.5" /> Restore</button>
                    <button onClick={() => deleteEditLink(editLid as string, (selLink || selCross)!.name)} disabled={linkBusy}
                      className="px-4 py-2 rounded-xl bg-red-500/15 text-red-400 text-[11px] font-black uppercase tracking-widest hover:bg-red-500/25 disabled:opacity-40 flex items-center gap-1.5"><Trash2 className="w-3.5 h-3.5" /> Delete</button>
                  </div>
                </div>
              ) : (() => {
                // Show BOTH tabs whenever cross-level is possible (root) — editing an
                // existing link or creating a new one alike. selectEditLink already
                // sets xMode to match the selected link's type.
                const canCross = isRootUser && !!onCreateCrossLink && !!rootNodeId;
                const otherOwnerGroups = allGroupNodes.filter(x => !(x.ownerId === (editLink as any).ownerId && x.groupId === (editLink as any).groupId));
                return (
                <>
                  {canCross && (
                    <div className="shrink-0 flex gap-1 p-0.5 bg-white/5 rounded-xl">
                      <button onClick={() => switchLinkMode(false)} className={`flex-1 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest transition-colors ${!xMode ? 'bg-amber-500 text-black' : 'text-zinc-400'}`}>Same level</button>
                      <button onClick={() => switchLinkMode(true)} className={`flex-1 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest transition-colors ${xMode ? 'bg-red-500 text-white' : 'text-zinc-400'}`}>Across levels</button>
                    </div>
                  )}
                  {xMode ? (
                    <>
                      <div className="shrink-0 text-[10px] text-red-300 bg-red-500/10 border border-red-500/25 rounded-lg px-2.5 py-2 leading-relaxed">⚠ Cross-level links punch a hole through your compartments — anyone in the chosen groups can talk to each other regardless of where they sit. Only do this if you’re sure.</div>
                      <div className="flex-1 overflow-y-auto no-scrollbar space-y-1 -mx-1 px-1">
                        <div className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg bg-amber-500/10">
                          <div className="w-4 h-4 rounded border bg-amber-500/60 border-amber-500/60 flex items-center justify-center shrink-0"><Check className="w-3 h-3 text-black" /></div>
                          <span className="text-sm text-white truncate flex-1 min-w-0">{editLink.name}</span>
                          <span className="text-[8px] uppercase tracking-widest text-zinc-600 shrink-0">this group</span>
                        </div>
                        {otherOwnerGroups.length === 0
                          ? <div className="text-[10px] text-zinc-600 italic py-4 text-center">No other groups in the network.</div>
                          : otherOwnerGroups.map(g => {
                              const key = `${g.ownerId}|${g.groupId}`; const on = xSel.has(key);
                              return (
                                <button key={key} disabled={linkBusy} onClick={() => setXSel(prev => { const nx = new Set(prev); nx.has(key) ? nx.delete(key) : nx.add(key); return nx; })}
                                  className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-colors disabled:opacity-50 ${on ? 'bg-red-500/15 ring-1 ring-red-500/30' : 'hover:bg-white/5'}`}>
                                  <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ${on ? 'bg-red-500 border-red-500' : 'border-zinc-600'}`}>{on && <Check className="w-3 h-3 text-white" />}</div>
                                  <span className="text-sm text-white truncate flex-1 min-w-0">{g.name}</span>
                                  <span className="text-[8px] uppercase tracking-widest text-zinc-600 shrink-0 max-w-[80px] truncate">under {g.ownerName || 'root'}</span>
                                </button>
                              );
                            })}
                      </div>
                      <div className="shrink-0 space-y-1.5">
                        <button onClick={submitCrossLink} disabled={linkBusy || xSel.size === 0}
                          className="w-full py-2.5 rounded-xl bg-red-500 text-white text-[11px] font-black uppercase tracking-widest hover:bg-red-400 active:scale-95 transition-all disabled:opacity-40 flex items-center justify-center gap-1.5">
                          {linkBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Link2 className="w-3.5 h-3.5" /> {selCross ? 'Save cross-level link' : 'Create cross-level link'} · {xSel.size + 1} groups</>}
                        </button>
                        {selCross && !selCross.archived && (
                          <button onClick={() => archiveEditLink(editLid as string, true)} disabled={linkBusy}
                            className="w-full py-2 rounded-xl bg-white/5 text-zinc-400 text-[10px] font-black uppercase tracking-widest hover:bg-red-500/15 hover:text-red-400 transition-colors disabled:opacity-40 flex items-center justify-center gap-1.5">
                            <Trash2 className="w-3.5 h-3.5" /> Delete chat
                          </button>
                        )}
                      </div>
                    </>
                  ) : (
                  <>
                  <div className="flex-1 overflow-y-auto no-scrollbar space-y-1 -mx-1 px-1">
                    {/* Anchor group — always part of the chat */}
                    <div className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg bg-amber-500/10">
                      <div className="w-4 h-4 rounded border bg-amber-500/60 border-amber-500/60 flex items-center justify-center shrink-0"><Check className="w-3 h-3 text-black" /></div>
                      <span className="text-sm text-white truncate flex-1 min-w-0">{editLink.name}</span>
                      <span className="text-[8px] uppercase tracking-widest text-zinc-600 shrink-0">this group</span>
                    </div>
                    {otherGroups.length === 0
                      ? <div className="text-[10px] text-zinc-600 italic py-4 text-center">No other groups to link with.</div>
                      : otherGroups.map(g => {
                          const on = editSel.has(g.groupId);
                          return (
                            <button key={g.groupId} disabled={linkBusy} onClick={() => setEditSel(prev => { const nx = new Set(prev); nx.has(g.groupId) ? nx.delete(g.groupId) : nx.add(g.groupId); return nx; })}
                              className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-colors disabled:opacity-50 ${on ? 'bg-amber-500/15 ring-1 ring-amber-500/30' : 'hover:bg-amber-500/10'}`}>
                              <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ${on ? 'bg-amber-500 border-amber-500' : 'border-zinc-600'}`}>{on && <Check className="w-3 h-3 text-black" />}</div>
                              <span className="text-sm text-white truncate flex-1 min-w-0">{g.name}</span>
                            </button>
                          );
                        })}
                  </div>
                  <div className="shrink-0 space-y-1.5">
                    <button onClick={saveEditLink} disabled={linkBusy || editSel.size === 0}
                      className="w-full py-2.5 rounded-xl bg-amber-500 text-black text-[11px] font-black uppercase tracking-widest hover:bg-amber-400 active:scale-95 transition-all disabled:opacity-40 flex items-center justify-center gap-1.5">
                      {linkBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <><Link2 className="w-3.5 h-3.5" /> {editLid === 'new' ? `Create link · ${editSel.size + 1} groups` : `Save changes · ${editSel.size + 1} groups`}</>}
                    </button>
                    {editLid !== 'new' && selLink && (
                      <button onClick={() => archiveEditLink(editLid as string, true)} disabled={linkBusy}
                        className="w-full py-2 rounded-xl bg-white/5 text-zinc-400 text-[10px] font-black uppercase tracking-widest hover:bg-red-500/15 hover:text-red-400 transition-colors disabled:opacity-40 flex items-center justify-center gap-1.5">
                        <Trash2 className="w-3.5 h-3.5" /> Delete chat
                      </button>
                    )}
                  </div>
                  <p className="text-[9px] text-zinc-600 leading-relaxed shrink-0">Everyone in the chosen groups (and you) shares one chat, walled off from every other. <span className="text-zinc-500">Delete archives the chat first — restore or erase it permanently from its <span className="text-amber-400/70">· arch</span> tab above.</span></p>
                  </>
                  )}
                </>
                );
              })()}
            </div>
          </div>
        );
      })()}

      {/* Move a member (with their whole subtree) into another group */}
      {movingNode && (
        <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onPointerDown={(e) => e.stopPropagation()}>
          <div className="w-full max-w-xs bg-[#111] border border-emerald-500/25 rounded-2xl shadow-2xl p-5 space-y-3 max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between shrink-0">
              <div className="min-w-0">
                <div className="text-sm font-bold text-white truncate flex items-center gap-1.5"><Layers className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Move {movingNode.name}</div>
                <div className="text-[10px] text-zinc-500">Takes everyone they invited (and those groups) along</div>
              </div>
              <button onClick={() => setMovingNode(null)} className="p-1 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
            </div>
            <div className="flex-1 overflow-y-auto no-scrollbar space-y-1 -mx-1 px-1">
              {(() => {
                const excluded = subtreeIdsOf(movingNode.id); // can't move into own branch
                const opts = allGroupNodes.filter(g => !excluded.has(g.ownerId));
                if (!opts.length) return <div className="text-[10px] text-zinc-600 italic py-4 text-center">No groups available to move into. Create a group first.</div>;
                return opts.map(g => (
                  <button key={g.ownerId + ':' + g.groupId} disabled={moveBusy} onClick={() => submitMove(g.ownerId, g.groupId)}
                    className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left hover:bg-emerald-500/10 transition-colors disabled:opacity-50">
                    <Layers className="w-3.5 h-3.5 text-emerald-500/70 shrink-0" />
                    <span className="min-w-0 flex-1">
                      <span className="text-sm text-white block truncate">{g.name}</span>
                      {g.ownerName && <span className="text-[9px] text-zinc-500 block truncate">under {g.ownerName}</span>}
                    </span>
                  </button>
                ));
              })()}
            </div>
            <p className="text-[9px] text-zinc-600 leading-relaxed shrink-0">The member is re-parented into the chosen group. Their descendants and their own groups move with them.</p>
          </div>
        </div>
      )}

      {/* Edit which of the inviter's groups a member belongs to (multi-select). */}
      {editGroupsNode && (
        <div className="absolute inset-0 z-30 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onPointerDown={(e) => e.stopPropagation()}>
          <div className="w-full max-w-xs bg-[#111] border border-emerald-500/25 rounded-2xl shadow-2xl p-5 space-y-3 max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between shrink-0">
              <div className="min-w-0">
                <div className="text-sm font-bold text-white truncate flex items-center gap-1.5"><Layers className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> {editGroupsNode.name}'s groups</div>
                <div className="text-[10px] text-zinc-500">Tick every group they belong to</div>
              </div>
              <button onClick={() => setEditGroupsNode(null)} className="p-1 text-zinc-600 hover:text-white shrink-0"><X className="w-4 h-4" /></button>
            </div>
            <div className="flex-1 overflow-y-auto no-scrollbar space-y-1 -mx-1 px-1">
              {(groupsOf ? groupsOf(editGroupsNode.invitedBy!) : []).map(g => {
                const on = egSel.has(g.groupId);
                return (
                  <button key={g.groupId} disabled={egBusy}
                    onClick={() => setEgSel(prev => { const nx = new Set(prev); nx.has(g.groupId) ? nx.delete(g.groupId) : nx.add(g.groupId); return nx; })}
                    className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-colors disabled:opacity-50 ${on ? 'bg-emerald-500/15' : 'hover:bg-white/5'}`}>
                    <span className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ${on ? 'bg-emerald-500 border-emerald-500' : 'border-white/20'}`}>{on && <Check className="w-3 h-3 text-black" />}</span>
                    <span className="text-sm text-white truncate flex-1 min-w-0">{g.name}</span>
                  </button>
                );
              })}
              {egSel.size === 0 && <div className="text-[10px] text-zinc-600 italic px-2 py-1">No groups ticked — they'll be ungrouped (default chat).</div>}
              {isRootUser && onSetGroupVisitors && (() => {
                const excluded = subtreeIdsOf(editGroupsNode.id);
                const others = allGroupNodes.filter(g => g.ownerId !== editGroupsNode.invitedBy && !excluded.has(g.ownerId) && g.ownerId !== editGroupsNode.id);
                if (!others.length) return null;
                return (
                  <>
                    <div className="text-[9px] font-black uppercase tracking-widest text-amber-400/70 px-1 pt-3 pb-0.5">Add as visitor · across levels</div>
                    {others.map(g => {
                      const key = `${g.ownerId}|${g.groupId}`; const on = egVisit.has(key);
                      return (
                        <button key={key} disabled={egBusy}
                          onClick={() => setEgVisit(prev => { const nx = new Set(prev); nx.has(key) ? nx.delete(key) : nx.add(key); return nx; })}
                          className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-colors disabled:opacity-50 ${on ? 'bg-amber-500/15' : 'hover:bg-white/5'}`}>
                          <span className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 ${on ? 'bg-amber-500 border-amber-500' : 'border-white/20'}`}>{on && <Check className="w-3 h-3 text-black" />}</span>
                          <span className="min-w-0 flex-1"><span className="text-sm text-white block truncate">{g.name}</span><span className="text-[9px] text-amber-400/60 block truncate">under {g.ownerName || 'another branch'} · across levels</span></span>
                        </button>
                      );
                    })}
                  </>
                );
              })()}
            </div>
            <div className="flex gap-2 shrink-0">
              <button onClick={() => setEditGroupsNode(null)} className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-white/5 text-zinc-400 hover:bg-white/10 transition-colors">Cancel</button>
              <button onClick={submitEditGroups} disabled={egBusy}
                className="flex-1 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-xl bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all disabled:opacity-40">
                {egBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin mx-auto" /> : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};


/**
 * A pannable/zoomable tree picker that looks exactly like the Network Tree —
 * used by Announcements (pick who receives) and the Monitor Hub (pick who to
 * monitor). Tapping a node highlights THAT node and the chain ABOVE it (its
 * ancestors up to you): for announcements that IS the delivery set — nobody
 * below the picked person receives the announcement. Nodes outside
 * `selectableIds` are dimmed and can't be picked.
 */
// Date-divider label for a message timestamp, per the spec: for messages less
// than a week old show the weekday ("Monday"), older than a week show the date.
// Today/Yesterday are called out explicitly.
const dayKey = (ts: number) => { const d = new Date(ts); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; };
const DateDivider = ({ ts }: { ts: number }) => {
    const { locale, t } = useLocale();
    const d = new Date(ts);
    const now = new Date();
    const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const days = Math.round((startOf(now) - startOf(d)) / 86400000);
    let label: string;
    if (days === 0) label = t('msg.today');
    else if (days === 1) label = t('msg.yesterday');
    else if (days < 7) label = d.toLocaleDateString(locale, { weekday: 'long' });
    else label = d.getFullYear() === now.getFullYear()
        ? d.toLocaleDateString(locale, { month: 'long', day: 'numeric' })
        : d.toLocaleDateString(locale, { month: 'long', day: 'numeric', year: 'numeric' });
    return (
        <div className="flex items-center justify-center my-3 select-none">
            <div className="px-3 py-1 rounded-full bg-white/[0.04] border border-white/5 text-[9px] font-black uppercase tracking-[0.15em] text-zinc-500">
                {label}
            </div>
        </div>
    );
};

const MiniTreeCanvas: React.FC<{
  root: TreeData;
  selectedIds: Set<string>;
  selectableIds: Set<string>;
  onTapNode: (id: string) => void;
  heightClass?: string;
  unselectableHint?: string;
}> = ({ root, selectedIds, selectableIds, onTapNode, heightClass = 'h-64', unselectableHint }) => {
  const layout = useMemo(() => layoutTree(root), [root]);
  // parent lookup for "highlight everything above the picked node"
  const parentOf = useMemo(() => {
    const m = new Map<string, string>();
    layout.edges.forEach(e => m.set(e.childId, e.parentId));
    return m;
  }, [layout]);
  const highlighted = useMemo(() => {
    const hot = new Set<string>();
    selectedIds.forEach(id => {
      let cur: string | undefined = id;
      for (let hops = 0; cur && hops < 200; hops++) { hot.add(cur); cur = parentOf.get(cur); }
    });
    return hot;
  }, [selectedIds, parentOf]);

  const containerRef = useRef<HTMLDivElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(0.7);
  const drag = useRef<{ startX: number; startY: number; panX: number; panY: number; moved: boolean } | null>(null);
  const pointers = useRef<Map<number, { x: number; y: number }>>(new Map());
  const pinch = useRef<{ dist: number; zoom: number; panX: number; panY: number; aKey: number; bKey: number; aStart: { x: number; y: number }; bStart: { x: number; y: number } } | null>(null);
  const clampZoom = (z: number) => Math.min(2, Math.max(0.25, z));
  const recenter = (z = 0.7) => {
    const cw = containerRef.current?.clientWidth || 600;
    setZoom(z);
    setPan({ x: (cw - layout.width * z) / 2, y: 14 });
  };
  useEffect(() => { recenter(0.7); // eslint-disable-next-line
  }, [layout.width, layout.height]);
  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const rect = containerRef.current!.getBoundingClientRect();
    const px = e.clientX - rect.left, py = e.clientY - rect.top;
    const nz = clampZoom(zoom * (e.deltaY < 0 ? 1.12 : 0.89));
    const wx = (px - pan.x) / zoom, wy = (py - pan.y) / zoom;
    setPan({ x: px - wx * nz, y: py - wy * nz });
    setZoom(nz);
  };
  const onPointerDown = (e: React.PointerEvent) => {
    (e.target as Element).setPointerCapture?.(e.pointerId);
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pointers.current.size === 2) {
      const [ka, kb] = [...pointers.current.keys()];
      const a = pointers.current.get(ka)!, b = pointers.current.get(kb)!;
      pinch.current = { dist: Math.hypot(a.x - b.x, a.y - b.y), zoom, panX: pan.x, panY: pan.y,
        aKey: ka, bKey: kb, aStart: { ...a }, bStart: { ...b } };
      drag.current = null;
    } else {
      drag.current = { startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y, moved: false };
    }
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!pointers.current.has(e.pointerId)) return;
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch.current && pointers.current.size === 2) {
      const pc = pinch.current;
      const a = pointers.current.get(pc.aKey)!, b = pointers.current.get(pc.bKey)!;
      const nz = clampZoom(pc.zoom * (Math.hypot(a.x - b.x, a.y - b.y) / pc.dist));
      const aMoved = Math.hypot(a.x - pc.aStart.x, a.y - pc.aStart.y);
      const bMoved = Math.hypot(b.x - pc.bStart.x, b.y - pc.bStart.y);
      const wa = 1 / (aMoved + 8), wb = 1 / (bMoved + 8);
      const cx = (a.x * wa + b.x * wb) / (wa + wb);
      const cy = (a.y * wa + b.y * wb) / (wa + wb);
      const rect = containerRef.current!.getBoundingClientRect();
      const ax = cx - rect.left, ay = cy - rect.top;
      const wx = (ax - pc.panX) / pc.zoom;
      const wy = (ay - pc.panY) / pc.zoom;
      setPan({ x: ax - wx * nz, y: ay - wy * nz });
      setZoom(nz);
    } else if (drag.current) {
      if (Math.abs(e.clientX - drag.current.startX) + Math.abs(e.clientY - drag.current.startY) > 6) drag.current.moved = true;
      setPan({ x: drag.current.panX + (e.clientX - drag.current.startX), y: drag.current.panY + (e.clientY - drag.current.startY) });
    }
  };
  const onPointerUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId);
    if (pointers.current.size < 2) pinch.current = null;
    if (pointers.current.size === 0) drag.current = null;
  };

  return (
    <div className={`relative overflow-hidden rounded-2xl bg-[#0a0a0a] border border-white/5 ${heightClass}`} style={{ touchAction: 'none' }}>
      <div ref={containerRef} className="absolute inset-0 cursor-grab active:cursor-grabbing" style={{ touchAction: 'none' }}
        onWheel={onWheel} onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerCancel={onPointerUp}>
        <div className="absolute top-0 left-0 origin-top-left" style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`, width: layout.width, height: layout.height }}>
          <svg width={layout.width} height={layout.height} className="absolute top-0 left-0 pointer-events-none">
            {layout.edges.map((e, i) => {
              const midY = (e.y1 + e.y2) / 2;
              const d = `M ${e.x1} ${e.y1 + NODE_H / 2} C ${e.x1} ${midY}, ${e.x2} ${midY}, ${e.x2} ${e.y2 - NODE_H / 2}`;
              // An edge lights up when BOTH ends are on a highlighted chain —
              // i.e. it lies on the path from a picked node upward.
              const hot = highlighted.has(e.parentId) && highlighted.has(e.childId);
              return (
                <g key={i}>
                  <path d={d} fill="none" stroke={hot ? 'rgba(52,211,153,0.9)' : 'rgba(16,185,129,0.18)'} strokeWidth={hot ? 3 : 2} strokeLinecap="round" />
                  {hot && <path d={d} fill="none" stroke="rgba(167,243,208,0.85)" strokeWidth={1.3} strokeLinecap="round" strokeDasharray="3 14" className="tree-flow" />}
                </g>
              );
            })}
          </svg>
          {layout.nodes.map(n => {
            const u = n.user;
            const isGroup = !!(u as any).isGroup;
            const isRef = !isGroup && !!(u as any).__ref; // a "visitor" — home is another group
            const isSel = selectedIds.has(u.id);
            const isHot = highlighted.has(u.id);
            const canPick = !isGroup && !isRef && selectableIds.has(u.id);
            // Group nodes are STRUCTURAL here — the same dashed folder label the
            // main Network Tree shows, so all three surfaces read alike. They're
            // never a monitor/announce target themselves (you pick people).
            if (isGroup) {
              const cnt = (u as any).__count ?? 0;
              return (
                <div key={u.id} className="absolute flex flex-col items-center" style={{ left: n.cx - NODE_W / 2, top: n.cy - NODE_H / 2, width: NODE_W }}>
                  <div className="w-full flex items-center gap-2.5 px-3 rounded-2xl bg-[#0e0e0e] border border-dashed border-emerald-500/30 cursor-default" style={{ height: NODE_H }} title={u.name}>
                    <span className="shrink-0 w-8 h-8 rounded-xl flex items-center justify-center ring-1 ring-white/10" style={{ backgroundColor: 'rgba(16,185,129,0.10)', border: '1px dashed rgba(16,185,129,0.4)' }}>
                      <Layers className="w-3.5 h-3.5 text-emerald-400" />
                    </span>
                    <span className="min-w-0 flex flex-col items-start leading-tight">
                      <span className="text-[12px] font-bold text-emerald-300 break-words line-clamp-2">{capName(u.name)}</span>
                      <span className="text-[9px] font-black uppercase tracking-widest text-emerald-500/80">{groupCountLabel(cnt, (u as any).__visitors || 0)}</span>
                    </span>
                  </div>
                </div>
              );
            }
            return (
              <div key={u.id} className="absolute flex flex-col items-center" style={{ left: n.cx - NODE_W / 2, top: n.cy - NODE_H / 2, width: NODE_W }}>
                <button
                  onPointerDown={(ev) => ev.stopPropagation()}
                  onClick={() => { if (canPick) onTapNode(u.id); }}
                  title={isRef ? `${u.name} — visitor (home group is elsewhere)` : canPick ? u.name : (unselectableHint || u.name)}
                  className={`w-full flex items-center gap-2.5 px-3 rounded-2xl text-white font-bold transition-all border ${
                    isRef ? 'bg-transparent border-emerald-500/25 border-dashed opacity-60 cursor-default'
                    : isSel ? 'bg-[#0f1512] border-emerald-300 shadow-[0_0_22px_rgba(16,185,129,0.8)]'
                    : isHot ? 'bg-[#0f1512] border-emerald-400/80 shadow-[0_0_14px_rgba(16,185,129,0.5)]'
                    : canPick ? 'bg-[#0f1512] border-emerald-500/40 hover:border-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.25)]'
                    : 'bg-[#0f1512] border-white/10 opacity-40 cursor-default'
                  }`}
                  style={{ height: NODE_H }}>
                  <span className="shrink-0 w-8 h-8 rounded-xl flex items-center justify-center text-white font-black text-sm ring-1 ring-white/10" style={{ backgroundColor: u.color }}>
                    {u.name?.[0]?.toUpperCase()}
                  </span>
                  <span className="min-w-0 flex flex-col items-start leading-tight">
                    <span className="text-[12px] font-bold text-white flex items-start gap-1">
                      <span className="min-w-0 break-words line-clamp-2">{capName(u.name)}</span>
                      {u.role === 'ROOT' && !isRef && <span className="text-amber-400 shrink-0" title="Root">★</span>}
                    </span>
                    <span className={`text-[8px] font-black uppercase tracking-widest flex items-center gap-1 ${isRef ? 'text-amber-400/80' : 'text-emerald-500/80'}`}>
                      {isRef ? 'Visitor' : u.isMe ? 'You' : (isSel || isHot) ? 'Receives' : ''}
                    </span>
                  </span>
                </button>
              </div>
            );
          })}
        </div>
      </div>
      <div className="absolute top-2 right-2 flex flex-col gap-1 z-20">
        <button onClick={() => setZoom(z => clampZoom(z * 1.15))} className="w-8 h-8 rounded-lg bg-[#151515] border border-white/10 text-zinc-300 hover:text-white flex items-center justify-center"><ZoomIn className="w-3.5 h-3.5" /></button>
        <button onClick={() => setZoom(z => clampZoom(z * 0.87))} className="w-8 h-8 rounded-lg bg-[#151515] border border-white/10 text-zinc-300 hover:text-white flex items-center justify-center"><ZoomOut className="w-3.5 h-3.5" /></button>
        <button onClick={() => recenter(0.7)} className="w-8 h-8 rounded-lg bg-[#151515] border border-white/10 text-zinc-300 hover:text-white flex items-center justify-center"><Maximize2 className="w-3.5 h-3.5" /></button>
      </div>
    </div>
  );
};


const JoinRequestItem = memo(({ req, onRespond }: { req: import('../types').JoinRequest; onRespond: (id: string, accept: boolean) => Promise<void> }) => {
  const [busy, setBusy] = useState<'accept' | 'decline' | null>(null);
  // v72 B2: only a request whose key is verified can be accepted.
  const verified = req.verified === 'link' || req.verified === 'network';
  const act = async (accept: boolean) => {
    if (busy || (accept && !verified)) return;
    if (!accept && !confirm(`Decline "${req.name}"? Their request is removed and their invite code becomes unusable for them.`)) return;
    setBusy(accept ? 'accept' : 'decline');
    try { await onRespond(req.id, accept); } catch (e: any) { alert(e?.message || 'Could not respond — try again.'); }
    setBusy(null);
  };
  return (
    <div className="mx-1 p-3 rounded-2xl bg-emerald-500/5 border border-emerald-500/20 mb-2">
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="text-sm font-bold text-white truncate">{req.name}</span>
        <span className="text-[9px] text-zinc-600 font-mono shrink-0">{req.requestedAt ? new Date(req.requestedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}</span>
      </div>
      {req.branchName && (
        <div className="text-[9px] text-emerald-400/90 uppercase tracking-widest font-black mb-1 truncate flex items-center gap-1"><FolderPlus className="w-2.5 h-2.5" /> Joining {req.branchName}</div>
      )}
      {req.referredByName && (
        <div className="text-[9px] text-emerald-400/80 uppercase tracking-widest font-black mb-2 truncate">Referred by {req.referredByName}</div>
      )}
      {verified
        ? <div className="text-[9px] text-emerald-400/80 font-bold mb-2 flex items-center gap-1"><ShieldCheck className="w-2.5 h-2.5 shrink-0" />{req.verified === 'network' ? 'Verified: a member of a network you share' : 'Verified: came through your invite link'}</div>
        : <div className="text-[9px] text-amber-400 font-bold mb-2 leading-relaxed">Can’t be verified — Arbor can’t confirm this request came from the person it names, so it can’t be accepted. Decline it and ask them to join again with a fresh invite link.</div>}
      <div className="flex gap-1.5">
        <button onClick={() => act(true)} disabled={!!busy || !verified} title={verified ? undefined : 'Unverified requests can’t be accepted'}
          className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all disabled:opacity-50">
          {busy === 'accept' ? '…' : 'Accept'}
        </button>
        <button onClick={() => act(false)} disabled={!!busy}
          className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-white/5 text-zinc-400 hover:text-red-400 hover:bg-red-500/10 active:scale-95 transition-all disabled:opacity-50">
          {busy === 'decline' ? '…' : 'Decline'}
        </button>
      </div>
    </div>
  );
});


/**
 * Personal-hub chats, iMessage style: one scrollable list of every contact with
 * the latest message previewed, a search bar on top that searches INSIDE all
 * personal chats (text + names, entirely on-device), and a person-plus button
 * top right that copies the invite link — anyone who opens it gets a private
 * chat with you and you appear in their own Personal Chats.
 */
const HubChatsView: React.FC<{
  contacts: User[];
  messages: Message[];
  me: User;
  lastSeen: Record<string, number>;
  seenFallback: number;
  onOpenChat: (contactId: string) => void;
  onCopyInvite: () => void;
  inviteBusy: boolean;
  copiedTip: string | null;
  onOpenProfile?: (info: { pid: string; name?: string; color?: string; avatarAt?: number; isMe?: boolean }) => void;
}> = ({ contacts, messages, me, lastSeen, seenFallback, onOpenChat, onCopyInvite, inviteBusy, copiedTip, onOpenProfile }) => {
  const t = useT();
  const [query, setQuery] = useState('');

  // Split the contact list: active chats, plus outgoing requests still waiting
  // for the other side to accept. Incoming requests live in the sidebar under
  // "Contact Requests", not here.
  const activeContacts = useMemo(() => contacts.filter(c => !c.pending), [contacts]);
  const waitingContacts = useMemo(() => contacts.filter(c => c.pending && c.pendingDirection === 'out'), [contacts]);

  // Assign each live PEER message to a contact's conversation.
  const byContact = useMemo(() => {
    const map = new Map<string, Message[]>();
    activeContacts.forEach(c => map.set(c.id, []));
    const now = Date.now();
    for (const m of messages) {
      if (m.type !== 'PEER') continue;
      if (typeof m.expiresAt === 'number' && m.expiresAt <= now) continue;
      let cid: string | null = null;
      if (m.senderId !== me.id && map.has(m.senderId)) cid = m.senderId;
      else if (m.senderId === me.id && m.peerId && map.has(m.peerId)) cid = m.peerId;
      else if (m.senderId === me.id && !m.peerId) {
        // Legacy own message without a recorded target: attach to every chat's
        // preview would be wrong; attach to none (it still shows inside chats).
        continue;
      }
      if (cid) map.get(cid)!.push(m);
    }
    return map;
  }, [activeContacts, messages, me.id]);

  const rows = useMemo(() => {
    return activeContacts.map(c => {
      const msgs = byContact.get(c.id) || [];
      const last = msgs.length ? msgs[msgs.length - 1] : null;
      const seenAt = (`C:${c.id}` in lastSeen) ? lastSeen[`C:${c.id}`] : seenFallback;
      const unread = msgs.filter(m => m.senderId === c.id && m.timestamp > seenAt).length;
      return { contact: c, last, unread };
    }).sort((a, b) => (b.last?.timestamp || 0) - (a.last?.timestamp || 0));
  }, [activeContacts, byContact, lastSeen]);

  // Search hits across ALL chats (message text + contact name), newest first.
  const hits = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    const out: { contact: User; message: Message | null }[] = [];
    for (const { contact } of rows) {
      const msgs = byContact.get(contact.id) || [];
      const nameHit = contact.name.toLowerCase().includes(q);
      const matched = msgs.filter(m => (m.text || '').toLowerCase().includes(q));
      if (matched.length) matched.slice(-5).reverse().forEach(m => out.push({ contact, message: m }));
      else if (nameHit) out.push({ contact, message: null });
    }
    return out.sort((a, b) => (b.message?.timestamp || 0) - (a.message?.timestamp || 0)).slice(0, 60);
  }, [query, rows, byContact]);

  const fmtTime = (ts?: number) => {
    if (!ts) return '';
    const d = new Date(ts);
    const today = new Date();
    return d.toDateString() === today.toDateString()
      ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };
  const preview = (m: Message | null) => {
    if (!m) return t('hub.sayHi');
    const who = m.senderId === me.id ? 'You: ' : '';
    return who + (m.text || (m.attachments?.length ? '📎 Attachment' : (m.imageUrl ? '📷 Photo' : m.audioUrl ? '🎤 Voice note' : m.videoUrl ? '🎬 Video' : 'Message')));
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden animate-in fade-in duration-300">
      {/* top bar: search across ALL chats + add-person */}
      <div className="px-4 md:px-8 pt-4 pb-2 shrink-0 flex items-center gap-2 max-w-3xl w-full mx-auto">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 text-zinc-600 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={t('hub.searchAll')}
            className="w-full bg-[#121212] border border-white/10 rounded-2xl pl-10 pr-4 py-3 text-sm text-white outline-none focus:border-emerald-500/40 placeholder:text-zinc-700"
          />
        </div>
        <button
          onClick={onCopyInvite}
          disabled={inviteBusy}
          title="Copy your invite link — anyone who opens it gets a private chat with you"
          className="shrink-0 w-11 h-11 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 hover:bg-emerald-500/20 flex items-center justify-center transition-colors disabled:opacity-50">
          {inviteBusy ? <Loader2 className="w-5 h-5 animate-spin" /> : <UserPlus className="w-5 h-5" />}
        </button>
      </div>
      {copiedTip && (
        <div className="text-center text-[9px] font-black uppercase tracking-widest text-emerald-500 animate-in fade-in shrink-0 pb-1">{copiedTip}</div>
      )}

      <div className="flex-1 overflow-y-auto no-scrollbar px-4 md:px-8 pb-6 max-w-3xl w-full mx-auto">
        {hits !== null ? (
          hits.length === 0 ? (
            <div className="text-center text-[10px] text-zinc-600 italic py-12">{t('hub.noMatches')}</div>
          ) : (
            <div className="space-y-1 pt-1">
              <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em] px-1 pb-1">{t('hub.results')}</div>
              {hits.map(({ contact, message }, i) => (
                <button key={i} onClick={() => onOpenChat(contact.id)}
                  className="w-full flex items-center gap-3 p-3 rounded-2xl bg-black/40 border border-white/5 hover:border-emerald-500/40 transition-all text-left active:scale-[0.99]">
                  <Avatar pid={contact.id} name={contact.name} color={contact.color} avatarAt={contact.avatarAt} viewerNodeId={me.id} size={40} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-bold text-white truncate">{contact.name}</span>
                      <span className="text-[9px] text-zinc-600 font-mono shrink-0">{fmtTime(message?.timestamp)}</span>
                    </div>
                    <div className="text-[11px] text-zinc-500 truncate">{message ? preview(message) : 'Name matches'}</div>
                  </div>
                </button>
              ))}
            </div>
          )
        ) : rows.length === 0 && waitingContacts.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-center py-16 gap-4">
            <MessageCircle className="w-14 h-14 text-zinc-800" />
            <div>
              <div className="text-sm font-bold text-white mb-1">{t('hub.noChatsTitle')}</div>
              <p className="text-[11px] text-zinc-500 leading-relaxed max-w-xs">Tap the <UserPlus className="w-3 h-3 inline text-emerald-500" /> button to copy your invite link and send it to someone — once they accept, the chat appears here and you appear in their chats too.</p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {waitingContacts.map(c => (
              <div key={c.id} className="w-full flex items-center gap-3.5 py-3.5 px-1 opacity-60">
                <Avatar pid={c.id} name={c.name} color={c.color} avatarAt={c.avatarAt} viewerNodeId={me.id} size={48} circle />
                <div className="flex-1 min-w-0">
                  <span className="text-[15px] font-bold text-zinc-300 truncate block">{c.name}</span>
                  <span className="text-[11px] text-zinc-500 flex items-center gap-1.5"><Loader2 className="w-3 h-3 animate-spin text-emerald-600" /> {t('hub.waiting')}</span>
                </div>
              </div>
            ))}
            {rows.map(({ contact, last, unread }) => (
              <div key={contact.id} className="w-full flex items-center hover:bg-white/[0.03] transition-colors">
                <button onClick={() => onOpenChat(contact.id)}
                  className="flex-1 min-w-0 flex items-center gap-3.5 py-3.5 px-1 text-left active:scale-[0.995]">
                  <Avatar pid={contact.id} name={contact.name} color={contact.color} avatarAt={contact.avatarAt} viewerNodeId={me.id} size={48} circle className="shadow-lg" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`text-[15px] truncate ${unread ? 'font-black text-white' : 'font-bold text-zinc-200'}`}>{contact.name}</span>
                      <span className="text-[10px] text-zinc-600 shrink-0">{fmtTime(last?.timestamp)}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <span className={`text-[12px] truncate ${unread ? 'text-zinc-300 font-medium' : 'text-zinc-500'}`}>{preview(last)}</span>
                      {unread > 0 && (
                        <span className="shrink-0 min-w-[19px] h-[19px] px-1 rounded-full bg-emerald-500 text-black text-[10px] font-black flex items-center justify-center">{unread > 99 ? '99+' : unread}</span>
                      )}
                    </div>
                  </div>
                </button>
                {onOpenProfile && (
                  <button onClick={() => onOpenProfile({ pid: contact.id, name: contact.name, color: contact.color, avatarAt: contact.avatarAt })}
                    className="p-2 mr-1 rounded-lg text-zinc-600 hover:text-emerald-400 hover:bg-white/5 transition-colors shrink-0" title={`View ${contact.name}'s profile`} aria-label={`View ${contact.name}'s profile`}>
                    <Info className="w-4 h-4" />
                  </button>
                )}
                <ChevronRight className="w-4 h-4 text-zinc-700 shrink-0 mr-1" />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};


// Invitee group editor. Holds a LOCAL DRAFT so the UI updates instantly as you
// assign people; "Confirm" commits the whole draft in one call and surfaces any
// error instead of silently swallowing it. Keyed by PUBLIC node id throughout,
// matching what the server exposes and expects.
const GroupEditor: React.FC<{
  childrenNodes: User[];
  inviteeGroups: Record<string, string | string[]>;
  groupLabels: Record<string, string>;
  onClose: () => void;
  onCommit: (assignments?: Record<string, string | string[] | null>, labels?: Record<string, string | null>) => Promise<void>;
}> = ({ childrenNodes, inviteeGroups, groupLabels, onClose, onCommit }) => {
  // Local editable copies — seeded from server state, mutated freely, committed on
  // Confirm. Membership is a SET per member (string[]): a person can be in several
  // groups at once. Seed normalises whatever shape the server sent (scalar or array).
  const seed = () => { const o: Record<string, string[]> = {}; for (const k of Object.keys(inviteeGroups)) { const gs = gidsOf(inviteeGroups[k]); if (gs.length) o[k] = gs; } return o; };
  const [draftGroups, setDraftGroups] = useState<Record<string, string[]>>(seed);
  const [draftLabels, setDraftLabels] = useState<Record<string, string>>({ ...groupLabels });
  // NOTE: no prop-driven reseed. After Confirm, the draft IS the saved state —
  // reseeding from props here let a racing refresh overwrite the just-saved
  // edits (they "vanished" until reload). The draft seeds once on mount;
  // reopening the editor picks up fresh props naturally.
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const gids: string[] = [];
  for (const gid of Object.keys(draftLabels)) if (!gids.includes(gid)) gids.push(gid);
  for (const u of childrenNodes) for (const g of (draftGroups[u.id] || [])) if (!gids.includes(g)) gids.push(g);

  const dirty = JSON.stringify(draftGroups) !== JSON.stringify(seed()) ||
                JSON.stringify(draftLabels) !== JSON.stringify(groupLabels);

  const newGroup = () => {
    const label = (prompt('Name this group (e.g. "Team A"):') || '').trim();
    if (!label) return;
    const gid = 'g' + randToken(6);
    setDraftLabels(p => ({ ...p, [gid]: label })); setSaved(false);
  };
  const rename = (gid: string) => {
    const label = (prompt('Rename group:', draftLabels[gid] || '') || '').trim();
    if (!label) return;
    setDraftLabels(p => ({ ...p, [gid]: label })); setSaved(false);
  };
  const deleteGroup = (gid: string) => {
    // Remove this group from every member's set (members with no groups left drop
    // back to ungrouped), and drop its label.
    setDraftGroups(p => { const n: Record<string, string[]> = {}; for (const k of Object.keys(p)) { const rest = p[k].filter(g => g !== gid); if (rest.length) n[k] = rest; } return n; });
    setDraftLabels(p => { const n = { ...p }; delete n[gid]; return n; });
    setSaved(false);
  };
  const addMember = (childPubId: string, gid: string) => {
    setDraftGroups(p => { const cur = p[childPubId] || []; if (cur.includes(gid)) return p; return { ...p, [childPubId]: [...cur, gid] }; });
    setSaved(false);
  };
  const removeMember = (childPubId: string, gid: string) => {
    setDraftGroups(p => { const cur = (p[childPubId] || []).filter(g => g !== gid); const n = { ...p }; if (cur.length) n[childPubId] = cur; else delete n[childPubId]; return n; });
    setSaved(false);
  };

  const confirm = async () => {
    setBusy(true); setErr(null);
    try {
      // Send the FULL desired state: assignments for every invitee (null clears),
      // labels for every group (null deletes those removed).
      const assignments: Record<string, string | string[] | null> = {};
      for (const u of childrenNodes) { const gs = draftGroups[u.id] || []; assignments[u.id] = gs.length ? (gs.length === 1 ? gs[0] : gs) : null; }
      const labels: Record<string, string | null> = {};
      for (const gid of Object.keys(groupLabels)) labels[gid] = draftLabels[gid] || null; // deletions
      for (const gid of Object.keys(draftLabels)) labels[gid] = draftLabels[gid];           // adds/renames
      await onCommit(assignments, labels);
      setSaved(true);
      setTimeout(() => setSaved(false), 1500); // show confirmation, then reset — do NOT close
    } catch (e: any) {
      setErr(e?.message || 'Could not save groups. Please try again.');
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-[80] bg-black/70 backdrop-blur-sm flex items-end md:items-center justify-center p-0 md:p-6 animate-in fade-in" onClick={onClose}>
      <div className="bg-[#0e0e0e] border border-white/10 rounded-t-3xl md:rounded-3xl w-full md:max-w-lg max-h-[85vh] flex flex-col shadow-2xl animate-in slide-in-from-bottom-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-white/5 shrink-0">
          <div className="flex items-center gap-2"><Users className="w-5 h-5 text-emerald-500" /><h3 className="text-sm font-black uppercase tracking-widest text-white">Invitee Groups</h3></div>
          <button onClick={onClose} className="p-2 text-zinc-500 hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto no-scrollbar p-4 space-y-4">
          <p className="text-[11px] text-zinc-500 leading-relaxed">
            Split your invitees into groups that can't see or message each other. A person can be in one or more groups (they'll see every group they're in); ungrouped invitees share the default chat. Changes apply when you tap <span className="text-emerald-400 font-bold">Confirm</span>.
          </p>
          <button onClick={newGroup} className="w-full py-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px] font-black uppercase tracking-widest hover:bg-emerald-500/20 transition-colors">+ New group</button>

          {gids.map(gid => {
            const members = childrenNodes.filter(u => (draftGroups[u.id] || []).includes(gid));
            // People not yet in THIS group (they may already be in others) — the
            // Add dropdown lets you put someone in more than one group.
            const addable = childrenNodes.filter(u => !(draftGroups[u.id] || []).includes(gid));
            return (
              <div key={gid} className="rounded-2xl border border-white/10 bg-white/[0.02] p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-black uppercase tracking-widest text-emerald-400 truncate">{draftLabels[gid] || 'Group'}</span>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={() => rename(gid)} className="text-[9px] font-bold uppercase tracking-widest text-zinc-500 hover:text-white">Rename</button>
                    <button onClick={() => deleteGroup(gid)} className="text-[9px] font-bold uppercase tracking-widest text-zinc-500 hover:text-red-400">Delete</button>
                  </div>
                </div>
                <div className="space-y-1">
                  {members.map(u => {
                    const others = (draftGroups[u.id] || []).filter(g => g !== gid).map(g => draftLabels[g]).filter(Boolean);
                    return (
                    <div key={u.id} className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-black/30">
                      <div className="flex items-center gap-2 min-w-0">
                        <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: u.color }} />
                        <span className="text-xs text-zinc-300 truncate">{u.name}</span>
                        {others.length > 0 && <span className="text-[8px] font-bold uppercase tracking-wider text-emerald-500/60 shrink-0" title={`Also in: ${others.join(', ')}`}>+{others.length}</span>}
                      </div>
                      <button onClick={() => removeMember(u.id, gid)} className="text-[9px] font-bold uppercase tracking-widest text-zinc-600 hover:text-red-400 shrink-0">Remove</button>
                    </div>
                    );
                  })}
                  {members.length === 0 && <div className="text-[10px] text-zinc-700 italic px-2 py-1">No members yet — add below.</div>}
                  {addable.length > 0 && (
                    <select value="" onChange={e => { if (e.target.value) addMember(e.target.value, gid); }}
                      className="w-full mt-1 bg-black border border-white/10 rounded-lg text-[10px] text-zinc-400 py-1.5 px-2 outline-none focus:border-emerald-500/40">
                      <option value="">+ Add someone to this group…</option>
                      {addable.map(u => <option key={u.id} value={u.id}>{u.name}</option>)}
                    </select>
                  )}
                </div>
              </div>
            );
          })}

          <div className="rounded-2xl border border-white/5 bg-white/[0.01] p-3 space-y-2">
            <span className="text-[9px] font-black uppercase tracking-widest text-zinc-600">Ungrouped</span>
            <div className="space-y-1">
              {childrenNodes.filter(u => !(draftGroups[u.id] || []).length).map(u => (
                <div key={u.id} className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-black/20 gap-2">
                  <div className="flex items-center gap-2 min-w-0"><div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: u.color }} /><span className="text-xs text-zinc-300 truncate">{u.name}</span></div>
                  {gids.length > 0 ? (
                    <select value="" onChange={e => { if (e.target.value) addMember(u.id, e.target.value); }}
                      className="shrink-0 bg-black border border-white/10 rounded-lg text-[10px] text-zinc-300 py-1 px-1.5 outline-none focus:border-emerald-500/40">
                      <option value="">Assign…</option>
                      {gids.map(gid => <option key={gid} value={gid}>{draftLabels[gid] || 'Group'}</option>)}
                    </select>
                  ) : <span className="text-[9px] text-zinc-700 italic shrink-0">Make a group first</span>}
                </div>
              ))}
              {childrenNodes.filter(u => !(draftGroups[u.id] || []).length).length === 0 && <div className="text-[10px] text-zinc-700 italic px-2 py-1">Everyone is grouped.</div>}
            </div>
          </div>

          {err && <div className="text-[11px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-xl px-3 py-2">{err}</div>}
        </div>

        <div className="p-4 border-t border-white/5 shrink-0 flex items-center gap-3">
          <button onClick={onClose} className="flex-1 py-3 rounded-xl bg-white/5 text-zinc-400 text-[11px] font-black uppercase tracking-widest hover:bg-white/10 transition-colors">Cancel</button>
          <button onClick={confirm} disabled={busy || !dirty}
            className={`flex-[2] py-3 rounded-xl text-[11px] font-black uppercase tracking-widest transition-colors ${saved ? 'bg-emerald-600 text-white' : dirty ? 'bg-emerald-500 text-black hover:bg-emerald-400' : 'bg-white/5 text-zinc-600'}`}>
            {busy ? 'Saving…' : saved ? '✓ Saved' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
};

const Dashboard: React.FC<DashboardProps> = ({ state, onLogout, onSendMessage, onPrune, onTogglePermissions, onUpdateTreeSettings, typingPeers, onReact, onTyping, notifPermission, onEnableNotifications, pushEnabled, billingAlert, onDismissBillingAlert, callState, callActions, onPanicWipe, joinRequests, onRespondJoin, onAcknowledge, onDeleteTree, onDeleteForMe, onDeleteForAll, onSetGroups, onMoveNode, onUpdateColor, onUpdateName, onUpdateProfile, onHubConnect }) => {
  const t = useT();
  const { locale } = useLocale();
  const { currentUser, users, invites } = state;
  const acksMap = state.acks || {};
  const reactionsMap = state.reactions || {};
  // Attach acknowledgments (sender view) and reactions to each message so the
  // bubbles can render them.
  // safety-number verify modal; reTrusted = senders re-trusted this session
  const [verifyPeer, setVerifyPeer] = useState<User | null>(null);
  const [verifySafety, setVerifySafety] = useState<string | null | 'loading'>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [reTrusted, setReTrusted] = useState<Set<string>>(new Set());
  const messages = useMemo(() => {
    const hasAcks = Object.keys(acksMap).length > 0;
    const hasReactions = Object.keys(reactionsMap).length > 0;
    const hasReTrust = reTrusted.size > 0;
    if (!hasAcks && !hasReactions && !hasReTrust) return state.messages;
    return state.messages.map(m => {
      const mid = m.id;
      const a = mid ? acksMap[mid] : undefined;
      const r = mid ? reactionsMap[mid] : undefined;
      const rt = hasReTrust && m.keyChanged && reTrusted.has(m.senderId);
      if (!a && !r && !rt) return m;
      // v71: re-trusting a key clears the key-change warning; it restores the
      // verified mark ONLY for messages that passed every other check at ingest
      // (content binding + membership) — it never promotes an unverified message.
      return { ...m, ...(a ? { acks: a } : {}), ...(r ? { reactions: r } : {}), ...(rt ? { keyChanged: false, verified: !!m.verifiedIfKeyOk } : {}) };
    });
  }, [state.messages, acksMap, reactionsMap, reTrusted]);
  const [activeTab, setActiveTab] = useState<'ANCESTORS' | 'DESCENDANTS' | 'BROADCAST' | 'GLOBAL' | 'HIERARCHY' | 'MONITOR' | 'HOWTO' | 'SETTINGS'>(() => (readStartTab(currentUser?.id) as any) || 'DESCENDANTS');
  // Dropdown value for the "Screen on start" setting (default: Descendants).
  const [startTab, setStartTab] = useState<string>(() => readStartTab(currentUser?.id) || 'DESCENDANTS');
  const [messageText, setMessageText] = useState('');
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  // Edit mode: when set, the composer is editing an already-sent message; on send
  // we dispatch an edit that carries the original mid and replaces its text.
  const [editingMsg, setEditingMsg] = useState<Message | null>(null);
  const EDIT_WINDOW_MS = 15 * 60 * 1000; // messages editable for 15 minutes
  // Scheduled messages: a compose-time picker sets a future fire time; a poller
  // dispatches due items through the normal send path. Held locally only.
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [scheduleAt, setScheduleAt] = useState<string>('');
  const [pendingScheduled, setPendingScheduled] = useState<scheduledStore.ScheduledMessage[]>([]);
  const refreshScheduled = useCallback(() => {
    // The list lives in the sealed local store (V8 M-12), which unseals asynchronously.
    if (currentUser) sealedLocal.init().then(() => setPendingScheduled(scheduledStore.listScheduled(currentUser.id)));
  }, [currentUser]);
  // Broadcast ack dashboard: my sent announcements that requested acknowledgment,
  // with who has acknowledged so far (a compact matrix).
  const [ackDashOpen, setAckDashOpen] = useState(false);
  const ackDashboard = useMemo(() => {
    if (!currentUser) return [];
    const acksMap = state.acks || {};
    return messages
      .filter(m => m.type === 'BROADCAST' && m.senderId === currentUser.id && m.ackRequested)
      .sort((a, b) => b.timestamp - a.timestamp)
      .map(m => ({
        id: m.id,
        timestamp: m.timestamp,
        text: (m.text || '📎 Announcement').slice(0, 80),
        acked: (acksMap[m.id] || []).map(a => ({ name: a.name, ts: a.ts })),
      }));
  }, [messages, state.acks, currentUser]);
  // Drafts: an unsent message is preserved per conversation so switching chats
  // (or reloading) never loses what you were typing. Keyed by node + tab +
  // opened contact so each thread keeps its own draft.
  const convKeyRef = useRef<string>('');
  const draftKey = (tab: string, filterId: string | null) => `arbor_draft_${currentUser?.id || 'x'}_${tab}_${filterId || 'all'}`;
  const draftRestored = useRef(false);
  const [reqAck, setReqAck] = useState(false); // broadcast: request acknowledgments
  const [ackedMids, setAckedMids] = useState<Set<string>>(new Set()); // local sent-state
  const [imagePayloads, setImagePayloads] = useState<string[]>([]);
  const [audioPayload, setAudioPayload] = useState<string | null>(null);
  const [videoPayload, setVideoPayload] = useState<string | null>(null);
  // Send button only appears once there's something to send (text or media).
  const hasSendContent = messageText.trim().length > 0 || imagePayloads.length > 0 || !!audioPayload || !!videoPayload;
  // Strip location/EXIF/device metadata from outgoing media.
  // OFF: send as-is. STANDARD (the default): images re-encoded; MP4/MOV video gets
  // the full, re-audited scrub (every metadata box at every level, metadata tracks,
  // capture times, handler names — V8 H-7/M-5); anything unscrubbable is blocked
  // (V8 M-4). DEEP: the same, plus voice notes re-synthesized to fresh PCM WAV.
  const [scrubMeta, setScrubMeta] = useState<'OFF' | 'STANDARD' | 'DEEP'>('STANDARD');
  const [mediaBusy, setMediaBusy] = useState(false);
  const [scrubNote, setScrubNote] = useState<string | null>(null);
  // Biometric app-lock availability/state (Settings panel).
  const [bioAvailable, setBioAvailable] = useState(false);
  const [bioEnabled, setBioEnabled] = useState(appLock.isEnabled());
  // v70 H5: turning App Lock on seals the account key under the authenticator's
  // PRF secret, which needs the password once (the in-memory key can't be exported).
  const [bioSetup, setBioSetup] = useState(false);
  const [bioPw, setBioPw] = useState('');
  const [bioBusy, setBioBusy] = useState(false);
  const [bioErr, setBioErr] = useState<string | null>(null);
  useEffect(() => { appLock.platformAuthenticatorAvailable().then(setBioAvailable); }, []);
  // In-chat search over the locally decrypted history (the server can't search
  // ciphertext — searching happens entirely on this device).
  const [searchOpen, setSearchOpen] = useState(false);
  // Message selection (delete for me / for everyone).
  const [selecting, setSelecting] = useState(false);
  const [selectedMsgs, setSelectedMsgs] = useState<Set<string>>(new Set());
  const toggleSelect = useCallback((id: string) => setSelectedMsgs(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; }), []);
  const enterSelect = useCallback((id: string) => { setSelecting(true); setSelectedMsgs(new Set([id])); }, []);
  // Long-press opens a small action sheet (Info / Pin / Select) instead of jumping
  // straight into selection mode.
  const [actionSheetMid, setActionSheetMid] = useState<string | null>(null);
  const [infoMid, setInfoMid] = useState<string | null>(null);
  // One pinned message per conversation, remembered locally per conversation key.
  const convKey = `arbor_pin_${activeTab}`;
  const [pinnedMid, setPinnedMid] = useState<string | null>(null);
  useEffect(() => {
    try { setPinnedMid(localStorage.getItem(convKey)); } catch { setPinnedMid(null); }
  }, [convKey]);
  const pinMessage = useCallback((id: string | null) => {
    setPinnedMid(id);
    try { if (id) localStorage.setItem(convKey, id); else localStorage.removeItem(convKey); } catch {}
  }, [convKey]);
  const exitSelect = useCallback(() => { setSelecting(false); setSelectedMsgs(new Set()); }, []);
  // Whether every selected message was sent by me (gate for delete-for-everyone).
  const allSelectedMine = useMemo(() => {
    if (!currentUser || selectedMsgs.size === 0) return false;
    for (const id of selectedMsgs) { const m = messages.find(x => x.id === id); if (!m || m.senderId !== currentUser.id) return false; }
    return true;
  }, [selectedMsgs, messages, currentUser]);
  const [searchQuery, setSearchQuery] = useState('');
  // Unread badges: purely client-side — last-seen timestamps per conversation.
  // Focused contact in Descendants / the open personal chat (hoisted above the
  // read-marker effect that depends on it).
  const [activeFilterId, setActiveFilterId] = useState<string | null>(null);
  const [groupEditorOpen, setGroupEditorOpen] = useState(false);
  // Descendants group chat scope: null = default chat (ungrouped invitees);
  // a group id = that group's isolated chat. Only meaningful for the inviter.
  const [activeGroupId, setActiveGroupId] = useState<string | null>(null);

  // Save the current draft when leaving a conversation, restore when entering.
  // Drafts live in the SEALED local store (AES-GCM under the account wrap key),
  // never plaintext localStorage (V8 M-12).
  useEffect(() => {
    const key = draftKey(activeTab, activeFilterId);
    // On conversation switch: flush the previous draft, then load the new one.
    if (convKeyRef.current && convKeyRef.current !== key) {
      if (messageText.trim()) sealedLocal.set(convKeyRef.current, messageText);
      else sealedLocal.remove(convKeyRef.current);
    }
    convKeyRef.current = key;
    if (activeTab === 'ANCESTORS' || activeTab === 'DESCENDANTS' || activeTab === 'BROADCAST') {
      let cancelled = false;
      sealedLocal.init().then(() => {
        if (cancelled || convKeyRef.current !== key) return;
        draftRestored.current = true;
        setComposer(sealedLocal.get(key) || '');
      });
      return () => { cancelled = true; };
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, activeFilterId, currentUser?.id]);

  // Persist keystrokes to the active draft (in memory; sealed + written in the
  // background by sealedLocal).
  useEffect(() => {
    if (!draftRestored.current) return;
    const key = convKeyRef.current;
    if (!key) return;
    if (messageText.trim()) sealedLocal.set(key, messageText);
    else sealedLocal.remove(key);
  }, [messageText]);

  const [lastSeen, setLastSeen] = useState<Record<string, number>>(() => {
    try { return JSON.parse(localStorage.getItem(`arbor_seen_${currentUser?.id}`) || '{}'); } catch { return {}; }
  });
  // Baseline for a chat we have NO saved read-mark for. Using the app's load time
  // (not 0) means opening the app never floods every never-opened chat with its
  // whole backlog as "unread" — only messages that actually arrive while you're
  // here count. Chats you HAVE opened keep their saved mark, so real unread
  // (including messages that landed while you were away) still shows.
  const firstLoadRef = useRef(Date.now());
  useEffect(() => {
    // Which conversation bucket is on screen — mark exactly that one seen so its
    // badge clears (and stays clear while new messages arrive as you watch).
    let key: string | null = null;
    if (activeTab === 'ANCESTORS') key = activeGroupId ? `AG:${activeGroupId}` : 'ANCESTORS';
    else if (activeTab === 'BROADCAST') key = 'BROADCAST';
    else if (activeTab === 'GLOBAL') key = 'GLOBAL';
    else if (activeTab === 'DESCENDANTS') {
      if (activeFilterId) key = `C:${activeFilterId}`;
      else if (activeGroupId) key = `G:${activeGroupId}`;
      else key = 'DESCENDANTS';
    }
    if (!key) return;
    setLastSeen(prev => {
      const next = { ...prev, [key!]: Date.now() };
      try { localStorage.setItem(`arbor_seen_${currentUser?.id}`, JSON.stringify(next)); } catch {}
      return next;
    });
  }, [activeTab, activeFilterId, activeGroupId, messages.length, currentUser?.id]);
  // Per-bucket unread counts. Every conversation gets its own last-seen key so
  // badges show EVERYWHERE — not just Descendants: the main descendants chat, each
  // sub-group, each linked chat, Announcements, Global, and Ancestors. The
  // Descendants nav badge is a rollup (main + all its groups + all its links).
  const unread = useMemo(() => {
    const res: Record<string, number> = {};
    if (!currentUser) return res;
    const now = Date.now();
    const bump = (k: string | null, ts: number) => { if (!k) return; const base = (k in lastSeen) ? lastSeen[k] : firstLoadRef.current; if (ts > base) res[k] = (res[k] || 0) + 1; };
    const linkIds = linkChatIds(currentUser, users);
    const isLinkId = (id: string) => linkIds.has(id);
    for (const m of messages) {
      if (m.senderId === currentUser.id) continue;
      if (m.expiresAt && m.expiresAt <= now) continue;
      if (m.type === 'BROADCAST') { bump('BROADCAST', m.timestamp); continue; }
      if (m.type === 'GLOBAL') { bump('GLOBAL', m.timestamp); continue; }
      if (m.type !== 'PEER') continue;
      const sender = users.find(u => u.id === m.senderId);
      if (!sender) continue;
      if (currentUser.treeMode === 'HUB') { bump(`C:${sender.id}`, m.timestamp); continue; }
      const tg = (m as any).targetGroup as string | undefined;
      // Linked cross-group chat — its own bucket (keyed by link id).
      if (tg && isLinkId(tg)) { bump(`G:${tg}`, m.timestamp); continue; }
      // A direct invitee replying UP → my Descendants side. In a 1:1 (DM) network
      // each invitee is its OWN conversation, so bucket per-invitee (`C:<id>`) to
      // match how the view marks it seen (dirKey `C:<id>`) — that's what lets each
      // invitee row carry its own unread badge. In a hierarchical network it's the
      // shared descendants chat (or the invitee's group).
      if (sender.invitedBy === currentUser.id && m.targetCircle === 'UP') {
        if (currentUser.treeMode === 'DM') { bump(`C:${sender.id}`, m.timestamp); continue; }
        // Tagged to one of my groups → that group's chat; untagged → the main chat.
        bump(tg ? `G:${tg}` : 'DESCENDANTS', m.timestamp);
        continue;
      }
      // Ancestor circle: my inviter talking DOWN, or a sibling talking UP — in the
      // main Ancestors chat, or (tagged) in one of my groups' chats under it.
      const isInviter = sender.id === currentUser.invitedBy;
      const isSibling = sender.invitedBy === currentUser.invitedBy && !!currentUser.invitedBy;
      if ((isInviter && m.targetCircle === 'DOWN') || (isSibling && m.targetCircle === 'UP')) { bump(tg ? `AG:${tg}` : 'ANCESTORS', m.timestamp); continue; }
    }
    // Descendants rollup = the main chat + every group + every link under it (and,
    // in a 1:1 network, every per-invitee conversation).
    let descTotal = res['DESCENDANTS'] || 0;
    for (const k of Object.keys(res)) if (k.startsWith('G:') || (currentUser.treeMode === 'DM' && k.startsWith('C:'))) descTotal += res[k];
    res['DESCENDANTS_TOTAL'] = descTotal;
    // Ancestors rollup = the main chat + every group chat I'm in under it.
    let ancTotal = res['ANCESTORS'] || 0;
    for (const k of Object.keys(res)) if (k.startsWith('AG:')) ancTotal += res[k];
    res['ANCESTORS_TOTAL'] = ancTotal;
    return res;
  }, [messages, users, currentUser, lastSeen]);

  // Read receipts (optional): when ON, viewing a chat tells senders their
  // messages were seen. Content-free — only opaque message ids travel.
  const [receiptsOn, setReceiptsOn] = useState(() => { try { return localStorage.getItem('arbor_receipts') !== '0'; } catch { return true; } });
  const [notifyPref, setNotifyPref] = useState<'all' | 'mentions' | 'alias'>('all');
  const [recoveryStatus, setRecoveryStatus] = useState<boolean | null>(null);
  const [settingsBusy, setSettingsBusy] = useState(false);
  // Load the server-side read-receipt setting once (it's now reciprocal, so the
  // server is the source of truth). Also fetch whether a recovery phrase exists.
  useEffect(() => {
    if (!currentUser) return;
    api.getSettings().then(s => {
      setReceiptsOn(s.readReceipts);
      if (s.notifyPref) setNotifyPref(s.notifyPref);
      try { localStorage.setItem('arbor_receipts', s.readReceipts ? '1' : '0'); } catch {}
    }).catch(() => {});
    api.recoveryStatus().then(r => setRecoveryStatus(r.hasRecovery)).catch(() => setRecoveryStatus(null));
  }, [currentUser?.id]);
  const updateNotifyPref = async (pref: 'all' | 'mentions' | 'alias') => {
    const prev = notifyPref; setNotifyPref(pref);
    try { await api.updateSettings({ notifyPref: pref }); } catch { setNotifyPref(prev); }
  };

  const toggleReceipts = async (on: boolean) => {
    setSettingsBusy(true);
    setReceiptsOn(on);
    try { localStorage.setItem('arbor_receipts', on ? '1' : '0'); } catch {}
    try { await api.updateSettings({ readReceipts: on }); }
    catch { setReceiptsOn(!on); }  // revert on failure
    setSettingsBusy(false);
  };
  const receiptsSent = useRef<Set<string>>(new Set());

  // Permanent invite QR: scan -> open the app with the code prefilled -> add to
  // Home Screen. The code stays stable until rotated.
  const [callMinimized, setCallMinimized] = useState(false);
  // Speakerphone. Strategy: setSinkId where available (desktop/Android Chrome);
  // WebAudio loudspeaker routing otherwise (iOS). The button shows everywhere.
  const [speakerOn, setSpeakerOn] = useState(false);
  const [speakerSink, setSpeakerSink] = useState<string | null>(null);
  const sinkSupported = typeof HTMLMediaElement !== 'undefined' && 'setSinkId' in HTMLMediaElement.prototype;
  useEffect(() => { if (callState.phase === 'idle') { setSpeakerOn(false); } }, [callState.phase]);
  const toggleSpeaker = async () => {
    if (speakerOn) { setSpeakerOn(false); return; }
    if (sinkSupported) {
      // Enumerate DURING the call: labels only populate once mic permission is live.
      const sink = await findSpeakerSinkId();
      setSpeakerSink(sink); // null -> element default; WebAudio path still applies below
    }
    setSpeakerOn(true);
  };
  useEffect(() => { if (callState.phase === 'idle' || callState.phase === 'incoming') setCallMinimized(false); }, [callState.phase]);
  const [permQr, setPermQr] = useState<{ code: string; dataUrl: string; link: string } | null>(null);
  const [qrBusy, setQrBusy] = useState(false);
  const [sideTip, setSideTip] = useState<string | null>(null);
  const sideTipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flashSideTip = (t: string) => { setSideTip(t); if (sideTipTimer.current) clearTimeout(sideTipTimer.current); sideTipTimer.current = setTimeout(() => setSideTip(null), 2500); };
  const loadPermQr = async (rotate = false): Promise<boolean> => {
    if (!currentUser) return false;
    // DM/hub non-roots normally can't invite — the server rejects with 403; don't
    // even ask. The exception is a DM tree in referral mode, where members MAY
    // mint a code (their joiners are re-parented to the root server-side).
    if ((currentUser.treeMode === 'DM' || currentUser.treeMode === 'HUB') && currentUser.role !== 'ROOT'
        && !(currentUser.treeMode === 'DM' && currentUser.referralOpen)) return false;
    setQrBusy(true);
    try {
      const { code, link } = await api.getPermanentInvite(currentUser.id, rotate, undefined, currentUser);
      const dataUrl = await QRCode.toDataURL(link, { width: 480, margin: 2, color: { dark: '#10b981', light: '#00000000' } });
      setPermQr({ code, dataUrl, link });
      setQrBusy(false);
      return true;
    } catch (e) {
      try { console.warn('[qr] load failed:', e); } catch {}
      setQrBusy(false);
      return false;
    }
  };
  // A single failed attempt (fresh-login race, proxy blip) used to leave the QR
  // missing until a manual reload. Retry with backoff; a Retry button covers the rest.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const tryLoad = async (attempt: number) => {
      if (cancelled) return;
      const ok = await loadPermQr(false);
      if (!ok && !cancelled && attempt < 4) timer = setTimeout(() => tryLoad(attempt + 1), 1500 * Math.pow(2, attempt));
    };
    setPermQr(null);
    tryLoad(0);
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
    // eslint-disable-next-line
  }, [currentUser?.id]);

  // Personal-hub invite: the person-plus button copies the permanent invite
  // link; anyone who opens it lands in the join flow and, once accepted, gets a
  // private chat with you (and you appear in THEIR Personal Chats).
  const [hubInviteBusy, setHubInviteBusy] = useState(false);
  const [hubTip, setHubTip] = useState<string | null>(null);
  const hubTipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flashHubTip = (t: string) => { setHubTip(t); if (hubTipTimer.current) clearTimeout(hubTipTimer.current); hubTipTimer.current = setTimeout(() => setHubTip(null), 3000); };
  const copyHubInvite = async () => {
    if (!currentUser || hubInviteBusy) return;
    setHubInviteBusy(true);
    try {
      let link = permQr?.link;
      if (!link) { const r = await api.getPermanentInvite(currentUser.id, false, undefined, currentUser); link = r.link; }
      try {
        await navigator.clipboard.writeText(link);
        flashHubTip('Invite link copied — send it to anyone');
      } catch {
        prompt('Copy your invite link:', link);
      }
    } catch {
      flashHubTip('Could not fetch your invite code — try again');
    }
    setHubInviteBusy(false);
  };

  // First-run pointer to the How-To guide.
  const [showHowtoPrompt, setShowHowtoPrompt] = useState(() => {
    try { return !localStorage.getItem('arbor_howto_seen'); } catch { return false; }
  });
  const dismissHowtoPrompt = (goRead: boolean) => {
    try { localStorage.setItem('arbor_howto_seen', '1'); } catch {}
    setShowHowtoPrompt(false);
    if (goRead) setActiveTab('HOWTO');
  };
  // Transient helper tips for composer controls (auto-clear).
  const tipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flashTip = (text: string) => {
    setScrubNote(text);
    if (tipTimer.current) clearTimeout(tipTimer.current);
    tipTimer.current = setTimeout(() => setScrubNote(null), 5000);
  };
  const [ttlSeconds, setTtlSeconds] = useState<number>(0); // 0 = off (no disappear)
  const [isRecording, setIsRecording] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordChunksRef = useRef<Blob[]>([]);
  // Live mic level while recording: a Web Audio analyser taps the same input
  // stream (never connected to output, so no echo). The <RecordingMeter> child
  // reads this analyser on its own rAF so only the meter re-renders.
  const recAnalyserRef = useRef<AnalyserNode | null>(null);
  const recAudioCtxRef = useRef<AudioContext | null>(null);
  // Amplitude envelope sampled ~18×/sec across the whole recording, so the SENT
  // bubble shows the real waveform (not a re-decode that may fail on some formats).
  const recEnvelopeRef = useRef<number[]>([]);
  const recSampleTimerRef = useRef<number | null>(null);
  const recStartRef = useRef<number>(0);
  const [audioPeaks, setAudioPeaks] = useState<number[] | null>(null);
  const [audioDurMs, setAudioDurMs] = useState<number | null>(null);
  const stopMeter = useCallback(() => {
    if (recSampleTimerRef.current != null) { clearInterval(recSampleTimerRef.current); recSampleTimerRef.current = null; }
    try { recAudioCtxRef.current?.close(); } catch {}
    recAudioCtxRef.current = null; recAnalyserRef.current = null;
  }, []);
  useEffect(() => () => stopMeter(), [stopMeter]); // tear down on unmount
  const [isSending, setIsSending] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  
  // DUAL BROADCAST FILTERS
  // Announcement reach: 'ALL' = whole subtree, or an explicit set of branch
  // roots picked on the mini-tree (picking a node includes its entire branch).
  const [annTargets, setAnnTargets] = useState<'ALL' | Set<string>>('ALL');
  const [annOpen, setAnnOpen] = useState(false); // announcement reach picker: tap to expand the tree
  const [selectedMonitorNodeId, setSelectedMonitorNodeId] = useState<string | null>(null);
  // Profile info view (opened by the ⓘ button in the tree / Direct Links).
  const [profileTarget, setProfileTarget] = useState<{ pid: string; name?: string; color?: string; avatarAt?: number; isMe?: boolean } | null>(null);
  // Which of the monitored person's chats to view: null = All, 'MAIN' = ungrouped
  // descendants chat, or a specific group id of theirs.
  const [monGroup, setMonGroup] = useState<string | null>(null);
  useEffect(() => { setMonGroup(null); }, [selectedMonitorNodeId]);

  const scrollRef = useRef<HTMLDivElement>(null);

  // Jump-to-reply: scroll a quoted message into view and flash it. If the
  // original has scrolled out of the virtualized window it may not be mounted;
  // we still try, and no-op gracefully when it isn't present.
  const jumpToMessage = useCallback((mid: string) => {
    const el = document.getElementById(`msg-${mid}`);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.classList.add('reply-flash');
    setTimeout(() => el.classList.remove('reply-flash'), 1200);
  }, []);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageInputRef = useRef<HTMLTextAreaElement>(null);
  // Set the composer text. The textarea is controlled by messageText, so this is
  // just the state setter (kept as a named helper so call sites read clearly).
  const setComposer = useCallback((text: string) => setMessageText(text), []);
  // Whether this is a touch-first device (mobile). On mobile, Return inserts a
  // newline; on desktop, Enter sends and Shift+Enter inserts a newline.
  const isCoarsePointer = typeof window !== 'undefined' && !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
  // Captured on the send button's pointerdown (BEFORE it steals focus) so that
  // tapping Send while the composer was collapsed keeps it collapsed instead of
  // popping the keyboard back up.
  const keepFocusRef = useRef(false);
  // Keep the auto-growing composer's height in sync with its content — most
  // Auto-grow the composer with its content (up to a cap), and collapse it back to
  // one row after the text is cleared on send.
  useEffect(() => {
    const el = messageInputRef.current;
    if (!el) return;
    if (!messageText) { el.style.height = 'auto'; return; }
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  }, [messageText]);
  // On mobile the on-screen keyboard is tied to input focus. We keep the bar
  // focused after sending so the keyboard stays up for the next message, and
  // allow an explicit swipe-down on the composer to dismiss it.
  const composerTouchStart = useRef<number | null>(null);

  const atBottomRef = useRef(true);
  // Full conversation identity — tab AND which group / contact is open. ANY change
  // means we just ENTERED a chat, which must always land on the newest message.
  const prevConvRef = useRef<string>('');
  // useLayoutEffect (not useEffect): pin to the bottom BEFORE the browser paints, so
  // the first frame of a freshly-entered chat is already at the newest message. As a
  // useEffect this ran AFTER paint, so the list flashed at the TOP first — bringing the
  // oldest messages' media into view just long enough to fire their loading spinners —
  // before jumping down. Pre-paint pinning keeps that top media off-screen entirely.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el || ['HIERARCHY', 'MONITOR', 'HOWTO', 'SETTINGS'].includes(activeTab)) return;
    const convKey = `${activeTab}|${activeGroupId || ''}|${activeFilterId || ''}`;
    const convChanged = prevConvRef.current !== convKey;
    prevConvRef.current = convKey;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    // Entering a chat (tab / group / contact switch) or a big first-load jump → land
    // instantly at the very bottom, and re-assert next frame in case late layout
    // (wrapped text, attachment cards) shifted the height. For a normal new message
    // while already at the bottom, SMOOTH-glide so the list follows it. If the user
    // has scrolled up to read history, don't yank them — the "new below" pill covers it.
    if (convChanged || distance > 1200) {
      // Pin to the very bottom, then re-assert across the next few frames and once
      // more after a beat — late layout (wrapped text, attachment/voice cards that
      // size after mount) keeps growing the list, so a single set lands short.
      const pin = () => { const e2 = scrollRef.current; if (e2) e2.scrollTop = e2.scrollHeight; };
      pin();
      requestAnimationFrame(pin);
      requestAnimationFrame(() => requestAnimationFrame(pin));
      setTimeout(pin, 60);
      setTimeout(pin, 180);
      return;
    }
    if (atBottomRef.current) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [messages.length, activeTab, activeGroupId, activeFilterId, isSending]);

  // Leaving search (closing it, or clearing the query) must land the view on
  // the MOST RECENT messages — the filtered list left scrollTop near the top,
  // which previously stranded people at the oldest history after searching.
  useEffect(() => {
    if (searchOpen && searchQuery.trim()) return; // actively browsing matches
    const el = scrollRef.current;
    if (el && !['HIERARCHY', 'MONITOR', 'HOWTO', 'SETTINGS'].includes(activeTab)) {
      requestAnimationFrame(() => { el.scrollTop = el.scrollHeight; });
    }
  }, [searchOpen, searchQuery]);

  // Resolve the 1:1 target for the current conversation (DM/hub/opened contact).
  const resolveTargetUserId = (): string | undefined => {
    if (currentUser?.treeMode === 'DM' || currentUser?.treeMode === 'HUB') {
      if (activeTab === 'ANCESTORS') return currentUser.invitedBy || undefined;
      if (activeTab === 'DESCENDANTS') return activeFilterId || undefined;
    }
    return undefined;
  };

  const [scheduling, setScheduling] = useState(false);
  const scheduleMessage = async () => {
    if (!currentUser || !messageText.trim() || !scheduleAt || scheduling) return;
    const fireAt = new Date(scheduleAt).getTime();
    if (!isFinite(fireAt)) return;
    if (fireAt <= Date.now() + 60_000) { alert('Pick a time at least a minute in the future.'); return; }
    if (activeTab !== 'ANCESTORS' && activeTab !== 'DESCENDANTS' && activeTab !== 'BROADCAST') return;
    const targetUserId = resolveTargetUserId();
    if ((currentUser.treeMode === 'DM' || currentUser.treeMode === 'HUB') && activeTab === 'DESCENDANTS' && !targetUserId) {
      alert('Open a chat first.'); return;
    }
    const text = messageText.trim();
    const type = activeTab === 'BROADCAST' ? 'BROADCAST' : 'PEER';
    const tCircle = activeTab === 'ANCESTORS' ? 'UP' : activeTab === 'DESCENDANTS' ? 'DOWN' : undefined;
    setScheduling(true);
    try {
      // Seal + hand the ciphertext to the server now; it releases at fireAt even
      // if this device is off. Plaintext stays only in the local pending store.
      // Group scope rides along (it used to be dropped, filing a scheduled group
      // message into the default chat — the gap noted in V8 M-13).
      const schedGroup = (activeTab === 'ANCESTORS' && activeGroupId) ? activeGroupId
        : (activeTab === 'DESCENDANTS' && activeGroupId && tCircle === 'DOWN') ? activeGroupId : undefined;
      const { id: serverId, mid } = await api.scheduleMessage(currentUser, text, fireAt, type as Message['type'], tCircle, targetUserId, activeTab === 'BROADCAST' ? reqAck : undefined, schedGroup);
      const peerName = targetUserId ? (usersById.get(targetUserId)?.name || undefined) : undefined;
      scheduledStore.addScheduled({
        nodeId: currentUser.id, serverId, mid, fireAt, text,
        tab: activeTab as 'ANCESTORS' | 'DESCENDANTS' | 'BROADCAST', targetUserId, peerName,
      });
      setComposer('');
      sealedLocal.remove(convKeyRef.current);
      setScheduleOpen(false);
      refreshScheduled();
      flashTip(`Scheduled for ${new Date(fireAt).toLocaleString()} — it will send even if the app is closed.`);
    } catch (e: any) {
      alert('Could not schedule: ' + (e?.message || e));
    } finally { setScheduling(false); }
  };

  const handleSend = async () => {
    // Only restore focus after sending if the composer was ALREADY focused (user
    // was typing / keyboard up). If they tapped Send with the bar collapsed, leave
    // it collapsed — don't yank the keyboard back up. keepFocusRef is set on the
    // button's pointerdown before it steals focus; the direct check covers Enter.
    const keepFocus = document.activeElement === messageInputRef.current || keepFocusRef.current;
    keepFocusRef.current = false;
    // Edit path: replace the text of a previously-sent own message. The edit is
    // delivered as an encrypted message carrying editsMid; recipients apply it.
    if (editingMsg) {
      const newText = messageText.trim();
      const target = editingMsg;
      if (!newText || newText === (target.text || '')) { setEditingMsg(null); setComposer(''); return; }
      setComposer(''); stopTypingLocal();
      setEditingMsg(null);
      sealedLocal.remove(convKeyRef.current);
      const isPeer = target.type === 'PEER';
      const tCircle = isPeer ? (target.targetCircle as 'UP' | 'DOWN' | undefined) : undefined;
      const tUser = (currentUser?.treeMode === 'DM' || currentUser?.treeMode === 'HUB') ? (target.peerId || undefined) : undefined;
      try {
        await onSendMessage({ text: newText, editsMid: target.id }, target.type, undefined,
          isPeer ? undefined : (annTargets !== 'ALL' ? Array.from(annTargets) : undefined), tCircle, tUser);
      } catch { setEditingMsg(target); setComposer(target.text || ''); }
      if (keepFocus) messageInputRef.current?.focus();
      return;
    }
    if (!messageText.trim() && imagePayloads.length === 0 && !audioPayload && !videoPayload) return;
    const type = activeTab === 'BROADCAST' ? 'BROADCAST' : activeTab === 'GLOBAL' ? 'GLOBAL' : 'PEER';
    // A linked cross-group chat I'm only a MEMBER of (the link lives on my inviter)
    // is posted UP; one I own is posted DOWN like a normal group chat.
    // A CROSS-LEVEL channel (root-owned, spans compartments) is routed by its
    // participant set, so direction doesn't matter — we just tag it and send.
    const crossLink = activeTab === 'DESCENDANTS' && !!activeGroupId && !!(((currentUser as any)?.crossLinks || {})[activeGroupId]);
    const memberLink = activeTab === 'DESCENDANTS' && !!activeGroupId && !crossLink
      && !((currentUser?.groupLinks || {}) as any)[activeGroupId]
      && !!(((users.find(u => u.id === currentUser?.invitedBy) as any)?.myLinks || {})[activeGroupId]);
    // A group on another branch I'm a cross-level VISITOR of — I post into it tagged
    // with the group id; the server routes it to that group's channel.
    const visitingGroup = activeTab === 'DESCENDANTS' && !!activeGroupId && ((currentUser as any)?.visiting || []).some((v: any) => v.g === activeGroupId);
    const targetCircle = activeTab === 'ANCESTORS' ? 'UP' : (activeTab === 'DESCENDANTS' ? ((memberLink || visitingGroup) && !crossLink ? 'UP' : 'DOWN') : undefined);
    let targets: string[] | undefined;
    if (activeTab === 'BROADCAST' && annTargets !== 'ALL') {
      targets = Array.from(annTargets);
      if (!targets.length) { alert('Tap at least one person on the tree for the announcement, or select Everyone.'); return; }
    }

    // In a Direct-Only network OR a Personal Hub, every message is a 1:1 DM to a
    // specific contact: your inviter (Ancestors tab) or the opened chat
    // (Descendants tab). A personal-chat message must never fan out to every
    // contact in the hub.
    let targetUserId: string | undefined;
    if (currentUser?.treeMode === 'DM' || currentUser?.treeMode === 'HUB') {
      if (activeTab === 'ANCESTORS') targetUserId = currentUser.invitedBy || undefined;
      else if (activeTab === 'DESCENDANTS') targetUserId = activeFilterId || undefined;
      if (!targetUserId) {
        alert(activeTab === 'DESCENDANTS'
          ? (currentUser?.treeMode === 'HUB' ? 'Open a chat first.' : 'Pick someone under "My Invitees" first.')
          : 'No inviter to message.');
        return;
      }
    }

    const expiresAt = ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : undefined;
    // Quote payload rides INSIDE the encrypted content; server never sees it.
    const replySender = replyingTo ? usersById.get(replyingTo.senderId) : undefined;
    const replyTo = replyingTo && replyingTo.id ? {
      mid: replyingTo.id,
      name: replySender?.name || 'Unknown',
      text: (replyingTo.text || (replyingTo.attachments?.length ? '📎 Attachment' : '')).slice(0, 200),
    } : undefined;
    const wantsAck = type === 'BROADCAST' && reqAck;

    // Snapshot then clear immediately so the composer feels instant and stays
    // open for the next message (mobile-friendly).
    const imgs = imagePayloads;
    const vid = videoPayload;
    const aud = audioPayload;
    const auPeaks = audioPeaks || undefined;
    const auDurMs = audioDurMs || undefined;
    const text = messageText;
    setComposer('');
    stopTypingLocal();
    sealedLocal.remove(convKeyRef.current); // draft consumed
    setReplyingTo(null);
    setReqAck(false);
    setImagePayloads([]);
    setAudioPayload(null);
    setAudioPeaks(null);
    setAudioDurMs(null);
    setVideoPayload(null);
    // Keep focus so the mobile keyboard doesn't dismiss between messages — but only
    // if the composer was already focused (otherwise a collapsed bar stays collapsed).
    if (keepFocus) messageInputRef.current?.focus();

    setIsSending(true);
    // Descendants group chat: an inviter viewing a specific group's tab sends
    // scoped to that group; the default tab (activeGroupId null) sends to
    // ungrouped invitees only. Only applies to the inviter's own DOWN messages.
    // A group chat under Ancestors (one I'm a member of) is posted UP, tagged to it.
    const sendGroup = (activeTab === 'ANCESTORS' && activeGroupId) ? activeGroupId
      : (activeTab === 'DESCENDANTS' && activeGroupId && (targetCircle === 'DOWN' || memberLink || crossLink || visitingGroup)) ? activeGroupId : undefined;
    // Resolve @mentions in the text → recipient ids (for mention-aware push).
    const mentions = text ? resolveMentions(text) : undefined;
    // Fire the send WITHOUT holding the button spinner for the whole network round
    // trip. The bubble renders optimistically & instantly and carries its own status
    // (clock → delivered → read), so the button is released as soon as the message is
    // on screen. The composer is already cleared above, so an early release can't
    // produce a duplicate (a stray tap sends nothing).
    (async () => {
      try {
        if (imgs.length > 0) {
            // One encrypted message per image; the text rides on the first.
            for (let i = 0; i < imgs.length; i++) {
                await onSendMessage(
                  { text: i === 0 ? text : undefined, imageUrl: imgs[i], expiresAt, replyTo: i === 0 ? replyTo : undefined },
                  type, undefined, targets, targetCircle, targetUserId, i === 0 ? wantsAck : undefined, sendGroup, i === 0 ? mentions : undefined);
            }
            // Any voice/video attached alongside images goes as its own message.
            if (vid) await onSendMessage({ videoUrl: vid, expiresAt }, type, undefined, targets, targetCircle, targetUserId, undefined, sendGroup);
            if (aud) await onSendMessage({ audioUrl: aud, expiresAt, audioPeaks: auPeaks, audioDurMs: auDurMs }, type, undefined, targets, targetCircle, targetUserId, undefined, sendGroup);
        } else {
            await onSendMessage(
              { text: text || undefined, audioUrl: aud || undefined, videoUrl: vid || undefined, expiresAt, replyTo, audioPeaks: aud ? auPeaks : undefined, audioDurMs: aud ? auDurMs : undefined },
              type, undefined, targets, targetCircle, targetUserId, wantsAck, sendGroup, mentions);
        }
      } catch {
        // Restore on failure so nothing is silently lost.
        setComposer(text);
        if (replyTo && replyingTo) setReplyingTo(replyingTo);
        setImagePayloads(imgs);
        setAudioPayload(aud);
        setAudioPeaks(auPeaks || null);
        setAudioDurMs(auDurMs || null);
        setVideoPayload(vid);
        alert('Could not send. Please try again.');
      }
    })();
    // Keep the send animation up ONLY until the optimistic bubble has actually
    // painted (a frame or two) — not gone entirely, and not held for the whole
    // encrypt + POST round-trip. Double rAF fires after the next paint, so the
    // spinner shows from tap until the message appears on screen, then clears.
    requestAnimationFrame(() => requestAnimationFrame(() => setIsSending(false)));
  };

  // Source files can be large; images are downscaled on attach so the PAYLOAD is
  // small. Videos aren't re-encoded here, so keep their raw cap tighter.
  const MAX_IMAGE_SOURCE_BYTES = 30 * 1024 * 1024; // 30MB source (any modern phone photo)
  // The server's per-file limit for this identity (12 MB free, 20 MB Premium), less headroom.
  const maxVideoBytes = () => (plan?.attachMax || 12 * 1024 * 1024) - 64 * 1024; // no re-encode
  const MAX_IMAGES = 10;

  const handleAttach = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    if (files.length === 0) return;

    const images = files.filter(f => f.type.startsWith('image/'));
    const videos = files.filter(f => f.type.startsWith('video/'));
    const unsupported = files.filter(f => !f.type.startsWith('image/') && !f.type.startsWith('video/'));
    if (unsupported.length) { setScrubNote('Some files were skipped (only images and video are supported).'); }

    setMediaBusy(true);
    try {
      // ---- images (multi) ----
      if (images.length) {
        const room = MAX_IMAGES - imagePayloads.length;
        const take = images.slice(0, Math.max(0, room));
        if (images.length > take.length) setScrubNote(`Up to ${MAX_IMAGES} images at once.`);
        const prepared: string[] = [];
        for (const f of take) {
          if (f.size > MAX_IMAGE_SOURCE_BYTES) { setScrubNote('An image was too large and was skipped.'); continue; }
          try {
            // Downscale + re-encode BEFORE it enters state. This both shrinks the
            // payload (no chat lag) and strips EXIF/GPS as a side effect.
            const url = await prepareImageForSend(f);
            prepared.push(url);
          } catch {
            setScrubNote('An image could not be processed and was skipped.');
          }
        }
        if (prepared.length) {
          setVideoPayload(null);
          setImagePayloads(prev => [...prev, ...prepared].slice(0, MAX_IMAGES));
          if (!scrubNote) setScrubNote(`${prepared.length} image${prepared.length > 1 ? 's' : ''} ready — location data removed.`);
        }
      }

      // ---- a single video (kept separate; images take priority if both picked) ----
      if (videos.length && images.length === 0) {
        const f = videos[0];
        if (f.size > maxVideoBytes()) { alert(`That video is too large (max ${Math.round((plan?.attachMax || 12 * 1048576) / 1048576)} MB).`); }
        else {
          let url = await blobToCleanDataUrl(f, 'video');
          if (scrubMeta !== 'OFF') {
            const r = scrubVideo(url);
            if (!r.scrubbed) {
              // V8 M-4: FAIL CLOSED. A video whose metadata can't be verifiably
              // removed is NOT attached while scrubbing is on — it used to be
              // attached anyway with a 5-second toast, one tap from being sent
              // with its GPS intact. Sending it as-is needs an explicit choice.
              setScrubNote(null);
              alert(`This video wasn’t attached: its location/metadata couldn’t be removed (${r.note}).\n\nTo send it anyway WITH its original metadata, turn Scrub OFF first. Recording in your phone’s camera app (MP4/MOV) usually scrubs fine.`);
              return;
            }
            url = r.url;
            // V8 H-7: this claim is now backed by an independent re-scan of the
            // OUTPUT (auditMp4) that must come back clean before scrubbed=true.
            setScrubNote('Video checked: location, device and capture-time metadata removed (verified).');
          }
          setImagePayloads([]);
          setVideoPayload(url);
        }
      }
    } catch {
      alert('Could not process that file.');
    } finally {
      setMediaBusy(false);
    }
  };

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      // Prefer a container that plays on the widest range of devices. iOS Safari can
      // record/play audio/mp4 but NOT webm/opus, so try mp4 first, then fall back.
      const prefer = ['audio/mp4', 'audio/webm;codecs=opus', 'audio/webm', 'audio/ogg'];
      const supported = (typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported)
        ? prefer.find(t => MediaRecorder.isTypeSupported(t))
        : undefined;
      const mr = supported ? new MediaRecorder(stream, { mimeType: supported }) : new MediaRecorder(stream);
      // Tap the SAME stream for a live level meter (analyser only — never connected
      // to the audio destination, so nothing is played back / no feedback).
      try {
        const AC: typeof AudioContext = (window.AudioContext || (window as any).webkitAudioContext);
        if (AC) {
          const ctx = new AC();
          try { await ctx.resume(); } catch {} // iOS needs a resume after the tap
          const analyser = ctx.createAnalyser();
          analyser.fftSize = 512;
          ctx.createMediaStreamSource(stream).connect(analyser);
          recAudioCtxRef.current = ctx;
          recAnalyserRef.current = analyser;
          // Sample the level across the whole take (for the sent waveform).
          recEnvelopeRef.current = [];
          const envData = new Uint8Array(analyser.fftSize);
          recSampleTimerRef.current = window.setInterval(() => {
            const an = recAnalyserRef.current; if (!an) return;
            an.getByteTimeDomainData(envData as any);
            let sum = 0, peak = 0;
            for (let i = 0; i < envData.length; i++) { const v = Math.abs((envData[i] - 128) / 128); sum += v * v; if (v > peak) peak = v; }
            const rms = Math.sqrt(sum / envData.length);
            recEnvelopeRef.current.push(Math.min(1, Math.pow(Math.max(rms * 3.6, peak * 1.6), 0.7)));
          }, 55);
        }
      } catch {}
      recordChunksRef.current = [];
      mr.ondataavailable = (ev) => { if (ev.data.size > 0) recordChunksRef.current.push(ev.data); };
      mr.onstop = async () => {
        stream.getTracks().forEach(t => t.stop());
        stopMeter();
        // True recording length from wall-clock (the blob's own duration is unreliable).
        setAudioDurMs(recStartRef.current ? Math.max(0, Date.now() - recStartRef.current) : null);
        // Reduce the sampled envelope to a fixed set of display peaks (same peak +
        // expansion treatment as the decoded waveform, so both look consistent).
        const env = recEnvelopeRef.current;
        if (env.length) {
          const N = 44; const buckets: number[] = []; let max = 0.0001;
          for (let i = 0; i < N; i++) {
            const s = Math.floor(i * env.length / N), e = Math.max(s + 1, Math.floor((i + 1) * env.length / N));
            let p = 0; for (let j = s; j < e && j < env.length; j++) if (env[j] > p) p = env[j];
            buckets.push(p); if (p > max) max = p;
          }
          const norm = max * 0.62;
          setAudioPeaks(buckets.map(v => Math.pow(Math.min(1, v / norm), 1.4)));
        } else setAudioPeaks(null);
        const blob = new Blob(recordChunksRef.current, { type: mr.mimeType || 'audio/mp4' });
        if (blob.size > maxVideoBytes()) { alert('Recording too long.'); return; }
        // Build the data URL ourselves with a sanitized MIME so phone-recorded audio
        // (odd/uppercase/parametered MIME types) always passes the receive validator.
        try {
          let url = await blobToCleanDataUrl(blob, 'audio');
          if (scrubMeta === 'DEEP') {
            setMediaBusy(true);
            const r = await reencodeAudioDeep(url);
            if (r.url.length < maxVideoBytes() * 1.4) { url = r.url; } // WAV can inflate; keep within cap
            setScrubNote(r.scrubbed ? 'Voice note re-synthesized — no container metadata survives.' : 'Voice sent as recorded (deep re-encode unavailable).');
            setMediaBusy(false);
          }
          setAudioPayload(url);
        }
        catch { setMediaBusy(false); alert('Could not process the recording.'); }
      };
      mediaRecorderRef.current = mr;
      recStartRef.current = Date.now();
      mr.start();
      setIsRecording(true);
    } catch {
      stopMeter();
      alert('Microphone access was denied or is unavailable.');
    }
  };
  const stopRecording = () => {
    mediaRecorderRef.current?.stop();
    mediaRecorderRef.current = null;
    setIsRecording(false);
    stopMeter();
  };

  const usersById = useMemo(() => { const m = new Map<string, User>(); for (const u of users) m.set(u.id, u); return m; }, [users]);
  // open the verify sheet and load the safety number
  const handleVerifyIdentity = useCallback(async (senderId: string) => {
    const other = usersById.get(senderId) || users.find(u => u.id === senderId) || null;
    if (!other || !currentUser) return;
    setVerifyPeer(other);
    setVerifySafety('loading');
    try { setVerifySafety(await api.safetyNumberWith(currentUser, other)); }
    catch { setVerifySafety(null); }
  }, [usersById, users, currentUser]);
  // accept the new identity and clear the warning
  const confirmVerify = useCallback(async () => {
    if (!verifyPeer || !currentUser) return;
    setVerifyBusy(true);
    try {
      await api.acceptKeyChange(currentUser, verifyPeer);
      setReTrusted(prev => new Set(prev).add(verifyPeer.id));
    } catch (e: any) {
      // v71 M2: refused because their key changed AGAIN after the number was
      // shown — show the new number instead of accepting a key nobody compared.
      setVerifyBusy(false);
      alert(e?.message || 'Their security key changed again. Compare the new safety number before trusting it.');
      setVerifySafety('loading');
      try { setVerifySafety(await api.safetyNumberWith(currentUser, verifyPeer)); } catch { setVerifySafety(null); }
      return;
    }
    setVerifyBusy(false);
    setVerifyPeer(null);
    setVerifySafety(null);
  }, [verifyPeer, currentUser]);
  const displayMessages = useMemo(() => {
    if (!currentUser) return [];
    const now = Date.now();
    // Enforce disappearing-message TTL client-side (server also sweeps/filters).
    const live = messages.filter(m => !m.expiresAt || m.expiresAt > now);
    if (activeTab === 'BROADCAST') {
        // Everything of type BROADCAST that reached this device belongs here:
        // the server only ever delivers announcements you're targeted by (or,
        // for ancestors, oversight copies). No client-side reception filter.
        return live.filter(m => m.type === 'BROADCAST');
    }
    if (activeTab === 'GLOBAL') return live.filter(m => m.type === 'GLOBAL');
    if (activeTab === 'ANCESTORS') {
        // The main Ancestors chat IS my inviter's main Descendants group chat
        // (untagged messages). Each group I'm in has its own tab under Ancestors
        // (activeGroupId): exactly the messages tagged to that group. Linked chats
        // have their own tabs as well, so any other tag is never shown here.
        return live.filter(m => {
            if (m.type !== 'PEER') return false;
            const tg = (m as any).targetGroup as string | undefined;
            if (activeGroupId ? tg !== activeGroupId : !!tg) return false;
            const sender = users.find(u => u.id === m.senderId);
            if (!sender) return false;
            const isMe = sender.id === currentUser.id;
            // Call logs are local entries authored by me, scoped to a peer.
            if (m.callLog && isMe) {
                const peer = users.find(u => u.id === m.peerId);
                if (!peer) return false;
                return peer.id === currentUser.invitedBy
                    || (peer.invitedBy === currentUser.invitedBy && currentUser.invitedBy !== null);
            }
            const isInviter = sender.id === currentUser.invitedBy;
            const isSibling = sender.invitedBy === currentUser.invitedBy && currentUser.invitedBy !== null && !isMe;
            return (isMe && m.targetCircle === 'UP') || (isSibling && m.targetCircle === 'UP') || (isInviter && m.targetCircle === 'DOWN');
        });
    }
    // Linked cross-group chat (whether I own the link or my group is part of it):
    // one shared channel = every message tagged to this link id. The server only
    // delivered link messages to actual participants, so this is safe.
    if (activeTab === 'DESCENDANTS' && activeGroupId && !activeFilterId) {
      const ownerLink = (currentUser.groupLinks || {})[activeGroupId];
      const inviterForLink = users.find(u => u.id === currentUser.invitedBy);
      const memberLink = (((inviterForLink as any)?.myLinks) || {})[activeGroupId];
      const crossLink = ((currentUser as any).crossLinks || {})[activeGroupId];
      // A group I'm a cross-level VISITOR of is a shared channel too — every message
      // tagged with this group id (the server only delivered them to participants).
      const visiting = ((currentUser as any).visiting || []).some((v: any) => v.g === activeGroupId);
      if (ownerLink || memberLink || crossLink || visiting) return live.filter(m => m.type === 'PEER' && (m as any).targetGroup === activeGroupId);
    }
    if (activeTab === 'DESCENDANTS') {
        // Personal hub: no tree, no circles — a chat is simply "messages between
        // me and that contact" (legacy hub history used UP/DOWN; both count).
        if (currentUser.treeMode === 'HUB') {
            let filtered = live.filter(m => m.type === 'PEER' && !!users.find(u => u.id === m.senderId));
            if (activeFilterId) filtered = filtered.filter(m =>
                m.senderId === activeFilterId
                || (m.senderId === currentUser.id && (!m.peerId || m.peerId === activeFilterId)));
            return filtered;
        }
        let filtered = live.filter(m => {
            if (m.type !== 'PEER') return false;
            const sender = users.find(u => u.id === m.senderId);
            if (!sender) return false;
            // Call logs: local entries authored by me toward an invitee.
            if (m.callLog && sender.id === currentUser.id) {
                const peer = users.find(u => u.id === m.peerId);
                return !!peer && peer.invitedBy === currentUser.id;
            }
            return (sender.id === currentUser.id && m.targetCircle === 'DOWN') || (sender.invitedBy === currentUser.id && m.targetCircle === 'UP');
        });
        // Chat scoping. The main Descendants chat is a group chat with ALL my direct
        // invitees (untagged messages, grouped or not). Each group is its own extra
        // chat: exactly the messages tagged to it, from me or its members.
        if (!activeFilterId) {
            filtered = activeGroupId
                ? filtered.filter(m => (m as any).targetGroup === activeGroupId)
                : filtered.filter(m => !(m as any).targetGroup);
        }
        if (activeFilterId) filtered = filtered.filter(m =>
            m.senderId === activeFilterId
            // Own messages: match the contact they were sent to. Older messages
            // (before per-contact targeting) have no peerId — keep showing them.
            || (m.senderId === currentUser.id && (!m.peerId || m.peerId === activeFilterId)));
        return filtered;
    }
    if (activeTab === 'MONITOR' && selectedMonitorNodeId) {
        const target = users.find(u => u.id === selectedMonitorNodeId);
        if (!target) return [];
        // EXACTLY the selected person's DESCENDANT circle — what they'd see on
        // their own Descendants tab: their DOWN messages to their invitees, and
        // their direct invitees' UP replies. Nothing deeper (monitor a deeper
        // person for that), and never their ancestor circle (that's your own
        // chat with them, or above).
        return live.filter(m => {
            if (m.type !== 'PEER') return false;
            const sender = users.find(u => u.id === m.senderId);
            if (!sender || sender.id === currentUser.id) return false;
            const isDown = sender.id === target.id && m.targetCircle === 'DOWN';
            const isUp = sender.invitedBy === target.id && m.targetCircle === 'UP';
            if (!isDown && !isUp) return false;
            if (monGroup === null) return true; // All chats
            // Scope to one of the target's chats: the main chat (untagged) or a group.
            const msgGid = (m as any).targetGroup || null;
            if (monGroup === 'MAIN') return !msgGid;
            return msgGid === monGroup;
        });
    }
    if (activeTab === 'HOWTO' || activeTab === 'SETTINGS') return [];
    return [];
  }, [messages, activeTab, activeFilterId, activeGroupId, users, currentUser, selectedMonitorNodeId, monGroup]);

  // Timestamp captured the moment a conversation is opened. Messages already present
  // when you open a chat render INSTANTLY (no entrance animation) — only messages
  // that arrive AFTER you're looking slide in. This kills the ~1s "load-in" that was
  // just every bubble replaying its 500ms fade on mount when switching chats.
  const convOpenedAt = useMemo(() => Date.now(), [activeTab, activeGroupId, activeFilterId]);
  // Local search over the decrypted history (device-side only).
  const visibleMessages = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!searchOpen || !q) return displayMessages;
    return displayMessages.filter(m => {
      const sender = users.find(u => u.id === m.senderId);
      return (m.text || '').toLowerCase().includes(q) || (sender?.name || '').toLowerCase().includes(q);
    });
  }, [displayMessages, searchOpen, searchQuery, users]);

  // WINDOWING: render only the most recent slice of a conversation on open, so a
  // chat with lots of history opens INSTANTLY instead of blocking ~0.6s while every
  // bubble in the whole thread mounts at once. "Load earlier" widens the window.
  // Resets to the base window whenever the conversation changes (guarded set-in-
  // render, the sanctioned pattern) so switching chats never renders a big list.
  const MSG_WINDOW = 50;
  const [extraOlder, setExtraOlder] = useState(0);
  const winKeyRef = useRef('');
  const _convKeyW = `${activeTab}|${activeGroupId || ''}|${activeFilterId || ''}`;
  if (winKeyRef.current !== _convKeyW) { winKeyRef.current = _convKeyW; if (extraOlder !== 0) setExtraOlder(0); }
  const searchingNow = searchOpen && !!searchQuery.trim();
  const windowedMessages = useMemo(
    () => searchingNow ? visibleMessages : visibleMessages.slice(Math.max(0, visibleMessages.length - MSG_WINDOW - extraOlder)),
    [visibleMessages, searchingNow, extraOlder]);
  const hasOlderToLoad = !searchingNow && windowedMessages.length < visibleMessages.length;
  const loadOlder = () => {
    const el = scrollRef.current; const prevH = el ? el.scrollHeight : 0;
    setExtraOlder(x => x + MSG_WINDOW);
    // Keep the viewport anchored where it was when older messages prepend.
    requestAnimationFrame(() => { const e2 = scrollRef.current; if (e2) e2.scrollTop += (e2.scrollHeight - prevH); });
  };

  // Unread divider: the first message newer than what we'd seen when the
  // conversation was opened. Captured once on entry so it doesn't jump as new
  // messages arrive while reading.
  const [unreadAnchor, setUnreadAnchor] = useState<number>(0);
  useEffect(() => {
    const dirKey = activeTab === 'DESCENDANTS' && activeFilterId ? `C:${activeFilterId}` : activeTab;
    setUnreadAnchor(lastSeen[dirKey] || 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, activeFilterId]);
  const firstUnreadId = useMemo(() => {
    if (!unreadAnchor || !currentUser) return null;
    const m = visibleMessages.find(x => x.senderId !== currentUser.id && x.timestamp > unreadAnchor && !x.callLog);
    return m ? m.id : null;
  }, [visibleMessages, unreadAnchor, currentUser]);

  // Jump-to-bottom button: track whether the list is scrolled near the bottom
  // and count messages that land while scrolled up.
  const [atBottom, setAtBottom] = useState(true);
  const [newBelow, setNewBelow] = useState(0);
  const lastCountRef = useRef(0);
  const onListScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const near = el.scrollHeight - el.scrollTop - el.clientHeight < 140;
    atBottomRef.current = near;
    setAtBottom(near);
    if (near) setNewBelow(0);
  }, []);
  useEffect(() => {
    const n = visibleMessages.length;
    if (!atBottom && n > lastCountRef.current) setNewBelow(c => c + (n - lastCountRef.current));
    lastCountRef.current = n;
  }, [visibleMessages.length, atBottom]);
  const scrollToBottom = useCallback(() => {
    const el = scrollRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
    setNewBelow(0);
  }, []);

  // Typing indicator dispatch. Scoped to 1:1 conversations (personal hub / DM,
  // and any single opened contact). Sends a 'start' heartbeat while typing and a
  // 'stop' after a short idle or on send. The peer is whoever's chat is open.
  const typingPeerId = (activeTab === 'ANCESTORS')
    ? (currentUser?.invitedBy || null)
    : (activeTab === 'DESCENDANTS' ? activeFilterId : null);
  const typingActiveRef = useRef(false);
  const typingIdleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const notifyTyping = useCallback(() => {
    if (!onTyping || !typingPeerId) return;
    if (!typingActiveRef.current) { typingActiveRef.current = true; onTyping(typingPeerId, 'start'); }
    if (typingIdleTimer.current) clearTimeout(typingIdleTimer.current);
    typingIdleTimer.current = setTimeout(() => {
      typingActiveRef.current = false;
      if (typingPeerId) onTyping(typingPeerId, 'stop');
    }, 3500);
  }, [onTyping, typingPeerId]);
  const stopTyping = useCallback(() => {
    if (typingIdleTimer.current) clearTimeout(typingIdleTimer.current);
    if (typingActiveRef.current && onTyping && typingPeerId) onTyping(typingPeerId, 'stop');
    typingActiveRef.current = false;
  }, [onTyping, typingPeerId]);
  // On SEND we stop signalling locally but DON'T emit 'stop' — otherwise the peer's
  // "typing…" blinks off a beat before the message lands. Instead the indicator
  // lingers (via its expiry) and is cleared the instant the message arrives.
  const stopTypingLocal = useCallback(() => {
    if (typingIdleTimer.current) clearTimeout(typingIdleTimer.current);
    typingActiveRef.current = false;
  }, []);
  // Stop signalling when the conversation changes.
  useEffect(() => () => { stopTyping(); }, [typingPeerId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Is the open 1:1 peer currently typing to me?
  const peerTyping = useMemo(() => {
    if (!typingPeerId || !typingPeers) return null;
    const entry = typingPeers[typingPeerId];
    return entry ? entry.name : null;
  }, [typingPeers, typingPeerId]);

  // Scheduled-message reconciler. Delivery itself is SERVER-side (the sealed
  // envelope was handed over at schedule time and fires on time even with this
  // device off) — this loop only writes the sender's OWN plaintext copy into
  // local history once the server reports the entry has fired, and keeps the
  // pending banner accurate.
  useEffect(() => {
    if (!currentUser) return;
    refreshScheduled();
    let busy = false;
    const tick = async () => {
      if (busy) return; busy = true;
      try {
        await sealedLocal.init();
        const mine = scheduledStore.listScheduled(currentUser.id);
        const due = mine.filter(x => x.fireAt <= Date.now());
        if (!due.length) return;
        const server = await api.listScheduledServer(currentUser.id).catch(() => null);
        if (!server) return;
        const stillPending = new Set((server.scheduled || []).map(x => x.id));
        let fired = 0;
        for (const s of due) {
          if (s.serverId && stillPending.has(s.serverId)) continue; // server hasn't released yet
          if (s.mid) { try { await api.recordFiredScheduled(currentUser, s as any); } catch {} }
          scheduledStore.removeScheduled(s.id);
          fired++;
        }
        if (fired) refreshScheduled();
      } finally { busy = false; }
    };
    tick();
    const iv = setInterval(tick, 20000);
    return () => clearInterval(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUser?.id, messages.length]);

  // Send read receipts for what's on screen (batched per sender, deduped).
  useEffect(() => {
    if (!receiptsOn || !currentUser) return;
    if (activeTab !== 'ANCESTORS' && activeTab !== 'DESCENDANTS') return;
    // Personal hub: the chat LIST shows previews of everything — receipts must
    // only go out when a chat is actually opened, or senders would see "read"
    // for chats never looked at.
    if (currentUser.treeMode === 'HUB' && currentUser.role === 'ROOT' && activeTab === 'DESCENDANTS' && !activeFilterId) return;
    const bySender = new Map<string, string[]>();
    for (const m of displayMessages) {
      if (m.senderId === currentUser.id || receiptsSent.current.has(m.id)) continue;
      const arr = bySender.get(m.senderId) || [];
      arr.push(m.id); bySender.set(m.senderId, arr);
    }
    bySender.forEach((mids, senderId) => {
      mids.forEach(mid => receiptsSent.current.add(mid));
      api.sendReadReceipts(currentUser.id, senderId, mids);
    });
  }, [receiptsOn, activeTab, displayMessages, currentUser]);

  // Optimistic prune: hide the branch locally the moment it's confirmed; entries
  // reconcile away once the server truth arrives (node gone / marked pruned) or
  // after 15s if the request failed, so a failure never hides someone forever.
  const [pendingPruned, setPendingPruned] = useState<Map<string, number>>(new Map());
  useEffect(() => {
    setPendingPruned(prev => {
      if (prev.size === 0) return prev;
      const now = Date.now();
      let changed = false;
      const next = new Map(prev);
      for (const [id, at] of prev) {
        const u = users.find(x => x.id === id);
        if (!u || (u as any).prunedAt || now - at > 15000) { next.delete(id); changed = true; }
      }
      return changed ? next : prev;
    });
  }, [users]);
  const handlePrune = (userId: string) => {
    setPendingPruned(prev => new Map(prev).set(userId, Date.now()));
    if (activeFilterId === userId) setActiveFilterId(null);
    onPrune(userId);
  };

  // Who a call from the current view reaches: a focused invitee = direct call;
  // otherwise the whole circle of the active tab (mesh, practical up to ~5).
  const callTargets = useMemo(() => {
    if (!currentUser) return [] as { id: string; name: string }[];
    if (activeTab === 'DESCENDANTS') {
      if (currentUser.treeMode === 'HUB') {
        // Personal chat: only the open conversation can be called — never the
        // whole contact list at once.
        if (!activeFilterId) return [];
        const c = users.find(u => u.id === activeFilterId && !u.pending);
        return c ? [{ id: c.id, name: c.name }] : [];
      }
      const kids = users.filter(u => u.invitedBy === currentUser.id && !pendingPruned.has(u.id));
      if (activeFilterId) { const one = kids.find(u => u.id === activeFilterId); return one ? [{ id: one.id, name: one.name }] : []; }
      return kids.map(u => ({ id: u.id, name: u.name }));
    }
    if (activeTab === 'ANCESTORS') {
      const circle = users.filter(u => u.id !== currentUser.id && (u.id === currentUser.invitedBy || (u.invitedBy === currentUser.invitedBy && currentUser.invitedBy)));
      return circle.map(u => ({ id: u.id, name: u.name }));
    }
    return [];
  }, [activeTab, activeFilterId, users, currentUser]);

  // Monitorable people = every strict descendant, rendered as an indented tree
  // mirroring the network map. Only those WITH invitees are selectable — a leaf
  // has no descendant circle to view.
  const monitorTree = useMemo(() => {
    if (!currentUser) return [] as { user: User; depth: number; hasChildren: boolean }[];
    const rows: { user: User; depth: number; hasChildren: boolean }[] = [];
    const walk = (parentId: string, depth: number) => {
      for (const u of users.filter(x => x.invitedBy === parentId)) {
        const kids = users.some(x => x.invitedBy === u.id);
        rows.push({ user: u, depth, hasChildren: kids });
        walk(u.id, depth + 1);
      }
    };
    walk(currentUser.id, 0);
    return rows;
  }, [users, currentUser]);

  const childrenNodes = useMemo(() => currentUser ? getChildren(currentUser.id, users).filter(u => !pendingPruned.has(u.id)) : [], [currentUser, users, pendingPruned]);

  // ---- @-mentions -----------------------------------------------------------
  // Groups I can @ (name + member ids) and people I can @ (my invitees + inviter).
  const mentionGroups = useMemo(() => {
    const labels = (currentUser?.groupLabels) || {};
    const gmap = (currentUser?.inviteeGroups) || {};
    return Object.keys(labels).map(gid => ({ id: gid, name: labels[gid], memberIds: childrenNodes.filter(u => gidsOf(gmap[u.id]).includes(gid)).map(u => u.id) })).filter(g => !!g.name);
  }, [currentUser, childrenNodes]);
  const mentionUsers = useMemo(() => {
    const arr: { id: string; name: string }[] = [];
    for (const u of childrenNodes) if (u.name) arr.push({ id: u.id, name: u.name });
    const inv = users.find(u => u.id === currentUser?.invitedBy);
    if (inv?.name) arr.push({ id: inv.id, name: inv.name });
    return arr;
  }, [childrenNodes, users, currentUser]);
  // Names the message renderer recognizes as mentions, and the subset that means
  // "you" (highlighted strongest): the viewer's own alias + any group they're in.
  const mentionNames = useMemo(() => {
    const s = new Set<string>();
    for (const g of mentionGroups) s.add(g.name.toLowerCase());
    for (const u of mentionUsers) s.add(u.name.toLowerCase());
    if (currentUser?.name) s.add(currentUser.name.toLowerCase());
    return s;
  }, [mentionGroups, mentionUsers, currentUser]);
  const selfNames = useMemo(() => {
    const s = new Set<string>();
    if (currentUser?.name) s.add(currentUser.name.toLowerCase());
    // The group(s) the viewer belongs to (their labels, when the viewer can see
    // them) — any of them counts as an "@you" mention.
    const myGids = gidsOf((currentUser as any)?.myGroupUnder);
    const inv = users.find(u => u.id === currentUser?.invitedBy);
    const invLabels = (inv as any)?.groupLabels || {};
    for (const g of myGids) if (invLabels[g]) s.add(String(invLabels[g]).toLowerCase());
    // Also fold in any group names the server exposed directly to me.
    for (const nm of ((currentUser as any)?.myGroupNames as string[] | undefined) || []) s.add(String(nm).toLowerCase());
    if ((currentUser as any)?.myGroupName) s.add(String((currentUser as any).myGroupName).toLowerCase());
    return s;
  }, [currentUser, users]);
  // Resolve @tokens in outgoing text to recipient public ids for push routing.
  const resolveMentions = useCallback((text: string): { users: string[]; viaGroup: string[] } => {
    if (!text || text.indexOf('@') < 0) return { users: [], viaGroup: [] };
    const groups = [...mentionGroups].sort((a, b) => b.name.length - a.name.length);
    const ppl = [...mentionUsers].sort((a, b) => b.name.length - a.name.length);
    const lower = text.toLowerCase();
    const uSet = new Set<string>(); const gSet = new Set<string>();
    const boundary = (rest: string, n: number) => rest.length === n || /[\s.,!?;:'")\]]/.test(rest[n]);
    for (let i = 0; i < text.length; i++) {
      if (text[i] !== '@') continue;
      if (i > 0 && !/\s/.test(text[i - 1])) continue;
      const rest = lower.slice(i + 1);
      const g = groups.find(x => rest.startsWith(x.name.toLowerCase()) && boundary(rest, x.name.length));
      if (g) { g.memberIds.forEach(id => gSet.add(id)); continue; }
      const p = ppl.find(x => rest.startsWith(x.name.toLowerCase()) && boundary(rest, x.name.length));
      if (p) uSet.add(p.id);
    }
    return { users: [...uSet], viaGroup: [...gSet] };
  }, [mentionGroups, mentionUsers]);
  // Autocomplete: the @token being typed at the caret. Suggests GROUPS and the
  // PEOPLE IN THIS CHAT (my invitees + inviter) — not the whole network, which
  // would be huge and privacy-invasive. Groups first, then matching people.
  const [mentionMenu, setMentionMenu] = useState<{ q: string; at: number } | null>(null);
  const mentionMenuOpts = useMemo(() => {
    if (!mentionMenu) return [] as { id: string; name: string; kind: 'group' | 'user'; count?: number }[];
    const q = mentionMenu.q.toLowerCase();
    const match = (n: string) => n.toLowerCase().startsWith(q);
    const groups = mentionGroups.filter(g => match(g.name)).map(g => ({ id: g.id, name: g.name, kind: 'group' as const, count: g.memberIds.length }));
    const seen = new Set<string>();
    const usersOpts = mentionUsers.filter(u => match(u.name) && !seen.has(u.id) && (seen.add(u.id), true)).map(u => ({ id: u.id, name: u.name, kind: 'user' as const }));
    return [...groups, ...usersOpts].slice(0, 8);
  }, [mentionMenu, mentionGroups, mentionUsers]);
  const onComposerChange = (el: HTMLTextAreaElement) => {
    const val = el.value;
    setMessageText(val); notifyTyping();
    const caret = el.selectionStart ?? val.length;
    const upto = val.slice(0, caret);
    const at = upto.lastIndexOf('@');
    const tok = at >= 0 ? upto.slice(at + 1) : '';
    if (at >= 0 && !tok.includes('\n') && tok.length <= 32 && (at === 0 || /\s/.test(upto[at - 1]))) setMentionMenu({ q: tok, at });
    else setMentionMenu(null);
  };
  const insertMention = (name: string) => {
    const el = messageInputRef.current; if (!el || !mentionMenu) return;
    const caret = el.selectionStart ?? messageText.length;
    const before = messageText.slice(0, mentionMenu.at);
    const after = messageText.slice(caret);
    const next = `${before}@${name} ${after}`;
    setMessageText(next); setMentionMenu(null);
    requestAnimationFrame(() => { const pos = (before + '@' + name + ' ').length; try { el.focus(); el.setSelectionRange(pos, pos); } catch {} });
  };

  const dmMode = currentUser?.treeMode === 'DM';
  const hubMode = currentUser?.treeMode === 'HUB';
  // Direct-Only referral mode (mirrored onto every node from the root): members
  // may invite, and their joiners flatten onto the root.
  const referralOpen = !!currentUser?.referralOpen;
  // Is the currently-open chat an ARCHIVED linked chat? (read-only — no composer)
  const activeLinkArchived = useMemo(() => {
    if (activeTab !== 'DESCENDANTS' || !activeGroupId) return false;
    const owned = (currentUser?.groupLinks || {})[activeGroupId];
    const inviter = users.find(u => u.id === currentUser?.invitedBy);
    const mine = ((inviter as any)?.myLinks || {})[activeGroupId];
    const cross = ((currentUser as any)?.crossLinks || {})[activeGroupId];
    return !!((owned && owned.archived) || (mine && (mine as any).archived) || (cross && (cross as any).archived));
  }, [activeTab, activeGroupId, currentUser, users]);
  // Direct-Only: the root's invitees, nested by who actually referred whom
  // (referredBy) rather than the flat structural parent. Rendered under the
  // "My Invitees" header in the sidebar; each row opens a 1:1 with that person.
  // Non-referral DM has no referredBy anywhere, so every row sits at depth 0.
  const dmInviteeRows = useMemo(() => {
    if (!dmMode || !currentUser) return [] as { user: User; depth: number }[];
    const rows: { user: User; depth: number }[] = [];
    const kidsOf = (pid: string) => users
      .filter(u => u.id !== currentUser.id && !pendingPruned.has(u.id) && ((u.referredBy || u.invitedBy) === pid))
      .sort((a, b) => a.name.localeCompare(b.name));
    const walk = (pid: string, depth: number) => {
      for (const u of kidsOf(pid)) { rows.push({ user: u, depth }); walk(u.id, depth + 1); }
    };
    walk(currentUser.id, 0);
    return rows;
  }, [dmMode, users, currentUser, pendingPruned]);
  // Personal hub: contacts are peer EDGES, not children. Everyone visible other
  // than me is a contact; pending ones carry pending/pendingDirection ('out' =
  // I asked and I'm waiting, 'in' = they asked — shown under Contact Requests).
  const hubContacts = useMemo(() => (hubMode && currentUser)
    ? users.filter(u => u.id !== currentUser.id)
    : [], [hubMode, users, currentUser]);
  const canAnnounce = !!(currentUser && (currentUser.role === 'ROOT' || currentUser.permissions?.announce));
  const hasTrueSight = !!(currentUser && (currentUser.role === 'ROOT' || currentUser.permissions?.viewTrueLevel));
  // The network name is shown when the root turned on name visibility (a switch
  // independent of True Sight) OR the viewer has True Sight. The server only
  // sends treeName to viewers allowed to see it, so its mere presence is the
  // signal — with the root's own node as the authority.
  const rootNode = useMemo(() => users.find(u => u.role === 'ROOT'), [users]);
  const nameVisibleToAll = !!(rootNode && (rootNode as any).treeNameVisible);
  const networkName = useMemo(() => {
    if (!hasTrueSight && !nameVisibleToAll) return null;
    return rootNode?.treeName || currentUser?.treeName || 'Network';
  }, [rootNode, currentUser, hasTrueSight, nameVisibleToAll]);

  // Build the nested tree to render. Privileged (ROOT / true sight) see the whole
  // network from its real root; everyone else sees the person who invited them at
  // the top, then themselves, then everyone they invited cascading down.
  const treeData = useMemo<TreeData | null>(() => {
    if (!currentUser) return null;
    const gone = (u: User) => pendingPruned.has(u.id);
    // Nest by the DISPLAY parent: in a Direct-Only referral tree everyone is
    // structurally re-parented onto the root (invitedBy = root), but referredBy
    // remembers who actually brought them in — so the visual tree shows the real
    // referral chain. Outside referral mode referredBy is unset, so this is just
    // invitedBy (unchanged for hierarchical/normal DM).
    // Inject synthetic GROUP nodes: a node's groups (from its groupLabels) render
    // as collapsible labels wrapping the invitees assigned to them; ungrouped
    // invitees stay direct. An empty group (label, no members yet) is a "skeleton
    // branch" — a labelled container ready to be populated via its join link.
    // Subtree size per node (1 = the node itself), so a group can report how many
    // people are BELOW it (its members plus everyone they invited, recursively).
    const subtreeSize = new Map<string, number>();
    const sizeOf = (id: string): number => {
      if (subtreeSize.has(id)) return subtreeSize.get(id)!;
      subtreeSize.set(id, 1); // guard against cycles
      const n = 1 + users.filter(c => (c.referredBy || c.invitedBy) === id && !gone(c)).reduce((s, c) => s + sizeOf(c.id), 0);
      subtreeSize.set(id, n);
      return n;
    };
    // groupName (when set) tags THIS node as belonging to that group, so the tree
    // can show a "which group am I in" badge on every member — not just via nesting.
    const build = (u: User, groupNames?: string[]): TreeData => {
      // Prefer the grouping the viewer can see (groupNames, from the parent's group
      // map); else fall back to the node's OWN self-reported membership (myGroupName
      // / myGroupNames) so a plain member still sees their own group(s) even when
      // their inviter's map isn't exposed. A member in multiple groups shows them
      // all in one pill ("A, B").
      const selfNames = (u as any).myGroupNames as string[] | undefined;
      const selfName = (u as any).myGroupName as string | undefined;
      const gList = (groupNames && groupNames.length) ? groupNames
        : (selfNames && selfNames.length) ? selfNames
        : (selfName ? [selfName] : []);
      const withGroup = gList.length ? ({ ...u, __group: gList[0], __groups: gList } as any) : u;
      const kids = users.filter(c => (c.referredBy || c.invitedBy) === u.id && !gone(c));
      const labels = (u as any).groupLabels as Record<string, string> | undefined;
      const gmap = (u as any).inviteeGroups as Record<string, string | string[]> | undefined;
      const parents = ((u as any).groupParents || {}) as Record<string, string>;
      if (!labels || Object.keys(labels).length === 0) return { user: withGroup, children: kids.map(c => build(c)) };
      const allGids = Object.keys(labels);
      // A member's VALID group ids (those still labelled), and their HOME group (the
      // first). The home box nests the member + their whole subtree exactly once; a
      // member in 2+ groups is drawn only in their home box, with every group named
      // in the pill. This keeps counts, move, prune and selection unambiguous.
      const memberGL = (c: User) => gidsOf(gmap && gmap[c.id]).filter(g => labels[g]);
      const homeOf = (c: User) => { const gs = memberGL(c); return gs.length ? gs[0] : null; };
      const membersOf = (gid: string) => kids.filter(c => homeOf(c) === gid);
      const subGidsOf = (gid: string) => allGids.filter(g => parents[g] === gid);
      // Deep count = everyone whose HOME is under this group: each member's whole
      // subtree (counted once, in their home box) plus the sub-groups' deep counts.
      const countDeep = (gid: string): number => membersOf(gid).reduce((s, c) => s + sizeOf(c.id), 0) + subGidsOf(gid).reduce((s, g) => s + countDeep(g), 0);
      // Recurse the group hierarchy: a group node holds its sub-groups then its own
      // direct (home) members. Nesting is organizational; a member's compartments
      // are still their exact leaf groups.
      // Members who belong to this group but live (home) in a DIFFERENT one — shown
      // here as lightweight "reference" nodes (no subtree) so a multi-group member
      // appears under every group they're in, without duplicating their branch.
      const refsOf = (gid: string) => kids.filter(c => memberGL(c).includes(gid) && homeOf(c) !== gid);
      // Cross-level VISITORS added to this group from other branches (public ids on
      // the owner's groupVisitors map) → shown as ghost visitor nodes here too.
      const gvis = (u as any).groupVisitors as Record<string, string[]> | undefined;
      const crossVisOf = (gid: string) => ((gvis && gvis[gid]) || []).map(pid => users.find(x => x.id === pid && !gone(x))).filter(Boolean) as User[];
      const buildGroup = (gid: string): TreeData => {
        const cv = crossVisOf(gid);
        const gUser: any = { id: `grp:${u.id}:${gid}`, name: labels[gid], color: '#3f3f46', role: 'MEMBER', invitedBy: u.id, isGroup: true, groupId: gid, ownerId: u.id, ownedByMe: !!u.isMe, __count: countDeep(gid), __visitors: refsOf(gid).length + cv.length };
        return { user: gUser as User, children: [
          ...subGidsOf(gid).map(buildGroup),
          ...membersOf(gid).map(c => build(c, memberGL(c).map(g => labels[g]))),
          ...refsOf(gid).map(c => ({ user: { ...c, id: `ref:${u.id}:${gid}:${c.id}`, __ref: true, __refOf: c.id } as any as User, children: [] })),
          ...cv.map(c => ({ user: { ...c, id: `vis:${u.id}:${gid}:${c.id}`, __ref: true, __refOf: c.id, __acrossLevels: true, __visOwner: u.id, __visGid: gid } as any as User, children: [] })),
        ] };
      };
      const topGids = allGids.filter(g => !parents[g] || !labels[parents[g]]);
      const groupNodes = topGids.map(buildGroup);
      const ungrouped = kids.filter(c => memberGL(c).length === 0);
      return { user: withGroup, children: [...groupNodes, ...ungrouped.map(c => build(c))] };
    };
    if (hasTrueSight) {
      const realRoot = users.find(u => u.role === 'ROOT') || currentUser;
      return build(realRoot);
    }
    const meTree = build(currentUser);
    const inviter = users.find(u => u.id === currentUser.invitedBy);
    if (!inviter) return meTree;
    // Show the group(s) I'm in under my inviter, with everyone else in those groups
    // (co-members + cross-level visitors). The server exposes only MY groups' roster,
    // so other groups/members stay hidden. Ungrouped → the flat inviter→me as before.
    const invLabels = ((inviter as any).groupLabels || {}) as Record<string, string>;
    const invGmap = ((inviter as any).inviteeGroups || {}) as Record<string, string | string[]>;
    const invGvis = (inviter as any).groupVisitors as Record<string, string[]> | undefined;
    const myGids = gidsOf(invGmap[currentUser.id]).filter(g => invLabels[g]);
    if (!myGids.length) return { user: inviter, children: [meTree] };
    const memberGLinv = (c: User) => gidsOf(invGmap[c.id]).filter(g => invLabels[g]);
    const homeInv = (c: User) => { const gs = memberGLinv(c); return gs.length ? gs[0] : null; };
    const roster = users.filter(u => u.invitedBy === inviter.id && !gone(u) && memberGLinv(u).some(g => myGids.includes(g)));
    const box = (gid: string): TreeData => {
      const home = roster.filter(c => homeInv(c) === gid);
      const refs = roster.filter(c => memberGLinv(c).includes(gid) && homeInv(c) !== gid);
      const cvis = ((invGvis && invGvis[gid]) || []).map(pid => users.find(x => x.id === pid && !gone(x))).filter(Boolean) as User[];
      const gUser: any = { id: `grp:${inviter!.id}:${gid}`, name: invLabels[gid], color: '#3f3f46', role: 'MEMBER', invitedBy: inviter!.id, isGroup: true, groupId: gid, ownerId: inviter!.id, __count: home.length, __visitors: refs.length + cvis.length };
      const node = (c: User) => c.id === currentUser.id
        ? build(currentUser, memberGLinv(c).map(g => invLabels[g]))
        : ({ user: ({ ...c, __group: memberGLinv(c).map(g => invLabels[g]).join(', ') } as any) as User, children: [] });
      return { user: gUser as User, children: [
        ...home.map(node),
        ...refs.map(c => ({ user: ({ ...c, id: `ref:${inviter!.id}:${gid}:${c.id}`, __ref: true, __refOf: c.id } as any) as User, children: [] })),
        ...cvis.map(c => ({ user: ({ ...c, id: `vis:${inviter!.id}:${gid}:${c.id}`, __ref: true, __refOf: c.id, __acrossLevels: true, __visOwner: inviter!.id, __visGid: gid } as any) as User, children: [] })),
      ] };
    };
    return { user: inviter, children: myGids.map(box) };
  }, [users, currentUser, hasTrueSight, pendingPruned]);

  // My own subtree (me at the top, everyone below cascading down) — the map the
  // Announcements and Monitor pickers render, regardless of True Sight.
  const mySubtreeData = useMemo<TreeData | null>(() => {
    if (!currentUser) return null;
    const gone = (u: User) => pendingPruned.has(u.id);
    // Inject the SAME synthetic group nodes the main Network Tree uses, so the
    // Monitor Hub and Announcements picker show one consistent structure (people
    // wrapped by their groups) rather than a bare people-only tree. Mirrors the
    // `build` in `treeData` (kept separate only because that one also handles
    // referral re-parenting / True Sight roots).
    const subtreeSize = new Map<string, number>();
    const sizeOf = (id: string): number => {
      if (subtreeSize.has(id)) return subtreeSize.get(id)!;
      subtreeSize.set(id, 1);
      const n = 1 + users.filter(c => c.invitedBy === id && !gone(c)).reduce((s, c) => s + sizeOf(c.id), 0);
      subtreeSize.set(id, n); return n;
    };
    const build = (u: User, groupNames?: string[]): TreeData => {
      // Prefer the grouping the viewer can see (groupNames, from the parent's group
      // map); else fall back to the node's OWN self-reported membership. Mirrors the
      // multi-group home-box logic in treeData's build.
      const selfNames = (u as any).myGroupNames as string[] | undefined;
      const selfName = (u as any).myGroupName as string | undefined;
      const gList = (groupNames && groupNames.length) ? groupNames
        : (selfNames && selfNames.length) ? selfNames
        : (selfName ? [selfName] : []);
      const withGroup = gList.length ? ({ ...u, __group: gList[0], __groups: gList } as any) : u;
      const kids = users.filter(c => c.invitedBy === u.id && !gone(c));
      const labels = (u as any).groupLabels as Record<string, string> | undefined;
      const gmap = (u as any).inviteeGroups as Record<string, string | string[]> | undefined;
      const parents = ((u as any).groupParents || {}) as Record<string, string>;
      if (!labels || Object.keys(labels).length === 0) return { user: withGroup, children: kids.map(c => build(c)) };
      const allGids = Object.keys(labels);
      const memberGL = (c: User) => gidsOf(gmap && gmap[c.id]).filter(g => labels[g]);
      const homeOf = (c: User) => { const gs = memberGL(c); return gs.length ? gs[0] : null; };
      const membersOf = (gid: string) => kids.filter(c => homeOf(c) === gid);
      const refsOf = (gid: string) => kids.filter(c => memberGL(c).includes(gid) && homeOf(c) !== gid);
      const gvis = (u as any).groupVisitors as Record<string, string[]> | undefined;
      const crossVisOf = (gid: string) => ((gvis && gvis[gid]) || []).map(pid => users.find(x => x.id === pid && !gone(x))).filter(Boolean) as User[];
      const subGidsOf = (gid: string) => allGids.filter(g => parents[g] === gid);
      const countDeep = (gid: string): number => membersOf(gid).reduce((s, c) => s + sizeOf(c.id), 0) + subGidsOf(gid).reduce((s, g) => s + countDeep(g), 0);
      const buildGroup = (gid: string): TreeData => {
        const cv = crossVisOf(gid);
        const gUser: any = { id: `grp:${u.id}:${gid}`, name: labels[gid], color: '#3f3f46', role: 'MEMBER', invitedBy: u.id, isGroup: true, groupId: gid, ownerId: u.id, ownedByMe: !!u.isMe, __count: countDeep(gid), __visitors: refsOf(gid).length + cv.length };
        return { user: gUser as User, children: [
          ...subGidsOf(gid).map(buildGroup),
          ...membersOf(gid).map(c => build(c, memberGL(c).map(g => labels[g]))),
          ...refsOf(gid).map(c => ({ user: { ...c, id: `ref:${u.id}:${gid}:${c.id}`, __ref: true, __refOf: c.id } as any as User, children: [] })),
          ...cv.map(c => ({ user: { ...c, id: `vis:${u.id}:${gid}:${c.id}`, __ref: true, __refOf: c.id, __acrossLevels: true, __visOwner: u.id, __visGid: gid } as any as User, children: [] })),
        ] };
      };
      const topGids = allGids.filter(g => !parents[g] || !labels[parents[g]]);
      const ungrouped = kids.filter(c => memberGL(c).length === 0);
      return { user: withGroup, children: [...topGids.map(buildGroup), ...ungrouped.map(c => build(c))] };
    };
    return build(currentUser);
  }, [users, currentUser, pendingPruned]);

  // Who can be MONITORED: strict descendants at most 2 levels below who have
  // invitees of their own. Applies to everyone, the founder included — anyone
  // deeper is out of monitoring range by design (the server refuses to deliver
  // oversight copies beyond this window, so this isn't just cosmetic).
  const monitorableIds = useMemo(() => {
    const s = new Set<string>();
    for (const { user: u, depth, hasChildren } of monitorTree) {
      if (hasChildren && depth <= 1) s.add(u.id); // depth 0 = 1 below, depth 1 = 2 below
    }
    return s;
  }, [monitorTree]);

  // Who an announcement can target: any strict descendant.
  const announceTargetIds = useMemo(() => new Set(monitorTree.map(r => r.user.id)), [monitorTree]);

  const handleToggleTrueSight = (userId: string, on: boolean) => {
    const u = users.find(x => x.id === userId);
    onTogglePermissions(userId, { viewTrueLevel: on, announce: !!u?.permissions?.announce });
  };
  const handleToggleAnnounce = (userId: string, on: boolean) => {
    const u = users.find(x => x.id === userId);
    onTogglePermissions(userId, { viewTrueLevel: !!u?.permissions?.viewTrueLevel, announce: on });
  };

  const isRootUser = currentUser?.role === 'ROOT';
  // Groups ("branches") are managed per node by its own owner. In the tree, the
  // create-group ⊕ shows on nodes you own (isMe) — for most people that's just
  // their own node (root's node for the root). Hierarchical networks only.
  const canManageGroups = !!(currentUser && !dmMode && !hubMode && !!onSetGroups);
  // Get (or rotate) a group's join link — a per-group permanent invite that drops
  // the joiner straight into that group.
  const getGroupInvite = useCallback(async (ownerNodeId: string, groupId: string, rotate = false) => {
    // Signed by the node I'm acting as (V8 phase 2); the joiner lands under the owner.
    const { link } = await api.getPermanentInvite(ownerNodeId, rotate, groupId, currentUser || undefined);
    return link;
  }, [currentUser]);
  // Groups live on a node; the root (an ancestor) may manage any node's groups, so
  // every helper takes the OWNER node id. Optionally nest under a parent group.
  const createGroup = useCallback(async (ownerNodeId: string, name: string, parentGroupId?: string) => {
    const gid = `g_${randToken(8)}`;
    // (ownerNodeId, assignments, LABELS, parents) — the name is a LABEL, not an assignment.
    await onSetGroups?.(ownerNodeId, undefined, { [gid]: name }, parentGroupId ? { [gid]: parentGroupId } : undefined);
    return gid;
  }, [onSetGroups]);
  const renameGroup = useCallback(async (ownerNodeId: string, gid: string, name: string) => { await onSetGroups?.(ownerNodeId, undefined, { [gid]: name }); }, [onSetGroups]);
  const deleteGroup = useCallback(async (ownerNodeId: string, gid: string) => { await onSetGroups?.(ownerNodeId, undefined, { [gid]: null }); }, [onSetGroups]);
  // Link two of a node's groups into one shared cross-group chat. If a chat
  // between this exact pair was linked before and later archived, the server
  // refuses the new link (409 archived-exists) and we offer to RESTORE that
  // chat — with its history — rather than start an empty duplicate. Order does
  // not matter: East×West and West×East resolve to the same archived link.
  const linkGroups = useCallback(async (ownerNodeId: string, groupIds: string[], name?: string) => {
    const lid = `lk_${randToken(8)}`;
    const groups = [...new Set(groupIds)];
    try {
      await onSetGroups?.(ownerNodeId, undefined, undefined, undefined, { [lid]: { groups, name } });
      return lid;
    } catch (e: any) {
      const body = e?.body;
      if (body?.code === 'archived-exists' && body.linkId) {
        const ok = window.confirm(`These groups already had a linked chat (“${body.name}”) that’s archived. Restore it with its history?`);
        if (!ok) return null;
        await onSetGroups?.(ownerNodeId, undefined, undefined, undefined, { [body.linkId]: { archived: false } });
        return body.linkId as string;
      }
      throw e;
    }
  }, [onSetGroups]);
  // Replace an existing link's group set exactly (add and/or remove groups); the
  // chat id + history are kept. Name re-derives from the new set.
  const updateLink = useCallback(async (ownerNodeId: string, linkId: string, groupIds: string[]) => {
    const owner = users.find(u => u.id === ownerNodeId);
    const groups = [...new Set(groupIds)];
    const labels = ((owner as any)?.groupLabels) || {};
    const name = groups.map((g: string) => labels[g] || g).join(' × ');
    await onSetGroups?.(ownerNodeId, undefined, undefined, undefined, { [linkId]: { groups, name } });
  }, [onSetGroups, users]);
  // Create a CROSS-LEVEL link (root only) — refs = [{o: ownerPublicId, g: groupId}]
  // spanning groups anywhere in the tree; the link lives on the root's node.
  const createCrossLink = useCallback(async (rootId: string, refs: { o: string; g: string }[], name: string) => {
    const lid = `lk_${randToken(8)}`;
    await onSetGroups?.(rootId, undefined, undefined, undefined, { [lid]: { refs, name } as any });
    return lid;
  }, [onSetGroups]);
  // Edit an existing cross-level link's group set (replace refs; keeps chat + history).
  const updateCrossLink = useCallback(async (rootId: string, linkId: string, refs: { o: string; g: string }[], name: string) => {
    await onSetGroups?.(rootId, undefined, undefined, undefined, { [linkId]: { refs, name } as any });
  }, [onSetGroups]);
  // The root's cross-level links (they live on the root's node), for the Edit Links chips.
  const rootCrossLinks = useMemo(() => {
    const gl: any = (currentUser?.groupLinks) || {};
    return Object.keys(gl).filter(lid => gl[lid].crossLevel).map(lid => ({ id: lid, refs: (gl[lid].refs || []) as { o: string; g: string }[], name: gl[lid].name as string, archived: !!gl[lid].archived }));
  }, [currentUser]);
  // Archive (soft-delete, keeps history) or restore a linked chat.
  const archiveLink = useCallback(async (ownerNodeId: string, linkId: string, archived: boolean) => { await onSetGroups?.(ownerNodeId, undefined, undefined, undefined, { [linkId]: { archived } }); }, [onSetGroups]);
  // Permanently delete a linked chat and its history.
  const deleteLink = useCallback(async (ownerNodeId: string, linkId: string) => { await onSetGroups?.(ownerNodeId, undefined, undefined, undefined, { [linkId]: null }); }, [onSetGroups]);
  // Assign a node's direct invitees to a group (used by "Add members").
  const assignToGroup = useCallback(async (ownerNodeId: string, childPublicIds: string[], gid: string | null) => {
    if (!childPublicIds.length) return;
    // ADDITIVE: adding someone to a group keeps the groups they're already in, so
    // "Add members" genuinely puts a person in multiple groups (gid null clears).
    const owner: any = (currentUser?.id === ownerNodeId ? currentUser : users.find(u => u.id === ownerNodeId));
    const gmap = (owner?.inviteeGroups) || {};
    const a: Record<string, string | string[] | null> = {};
    for (const id of childPublicIds) {
      if (gid == null) { a[id] = null; continue; }
      const cur = gidsOf(gmap[id]);
      if (cur.includes(gid)) { a[id] = cur.length === 1 ? cur[0] : cur; continue; }
      const next = [...cur, gid];
      a[id] = next.length === 1 ? next[0] : next;
    }
    await onSetGroups?.(ownerNodeId, a);
  }, [onSetGroups, users, currentUser]);
  // Set the EXACT groups a member belongs to (from the per-member "Edit groups"
  // picker). Stores scalar-when-one, array for multi, null when cleared.
  const editMemberGroups = useCallback(async (ownerNodeId: string, childPublicId: string, groupIds: string[]) => {
    const uniq = [...new Set(groupIds)];
    const val = uniq.length ? (uniq.length === 1 ? uniq[0] : uniq) : null;
    await onSetGroups?.(ownerNodeId, { [childPublicId]: val });
  }, [onSetGroups]);
  // Nodes whose groups I may manage: my own node + everything below me (the root
  // sees the whole tree). The server allows an ancestor to group any descendant.
  const manageableNodeIds = useMemo(() => {
    if (!currentUser) return new Set<string>();
    const ids = new Set<string>([currentUser.id]);
    let added = true;
    while (added) { added = false; for (const u of users) { if (!ids.has(u.id) && u.invitedBy && ids.has(u.invitedBy)) { ids.add(u.id); added = true; } } }
    return ids;
  }, [users, currentUser]);
  // A node's direct invitees + their current group — the "Add members" candidates
  // for any node (inviteeGroups is exposed to the privileged root for all nodes).
  const inviteesOf = useCallback((ownerNodeId: string) => {
    const owner = users.find(u => u.id === ownerNodeId);
    const gmap = (owner as any)?.inviteeGroups || {};
    return users.filter(u => u.invitedBy === ownerNodeId && !u.pending).map(u => ({ id: u.id, name: u.name, groupIds: gidsOf(gmap[u.id]) }));
  }, [users]);
  // The groups defined on a node (for the "Link" picker).
  const groupsOf = useCallback((ownerNodeId: string) => {
    const owner = users.find(u => u.id === ownerNodeId);
    const labels = (owner as any)?.groupLabels || {};
    return Object.keys(labels).map(gid => ({ groupId: gid, name: labels[gid] as string }));
  }, [users]);
  // Active links on a node (to dedupe the Link picker).
  const linksOf = useCallback((ownerNodeId: string) => {
    const owner = users.find(u => u.id === ownerNodeId);
    const gl = (owner as any)?.groupLinks || {};
    return Object.keys(gl).map(lid => ({ id: lid, groups: (gl[lid].groups || []) as string[], name: gl[lid].name as string, archived: !!gl[lid].archived, crossLevel: !!gl[lid].crossLevel }));
  }, [users]);
  // Edges to draw between linked group nodes on the tree (active links only).
  // Each carries the link name + id so the canvas can label the connector.
  const linkEdges = useMemo(() => {
    const out: { a: string; b: string; name: string; lid: string }[] = [];
    for (const u of users) {
      const gl = (u as any).groupLinks || {};
      for (const lid of Object.keys(gl)) {
        const spec = gl[lid]; if (spec.archived || spec.crossLevel) continue;
        const gs: string[] = spec.groups || [];
        for (let i = 1; i < gs.length; i++) out.push({ a: `grp:${u.id}:${gs[0]}`, b: `grp:${u.id}:${gs[i]}`, name: spec.name, lid });
      }
    }
    return out;
  }, [users]);
  // CROSS-LEVEL links span groups on different owners; their group node ids are
  // grp:<ownerPublicId>:<groupId> from the refs. Rendered as long "over-the-top"
  // wires so they don't blend with the tree or cut through nodes.
  const crossLevelEdges = useMemo(() => {
    const out: { a: string; b: string; ao: string; bo: string; name: string; lid: string }[] = [];
    for (const u of users) {
      const gl = (u as any).groupLinks || {};
      for (const lid of Object.keys(gl)) {
        const spec = gl[lid]; if (!spec.crossLevel || spec.archived) continue;
        const refs = (spec.refs || []) as { o: string; g: string }[];
        for (let i = 1; i < refs.length; i++) out.push({ a: `grp:${refs[0].o}:${refs[0].g}`, b: `grp:${refs[i].o}:${refs[i].g}`, ao: refs[0].o, bo: refs[i].o, name: spec.name, lid });
      }
    }
    return out;
  }, [users]);

  // ---- Network plan (free-tier limit + upgrade) ----------------------------
  const [plan, setPlan] = useState<null | { treeSize: number; limit: number; premiumLimit?: number; relayCalls?: boolean; priceUsd: number; premium: boolean; premiumUntil: number | null; isRoot: boolean; archived: boolean; graceUntil: number | null; cardConfigured: boolean; moneroConfigured: boolean; cardSubscription?: { renews: boolean } | null; media?: { used: number; quota: number }; historyDays?: number; limits?: { freeMediaBytes: number; premiumMediaBytes: number; freeHistoryDays: number; premiumHistoryDays: number; attachmentBytes: number; premiumAttachmentBytes?: number }; attachMax?: number }>(null);
  const [upgradeOpen, setUpgradeOpen] = useState(false);
  const [xmrReq, setXmrReq] = useState<null | { requestId: string; address: string; amountXmr: number; usd: number }>(null);
  const [billingBusy, setBillingBusy] = useState(false);
  const [billingMsg, setBillingMsg] = useState<string | null>(null);
  // A personal hub: no member limit and no network upgrade — only storage applies.
  const isHubPlan = currentUser?.treeMode === 'HUB';
  // The limits shown in the plan box and the Free vs Premium panel come from the
  // server (what it actually enforces); these are only the defaults until it answers.
  const LIM = plan?.limits || { freeMediaBytes: 300 * 1048576, premiumMediaBytes: 500 * 1048576, freeHistoryDays: 90, premiumHistoryDays: 365, attachmentBytes: 12 * 1048576, premiumAttachmentBytes: 20 * 1048576 };
  const fmtBytes = (b: number) => (b >= 1073741824 ? `${+(b / 1073741824).toFixed(1)} GB` : `${Math.round(b / 1048576)} MB`);
  const fmtDays = (d: number) => (!d ? 'Forever' : d % 365 === 0 ? (d === 365 ? '1 year' : `${d / 365} years`) : `${d} days`);
  useEffect(() => {
    if (!currentUser) { setPlan(null); return; }
    // Back from card checkout: confirm the payment first so the plan shows Premium
    // right away (it doesn't wait for Stripe's webhook).
    api.billingConfirmPending()
      .then(paid => { if (paid) setBillingMsg('Payment received — Premium is active.'); })
      .catch(() => {})
      .finally(() => api.billingStatus(currentUser.id).then(setPlan).catch(() => setPlan(null)));
    // eslint-disable-next-line
  }, [currentUser?.id, users.length]);
  // ---- Donations (paywall removed; Arbor is donation-supported) ----
  const [donateOpen, setDonateOpen] = useState(false);
  const [donateAmt, setDonateAmt] = useState(20);
  const [donateCustom, setDonateCustom] = useState('');
  const [donateBusy, setDonateBusy] = useState(false);
  const [donateErr, setDonateErr] = useState<string | null>(null);
  const [donateCfg, setDonateCfg] = useState<{ card: boolean; crypto: boolean } | null>(null);
  useEffect(() => { api.donateConfig().then(setDonateCfg).catch(() => setDonateCfg(null)); }, []);
  const donate = async (method: 'card' | 'crypto') => {
    const amt = donateCustom ? parseFloat(donateCustom) : donateAmt;
    if (!(amt >= 1 && amt <= 10000)) { setDonateErr('Enter an amount between $1 and $10,000.'); return; }
    setDonateBusy(true); setDonateErr(null);
    try {
      const { url } = method === 'card' ? await api.donateStripe(amt) : await api.donateCrypto(amt);
      if (url) window.location.href = url;
    } catch (e: any) { setDonateErr(e?.message || 'Could not start the donation.'); }
    finally { setDonateBusy(false); }
  };

  // Free plan at capacity: hide every invite affordance (no stale invites) and
  // show why. Archived: the whole network is suspended pending payment.
  // at the free limit and not premium -> can't invite
  const inviteBlocked = !!(plan && !plan.premium && plan.treeSize >= plan.limit);
  const archived = false;

  // Tabs adapt to the user: the root has no inviter (so no Ancestors); broadcast is a
  // True-Sight power; everyone gets the network map and a How-To guide.
  // In a 1:1 (Direct-Only) network the "Ancestors" tab IS the conversation with the
  // person who invited you — so label it with their actual name instead of the
  // generic word "Inviter". Falls back to "Inviter" only if the name isn't loaded.
  const inviterName = (dmMode && !isRootUser) ? (users.find(u => u.id === currentUser?.invitedBy)?.name || null) : null;
  const navItems = useMemo(() => {
    const base: { id: string; icon: any; label: string }[] = [];
    if (!isRootUser) base.push({ id: 'ANCESTORS', icon: ArrowUpLeft, label: hubMode ? t('hub.chat') : (dmMode ? (inviterName || 'Inviter') : t('nav.ancestors')) });
    // DM/HUB members can't invite anyone, so an invitees tab would always be
    // empty — their only conversation is with the owner (the ANCESTORS tab).
    if (!((dmMode || hubMode) && !isRootUser)) {
      base.push({ id: 'DESCENDANTS', icon: hubMode ? MessageCircle : ArrowDownRight, label: hubMode ? t('hub.chats') : (dmMode ? t('nav.myInvitees') : t('nav.descendants')) });
    }
    // Announcements: EVERYONE in a hierarchical network gets the tab (to
    // receive); sending is gated separately by canAnnounce in the composer.
    if (!dmMode && !hubMode) base.push({ id: 'BROADCAST', icon: Radio, label: t('nav.broadcast') });
    if (!hubMode && currentUser?.globalChat) base.push({ id: 'GLOBAL', icon: Globe, label: 'Global' });
    if (!hubMode) base.push({ id: 'HIERARCHY', icon: Waypoints, label: t('nav.networkTree') });
    if (!dmMode && !hubMode && currentUser?.monitorEnabled !== false) base.push({ id: 'MONITOR', icon: Monitor, label: t('nav.monitor') });
    base.push({ id: 'HOWTO', icon: HelpCircle, label: t('nav.howto') });
    base.push({ id: 'SETTINGS', icon: Settings, label: t('nav.settings') });
    return base;
  }, [dmMode, hubMode, isRootUser, currentUser?.monitorEnabled, currentUser?.globalChat, inviterName, t]);

  // If the active tab isn't available for this user (e.g. root has no
  // Ancestors; DM/HUB members have no invitees tab), snap to the first one.
  useEffect(() => {
    if (navItems.length && !navItems.some(n => n.id === activeTab)) setActiveTab(navItems[0].id as any);
  }, [navItems, activeTab]);

  // Keep the active tab valid as permissions/role change (e.g. root must not sit on
  // Ancestors; a user who loses True Sight must leave Broadcast).
  useEffect(() => {
    if (!navItems.some(t => t.id === activeTab)) {
      setActiveTab((isRootUser ? 'DESCENDANTS' : 'ANCESTORS') as any);
    }
  }, [navItems, activeTab, isRootUser]);

  // Landing view is set once, synchronously, from the "Screen on start" preference
  // (the initial activeTab above) — so the chosen tab is what paints first, with no
  // flash of a default then a switch, and we DON'T auto-open a specific chat (that
  // made personal chats jump into the most-recent conversation on open).

  if (!currentUser) return null;

  return (
    <div className="flex h-[100dvh] w-full bg-[#0a0a0a] text-zinc-300 overflow-hidden relative">
      <div className={`fixed inset-0 bg-black/60 backdrop-blur-sm z-[60] md:hidden transition-opacity duration-300 ${isSidebarOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`} onClick={() => setIsSidebarOpen(false)} />
      
      <div className={`fixed md:relative z-[70] h-full w-[280px] lg:w-80 bg-[#0d0d0d] border-r border-white/5 transition-transform duration-300 flex flex-col ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}>
          <div className="p-6 border-b border-white/5 pt-[calc(1.5rem+env(safe-area-inset-top))] flex items-center justify-between shrink-0">
            <div className="flex items-center gap-3 text-white overflow-hidden text-left">
              <div className="w-10 h-10 bg-emerald-500/10 rounded-xl flex items-center justify-center shrink-0 border border-emerald-500/20">{hubMode ? <MessageCircle className="w-6 h-6 text-emerald-500" /> : <Network className="w-6 h-6 text-emerald-500" />}</div>
              <div className="overflow-hidden">
                <div className="font-bold tracking-tight text-lg truncate pr-2">{hubMode ? t('side.personalChats') : (networkName || t('side.gridNetwork'))}</div>
                <div className="text-[9px] text-zinc-500 uppercase tracking-widest font-black">{t('side.encrypted')}</div>
              </div>
            </div>
            <button onClick={onLogout} className="p-2 text-zinc-500 hover:text-red-400 transition-colors shrink-0"><LogOut className="w-5 h-5"/></button>
          </div>
          
          <div className="flex-1 overflow-y-auto no-scrollbar p-4 space-y-8">
             <div className="space-y-1">
                <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em] px-2 mb-2">{hubMode ? 'Menu' : 'Protocols'}</div>
                {navItems.map(item => {
                  // Direct-Only: "My Invitees" is a header, not a destination — the
                  // roster of people to open lives nested beneath it. Clicking the
                  // button itself does nothing; you pick a person from the list.
                  const dmInvHeader = dmMode && item.id === 'DESCENDANTS';
                  return (
                  <React.Fragment key={item.id}>
                  <button onClick={dmInvHeader ? undefined : () => { setActiveTab(item.id as any); setActiveGroupId(null); setActiveFilterId(null); setIsSidebarOpen(false); }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all ${dmInvHeader ? 'text-zinc-400 cursor-default' : (activeTab === item.id && !(item.id === 'DESCENDANTS' && (activeGroupId || activeFilterId)) && !(item.id === 'ANCESTORS' && activeGroupId) ?'bg-emerald-500/10 text-emerald-400 font-bold border border-emerald-500/20' : 'text-zinc-500 hover:bg-white/5')}`}>
                    <item.icon className="w-4 h-4 shrink-0" /> <span className="truncate">{item.label}</span>
                    {(() => { const c = item.id === 'DESCENDANTS' ? (unread['DESCENDANTS_TOTAL'] || 0) : item.id === 'ANCESTORS' ? (unread['ANCESTORS_TOTAL'] || 0) : (unread[item.id] || 0); return c > 0 ? (
                      <span className="ml-auto shrink-0 min-w-[18px] h-[18px] px-1 rounded-full bg-emerald-500 text-black text-[10px] font-black flex items-center justify-center">
                        {c > 99 ? '99+' : c}
                      </span>
                    ) : null; })()}
                  </button>
                  {/* Direct-Only: the invitee roster, nested by who referred whom.
                      Each row opens a 1:1 with that person. */}
                  {item.id === 'DESCENDANTS' && dmMode && (
                    <div className="mt-0.5 space-y-0.5">
                      {dmInviteeRows.length === 0 ? (
                        <div className="text-[10px] text-zinc-700 px-3 italic py-1.5 ml-4">{t('status.isolatedNode')}</div>
                      ) : dmInviteeRows.map(({ user: u, depth }) => {
                        const active = activeTab === 'DESCENDANTS' && activeFilterId === u.id;
                        const n = unread[`C:${u.id}`] || 0; // this invitee's own 1:1 unread
                        return (
                          <button key={u.id}
                            onClick={() => { setActiveFilterId(u.id); setActiveGroupId(null); setActiveTab('DESCENDANTS'); setIsSidebarOpen(false); }}
                            style={{ paddingLeft: `${16 + depth * 16}px` }}
                            className={`w-full flex items-center gap-2 pr-3 py-1.5 rounded-lg transition-all ${active ? 'bg-emerald-500/10 text-emerald-400 font-bold' : 'text-zinc-500 hover:bg-white/5'}`}>
                            {depth > 0 && <span className="text-zinc-700 shrink-0 -ml-1">↳</span>}
                            <div className="w-2 h-2 rounded-full shrink-0 shadow-[0_0_5px_currentColor]" style={{ backgroundColor: u.color, color: u.color }} />
                            <span className={`text-sm truncate text-left ${n > 0 ? 'font-black text-white' : 'font-medium'}`}>{u.name}</span>
                            {n > 0 && (
                              <span className="ml-auto shrink-0 min-w-[18px] h-[18px] px-1 rounded-full bg-emerald-500 text-black text-[10px] font-black flex items-center justify-center">{n > 99 ? '99+' : n}</span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  )}
                  {/* The groups I'm in under my inviter: each is its own chat beneath
                      Ancestors, separate from the main Ancestors group chat. */}
                  {item.id === 'ANCESTORS' && !hubMode && !dmMode && (() => {
                    const inv = users.find(u => u.id === currentUser?.invitedBy);
                    const gl = ((inv as any)?.myGroupLabels || {}) as Record<string, string>;
                    const gids = Object.keys(gl);
                    if (!gids.length) return null;
                    return (
                      <div className="pl-3 mt-0.5 space-y-0.5 border-l border-white/5 ml-4">
                        {gids.map(gid => {
                          const active = activeTab === 'ANCESTORS' && activeGroupId === gid;
                          const n = unread[`AG:${gid}`] || 0;
                          return (
                            <button key={gid} onClick={() => { setActiveTab('ANCESTORS'); setActiveGroupId(gid); setActiveFilterId(null); setIsSidebarOpen(false); }}
                              className={`w-full flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all ${active ? 'bg-emerald-500/10 text-emerald-400 font-bold' : 'text-zinc-500 hover:bg-white/5'}`}>
                              <Users className="w-3.5 h-3.5 shrink-0" />
                              <span className="text-xs font-bold uppercase tracking-wider truncate">{gl[gid]}</span>
                              {n > 0 && <span className="ml-auto shrink-0 min-w-[16px] h-4 px-1 rounded-full bg-emerald-500 text-black text-[9px] font-black flex items-center justify-center">{n > 99 ? '99+' : n}</span>}
                            </button>
                          );
                        })}
                      </div>
                    );
                  })()}
                  {/* Group chat tabs sit directly beneath the Descendants tab (hierarchical only). */}
                  {item.id === 'DESCENDANTS' && !hubMode && !dmMode && onSetGroups && (() => {
                    const gmap = (currentUser?.inviteeGroups) || {};
                    const glabels = (currentUser?.groupLabels) || {};
                    const gids: string[] = [];
                    for (const gid of Object.keys(glabels)) if (!gids.includes(gid)) gids.push(gid);
                    for (const u of childrenNodes) for (const g of gidsOf(gmap[u.id])) if (!gids.includes(g)) gids.push(g);
                    if (!gids.length) return null;
                    return (
                      <div className="pl-3 mt-0.5 space-y-0.5 border-l border-white/5 ml-4">
                        {gids.map(gid => {
                          const count = childrenNodes.filter(u => gidsOf(gmap[u.id]).includes(gid)).length;
                          const active = activeTab === 'DESCENDANTS' && activeGroupId === gid && !activeFilterId;
                          return (
                            <button key={gid} onClick={() => { setActiveTab('DESCENDANTS'); setActiveGroupId(gid); setActiveFilterId(null); setIsSidebarOpen(false); }}
                              className={`w-full flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all ${active ? 'bg-emerald-500/10 text-emerald-400 font-bold' : 'text-zinc-500 hover:bg-white/5'}`}>
                              <Users className="w-3.5 h-3.5 shrink-0" />
                              <span className="text-xs font-bold uppercase tracking-wider truncate">{glabels[gid] || 'Group'}</span>
                              <span className="text-[9px] text-zinc-600 ml-auto shrink-0" title="members">{count}</span>
                              {(unread[`G:${gid}`] || 0) > 0 && <span className="shrink-0 ml-1 min-w-[16px] h-4 px-1 rounded-full bg-emerald-500 text-black text-[9px] font-black flex items-center justify-center">{unread[`G:${gid}`] > 99 ? '99+' : unread[`G:${gid}`]}</span>}
                            </button>
                          );
                        })}
                      </div>
                    );
                  })()}
                  {/* Groups on OTHER branches I'm a cross-level VISITOR of. */}
                  {item.id === 'DESCENDANTS' && !hubMode && !dmMode && ((currentUser as any)?.visiting || []).length > 0 && (
                    <div className="pl-3 mt-0.5 space-y-0.5 border-l border-amber-500/20 ml-4">
                      {((currentUser as any).visiting as any[]).map(v => {
                        const on = activeTab === 'DESCENDANTS' && activeGroupId === v.g && !activeFilterId;
                        return (
                          <button key={v.g} onClick={() => { setActiveTab('DESCENDANTS'); setActiveGroupId(v.g); setActiveFilterId(null); setIsSidebarOpen(false); }}
                            className={`w-full flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all ${on ? 'bg-amber-500/10 text-amber-300 font-bold ring-1 ring-amber-500/20' : 'text-amber-500/70 hover:bg-white/5'}`}>
                            <Layers className="w-3.5 h-3.5 shrink-0 text-amber-500/80" />
                            <span className="text-xs font-bold uppercase tracking-wider truncate">{v.name}</span>
                            <span className="text-[8px] text-amber-500/50 ml-auto shrink-0" title={`Visiting · under ${v.ownerName || 'another branch'}`}>visiting</span>
                            {(unread[`G:${v.g}`] || 0) > 0 && <span className="ml-1 shrink-0 min-w-[16px] h-4 px-1 rounded-full bg-amber-500 text-black text-[9px] font-black flex items-center justify-center">{unread[`G:${v.g}`] > 99 ? '99+' : unread[`G:${v.g}`]}</span>}
                          </button>
                        );
                      })}
                    </div>
                  )}
                  {/* Linked cross-group chats: ones I own + ones my group is part of.
                      Active links are chat tabs; archived ones are read-only history. */}
                  {item.id === 'DESCENDANTS' && !hubMode && !dmMode && (() => {
                    const owned = (currentUser?.groupLinks) || {};
                    const inviter = users.find(u => u.id === currentUser?.invitedBy);
                    const mine = ((inviter as any)?.myLinks) || {};
                    const cross = ((currentUser as any)?.crossLinks) || {};
                    const entries: { lid: string; name: string; archived: boolean; owned: boolean; cross?: boolean }[] = [];
                    for (const lid of Object.keys(owned)) entries.push({ lid, name: (owned as any)[lid].name, archived: !!(owned as any)[lid].archived, owned: true, cross: !!(owned as any)[lid].crossLevel });
                    for (const lid of Object.keys(mine)) if (!entries.some(e => e.lid === lid)) entries.push({ lid, name: mine[lid].name, archived: !!mine[lid].archived, owned: false });
                    for (const lid of Object.keys(cross)) if (!entries.some(e => e.lid === lid)) entries.push({ lid, name: cross[lid].name, archived: !!cross[lid].archived, owned: false, cross: true });
                    const activeLinks = entries.filter(e => !e.archived);
                    const archivedLinks = entries.filter(e => e.archived);
                    if (!entries.length) return null;
                    const row = (e: { lid: string; name: string; owned: boolean }, arch: boolean) => {
                      const on = activeTab === 'DESCENDANTS' && activeGroupId === e.lid && !activeFilterId;
                      return (
                        <div key={e.lid} className="flex items-center group/lk">
                          <button onClick={() => { setActiveTab('DESCENDANTS'); setActiveGroupId(e.lid); setActiveFilterId(null); setIsSidebarOpen(false); }}
                            className={`flex-1 min-w-0 flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all ${on ? 'bg-amber-500/10 text-amber-300 font-bold ring-1 ring-amber-500/20' : `${arch ? 'text-zinc-600' : 'text-amber-500/70'} hover:bg-white/5`}`}>
                            <Link2 className={`w-3.5 h-3.5 shrink-0 ${arch ? 'text-zinc-600' : 'text-amber-500/80'}`} />
                            <span className="text-xs font-bold uppercase tracking-wider truncate">{e.name}</span>
                            {arch && <span className="text-[8px] text-zinc-700 ml-auto shrink-0">archived</span>}
                            {!arch && (unread[`G:${e.lid}`] || 0) > 0 && <span className="ml-auto shrink-0 min-w-[16px] h-4 px-1 rounded-full bg-amber-500 text-black text-[9px] font-black flex items-center justify-center">{unread[`G:${e.lid}`] > 99 ? '99+' : unread[`G:${e.lid}`]}</span>}
                          </button>
                          {e.owned && onSetGroups && (
                            <div className="shrink-0 flex items-center opacity-0 group-hover/lk:opacity-100 transition-opacity">
                              <button title={arch ? 'Restore this chat (keeps history)' : 'Unlink (archives the chat)'}
                                onClick={async () => { try { await onSetGroups(currentUser!.id, undefined, undefined, undefined, { [e.lid]: { archived: !arch } }); } catch (err: any) { alert(err?.message || 'Failed'); } }}
                                className="p-1 text-zinc-700 hover:text-amber-400 transition-colors">
                                {arch ? <Radio className="w-3 h-3" /> : <X className="w-3 h-3" />}
                              </button>
                              {arch && (
                                <button title="Delete permanently — erases this chat and its history"
                                  onClick={async () => { if (!window.confirm(`Permanently delete the archived “${e.name}” chat? Its message history is erased and cannot be recovered.`)) return; try { await onSetGroups(currentUser!.id, undefined, undefined, undefined, { [e.lid]: null }); } catch (err: any) { alert(err?.message || 'Failed'); } }}
                                  className="p-1 text-zinc-700 hover:text-red-400 transition-colors">
                                  <Trash2 className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    };
                    return (
                      <div className="pl-3 mt-0.5 space-y-0.5 border-l border-amber-500/20 ml-4">
                        {activeLinks.map(e => row(e, false))}
                        {archivedLinks.length > 0 && (
                          <details className="mt-0.5">
                            <summary className="text-[9px] text-zinc-700 uppercase tracking-widest px-3 py-1 cursor-pointer hover:text-zinc-500">Archived ({archivedLinks.length})</summary>
                            {archivedLinks.map(e => row(e, true))}
                          </details>
                        )}
                      </div>
                    );
                  })()}
                  </React.Fragment>
                  );
                })}
             </div>

             {!hubMode && !dmMode && (
             <div className="space-y-1">
                <div className="flex items-center justify-between px-2 mb-2">
                  <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em]">{t('side.directLinks')}</div>
                  {childrenNodes.length > 1 && onSetGroups && (
                    <button onClick={() => setGroupEditorOpen(true)} title="Organize invitees into groups"
                      className="text-[9px] font-black uppercase tracking-widest text-emerald-500 hover:text-emerald-400 px-1.5 py-0.5 rounded">Groups</button>
                  )}
                </div>
                {childrenNodes.length === 0 ? <div className="text-[10px] text-zinc-700 px-3 italic py-2">{t('status.isolatedNode')}</div> : (() => {
                    // Groups now live as tabs under Descendants (above). Here we simply
                    // list every direct invitee for 1:1 selection; tapping one opens
                    // that person and scopes to their group if they're in one.
                    const gmap = (currentUser?.inviteeGroups) || {};
                    return <>{childrenNodes.map(u => {
                        const n = unread[`C:${u.id}`] || 0;
                        return (
                        <div key={u.id} className={`w-full flex items-center gap-1 rounded-xl transition-all ${activeFilterId === u.id && activeTab === 'DESCENDANTS' ? 'bg-emerald-500/10 border border-emerald-500/20' : 'hover:bg-white/5'}`}>
                          <button onClick={() => { setActiveFilterId(u.id); setActiveGroupId(gidsOf(gmap[u.id])[0] || null); setActiveTab('DESCENDANTS'); setIsSidebarOpen(false); }}
                            className={`flex-1 min-w-0 flex items-center justify-between gap-2 px-3 py-2 text-left ${activeFilterId === u.id && activeTab === 'DESCENDANTS' ? 'text-emerald-400 font-bold' : 'text-zinc-500'}`}>
                            <div className="flex items-center gap-2.5 overflow-hidden text-left min-w-0">
                              <Avatar pid={u.id} name={u.name} color={u.color} avatarAt={u.avatarAt} viewerNodeId={currentUser?.id} size={22} />
                              <span className={`text-sm truncate ${n > 0 ? 'font-black text-white' : 'font-medium'}`}>{u.name}</span>
                            </div>
                            {n > 0 && (
                              <span className="shrink-0 min-w-[18px] h-[18px] px-1 rounded-full bg-emerald-500 text-black text-[10px] font-black flex items-center justify-center">{n > 99 ? '99+' : n}</span>
                            )}
                          </button>
                          <button onClick={() => setProfileTarget({ pid: u.id, name: u.name, color: u.color, avatarAt: u.avatarAt })}
                            className="p-1.5 mr-1 rounded-lg text-zinc-600 hover:text-emerald-400 hover:bg-white/5 transition-colors shrink-0" title={`View ${u.name}'s profile`} aria-label={`View ${u.name}'s profile`}>
                            <Info className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        );
                    })}</>;
                })()}
             </div>
             )}

             {joinRequests.length > 0 && (
             <div className="space-y-1">
                <div className="text-[10px] font-bold text-emerald-500 uppercase tracking-[0.2em] px-2 mb-2 flex items-center gap-2">
                  {hubMode ? t('side.contactRequests') : t('side.joinRequests')}
                  <span className="min-w-[18px] h-[18px] px-1 rounded-full bg-emerald-500 text-black text-[10px] font-black flex items-center justify-center">{joinRequests.length}</span>
                </div>
                {joinRequests.map(r => (
                  <JoinRequestItem key={r.id} req={r} onRespond={onRespondJoin} />
                ))}
                <p className="text-[9px] text-zinc-600 leading-relaxed px-2 pb-1">{hubMode
                  ? 'Only accept people you recognize — accepting opens a private chat between you, and you appear in their chats too. They get no access to anyone else you talk to.'
                  : 'Only accept aliases you recognize — anyone you accept joins directly under you.'}</p>
             </div>
             )}

             {plan && plan.isRoot && (
             <div className="space-y-1">
                <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em] px-2 mb-2">{isHubPlan ? 'Storage' : 'Network Plan'}</div>
                <div className="mx-1 p-3 rounded-2xl bg-black/40 border border-white/10 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-white">{isHubPlan ? 'Personal hub' : 'Your network'}</span>
                    {plan.premium
                      ? <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">Premium</span>
                      : plan.archived
                        ? <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full bg-red-500/15 text-red-300 border border-red-500/30">Archived</span>
                        : <span className="text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full bg-white/5 text-zinc-400 border border-white/10">Free plan</span>}
                  </div>
                  {!isHubPlan && (
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-zinc-500">Members</span>
                      <span className="font-mono font-bold text-zinc-200">{plan.premium ? `${plan.treeSize} / ${(plan.premiumLimit || 2000).toLocaleString()}` : `${plan.treeSize} / ${plan.limit}`}</span>
                    </div>
                  )}
                  {plan.media && plan.media.quota > 0 && (() => {
                    // This identity's stored media (sizes of its end-to-end encrypted
                    // attachments — the server never sees what's in them).
                    const pct = Math.min(100, (plan.media.used / plan.media.quota) * 100);
                    const high = pct >= 70;
                    const mb = (b: number) => b >= 1024 * 1024 * 1024 ? `${(b / 1024 / 1024 / 1024).toFixed(1)} GB` : `${Math.round(b / 1024 / 1024)} MB`;
                    return (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-zinc-500">Media storage</span>
                          <span className={`font-mono font-bold ${high ? 'text-red-400' : 'text-zinc-200'}`}>{mb(plan.media.used)} / {mb(plan.media.quota)}</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
                          <div className={`h-full rounded-full ${high ? 'bg-red-500' : 'bg-emerald-500'}`} style={{ width: `${Math.max(pct, plan.media.used ? 2 : 0)}%` }} />
                        </div>
                        {high && (
                          <div className="text-[9px] text-red-300/90 leading-relaxed">
                            {pct >= 100 ? 'Media storage is full — new photos and videos won’t send.' : 'Media storage is almost full.'} {plan.premium ? 'Delete large attachments' : 'Upgrade to Premium, or delete large attachments'} to free space.{plan.historyDays ? ` Media also expires on its own after ${fmtDays(plan.historyDays)}.` : ''}
                          </div>
                        )}
                      </div>
                    );
                  })()}
                  {isHubPlan && !plan.premium ? (
                    // A personal hub has no member limit — only the storage and
                    // history limits apply to it. It can still be upgraded.
                    <>
                      <div className="pt-1.5 border-t border-white/5 space-y-1">
                        {[['Message history', fmtDays(LIM.freeHistoryDays)], ['Attachments', fmtBytes(LIM.attachmentBytes) + ' / file']].map(([k, v]) => (
                          <div key={k} className="flex items-center justify-between text-[10px]"><span className="text-zinc-600">{k}</span><span className="text-zinc-400 font-mono">{v}</span></div>
                        ))}
                      </div>
                      <button onClick={() => { setUpgradeOpen(true); setBillingMsg(null); }}
                        className="w-full text-[10px] font-black uppercase tracking-widest py-2.5 rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all">Upgrade to Premium · ${plan.priceUsd}/mo</button>
                    </>
                  ) : plan.premium ? (
                    <>
                      {plan.premiumUntil ? <div className="text-[10px] text-zinc-500">{plan.cardSubscription?.renews ? 'Renews' : 'Active until'} {new Date(plan.premiumUntil).toLocaleDateString()}</div> : null}
                      {plan.isRoot && plan.cardSubscription && (
                        plan.cardSubscription.renews ? (
                          <button disabled={billingBusy}
                            onClick={async () => {
                              if (!currentUser) return;
                              if (!confirm('Cancel the card subscription? It stops renewing; Premium stays until the end of the period you already paid for.')) return;
                              setBillingBusy(true); setBillingMsg(null);
                              try { await api.billingCancel(currentUser.id); setBillingMsg('Subscription cancelled — Premium stays until the end of the paid period.'); }
                              catch (e: any) { setBillingMsg(e?.message || 'Could not cancel the subscription.'); }
                              api.billingStatus(currentUser.id).then(setPlan).catch(() => {});
                              setBillingBusy(false);
                            }}
                            className="w-full text-[10px] font-black uppercase tracking-widest py-2 rounded-lg bg-white/5 text-zinc-300 border border-white/10 hover:bg-red-500/10 hover:text-red-300 active:scale-95 transition-all disabled:opacity-40">
                            {billingBusy ? '…' : 'Cancel card subscription'}
                          </button>
                        ) : (
                          <>
                            <div className="text-[10px] text-amber-400/80">Card subscription cancelled — it won’t renew.</div>
                            <button disabled={billingBusy}
                              onClick={async () => {
                                if (!currentUser) return;
                                setBillingBusy(true); setBillingMsg(null);
                                try { await api.billingResume(currentUser.id); setBillingMsg('Subscription resumed — it renews as before.'); }
                                catch (e: any) { setBillingMsg(e?.message || 'Could not resume the subscription.'); }
                                api.billingStatus(currentUser.id).then(setPlan).catch(() => {});
                                setBillingBusy(false);
                              }}
                              className="w-full text-[10px] font-black uppercase tracking-widest py-2 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/25 active:scale-95 transition-all disabled:opacity-40">
                              {billingBusy ? '…' : 'Resume subscription'}
                            </button>
                          </>
                        )
                      )}
                      {billingMsg && <div className="text-[10px] text-zinc-400">{billingMsg}</div>}
                    </>
                  ) : (
                    <>
                      <div className="pt-1.5 border-t border-white/5 space-y-1">
                        <div className="text-[8px] font-black uppercase tracking-widest text-zinc-700 mb-0.5">Free plan includes</div>
                        {[['Max members', String(plan.limit)], ['Message history', fmtDays(LIM.freeHistoryDays)], ['Attachments', fmtBytes(LIM.attachmentBytes) + ' / file']].map(([k, v]) => (
                          <div key={k} className="flex items-center justify-between text-[10px]"><span className="text-zinc-600">{k}</span><span className="text-zinc-400 font-mono">{v}</span></div>
                        ))}
                      </div>
                      <button onClick={() => { setUpgradeOpen(true); setBillingMsg(null); }}
                        className="w-full text-[10px] font-black uppercase tracking-widest py-2.5 rounded-lg bg-emerald-500 text-black hover:bg-emerald-400 active:scale-95 transition-all">Upgrade to Premium · ${plan.priceUsd}/mo</button>
                    </>
                  )}
                  <button onClick={() => { setUpgradeOpen(true); setBillingMsg(null); }}
                    className="w-full text-[9px] font-bold uppercase tracking-widest text-zinc-500 hover:text-emerald-300 transition-colors py-0.5">Compare Free vs Premium</button>
                  <p className="text-[9px] text-zinc-600 leading-relaxed">{isHubPlan ? 'Arbor is free and open-source; donations help keep it running.' : 'Arbor is free for small networks and open-source. Premium lifts the limits; donations help keep it running.'}</p>
                  <button onClick={() => { setDonateOpen(true); setDonateErr(null); }}
                    className="w-full text-[10px] font-black uppercase tracking-widest py-2.5 rounded-lg bg-white/5 text-zinc-200 border border-white/10 hover:bg-white/10 active:scale-95 transition-all">Donate</button>
                </div>
             </div>
             )}

             {(dmMode || hubMode) && !isRootUser && !(dmMode && referralOpen) ? (
             <div className="space-y-1">
                <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em] px-2 mb-2">{hubMode ? 'Personal QR' : 'Invite QR'}</div>
                <p className="mx-1 p-3 rounded-2xl bg-black/40 border border-white/10 text-[10px] text-zinc-500 leading-relaxed">{hubMode ? 'This is a private line to the hub owner — only they can invite people.' : 'This is a Direct-Only network — only the network root can invite people.'}</p>
             </div>
             ) : inviteBlocked ? (
             <div className="space-y-1">
                <div className="text-[10px] font-bold text-amber-500 uppercase tracking-[0.2em] px-2 mb-2">Tree Limit Reached</div>
                <p className="mx-1 p-3 rounded-2xl bg-black/40 border border-white/10 text-[10px] text-zinc-500 leading-relaxed">{plan?.isRoot ? 'Upgrade to Premium to send more invites and keep growing your network.' : 'The network root has been notified — invites resume once they upgrade.'}</p>
             </div>
             ) : (
             <div className="space-y-1">
                <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em] px-2 mb-2">{hubMode ? 'Personal QR' : 'Invite QR'}</div>
                {permQr ? (
                  <div className="mx-1 p-3 rounded-2xl bg-black/40 border border-emerald-500/15 space-y-2.5">
                    <img src={permQr.dataUrl} alt="Invite QR" className="w-44 mx-auto block rounded-xl bg-[#0a0a0a] border border-white/5" />
                    <div className="text-center">
                      <div className="text-[9px] font-black uppercase tracking-widest text-zinc-600">{t('plan.scanToJoin')}</div>
                      <div className="text-[11px] font-mono font-bold text-emerald-400 tracking-wider mt-0.5 select-all">{permQr.code}</div>
                    </div>
                    <p className="text-[9px] text-zinc-600 leading-relaxed">{hubMode
                      ? 'This code stays the same until you refresh it. Anyone who scans or opens it can request a private chat with you — they never see or reach your other contacts. Rotate it if it leaks.'
                      : (dmMode && referralOpen && !isRootUser)
                      ? 'This code stays the same until you refresh it. Anyone who scans it is connected 1:1 with the network owner (never with you or each other), pending the owner’s approval. Rotate it if it leaks.'
                      : 'This code stays the same until you refresh it. Anyone who scans it joins directly under you — rotate it if it leaks.'}</p>
                    <div className="flex gap-1.5">
                      <button onClick={() => { navigator.clipboard?.writeText(permQr.link).catch(() => {}); flashSideTip('Link copied'); }}
                        className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-white/5 text-zinc-300 hover:bg-white/10 transition-colors">{t('plan.copyLink')}</button>
                      <button onClick={() => { if (confirm('Rotate the permanent invite? The old QR/link stops working immediately.')) loadPermQr(true); }} disabled={qrBusy}
                        className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50">{qrBusy ? '…' : 'New code'}</button>
                    </div>
                    {sideTip && <div className="text-center text-[9px] font-black uppercase tracking-widest text-emerald-500 animate-in fade-in">{sideTip}</div>}
                  </div>
                ) : (
                  <div className="text-[10px] text-zinc-700 px-3 italic py-2 flex items-center gap-2">
                    {qrBusy ? 'Generating…' : (<>
                      Unavailable
                      <button onClick={() => loadPermQr(false)} className="not-italic text-emerald-500 hover:text-emerald-400 font-black uppercase tracking-widest text-[9px] underline underline-offset-2">{t('plan.retry')}</button>
                    </>)}
                  </div>
                )}
             </div>
             )}

             <div className="space-y-1">
                <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-[0.2em] px-2 mb-2">{t('side.device')}</div>
                {/* Notifications: a user gesture is required to grant; tapping
                    again while ON unsubscribes this device (toggle off). */}
                <button
                  title={pushEnabled ? 'Tap to turn notifications off on this device' : 'Tap to enable notifications'}
                  onClick={async () => {
                    const wasOn = pushEnabled;
                    const p = await onEnableNotifications();
                    if (!wasOn && p === 'denied') alert('Notifications are blocked for this site. Enable them in your browser/OS settings, then try again. On iPhone, Arbor must be added to the Home Screen (Share → Add to Home Screen) first.');
                  }}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all ${pushEnabled ? 'text-emerald-400 bg-emerald-500/5' : 'text-zinc-500 hover:bg-white/5'}`}>
                  <Bell className="w-4 h-4 shrink-0" />
                  <span className="truncate text-sm">{pushEnabled ? 'Notifications On' : 'Enable Notifications'}</span>
                </button>
                {/* Biometric app lock (Face ID / Touch ID / Android biometrics). */}
                {bioAvailable && (
                  <button
                    onClick={async () => {
                      if (bioEnabled) { await appLock.disable(); setBioEnabled(false); return; }
                      setBioErr(null); setBioPw(''); setBioSetup(s => !s);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all ${bioEnabled ? 'text-emerald-400 bg-emerald-500/5' : 'text-zinc-500 hover:bg-white/5'}`}>
                    <Fingerprint className="w-4 h-4 shrink-0" />
                    <span className="truncate text-sm">{bioEnabled ? 'App Lock On (Face ID)' : 'Enable App Lock'}</span>
                  </button>
                )}
                {bioAvailable && bioSetup && !bioEnabled && (
                  <form className="px-3 pb-2 space-y-2" onSubmit={async (e) => {
                    e.preventDefault();
                    const who = state.account?.username;
                    if (!who || !bioPw) return;
                    setBioBusy(true); setBioErr(null);
                    try { await api.enableBiometricUnlock(who, bioPw); setBioEnabled(true); setBioSetup(false); }
                    catch (x: any) { setBioErr(x?.message || 'Biometric setup was cancelled or failed.'); }
                    finally { setBioBusy(false); setBioPw(''); }
                  }}>
                    <div className="text-[10px] text-zinc-500 leading-snug">Enter your password once. Arbor then keeps this device’s key sealed so only your biometrics (or the password) can open it.</div>
                    <input type="password" autoComplete="current-password" value={bioPw} onChange={e => setBioPw(e.target.value)} placeholder="Password"
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-emerald-500/50" />
                    <button type="submit" disabled={bioBusy || !bioPw} className="w-full text-[10px] font-black uppercase tracking-widest px-3 py-2 rounded-lg bg-emerald-500 text-black disabled:opacity-50">{bioBusy ? 'Setting up…' : 'Turn on App Lock'}</button>
                    {bioErr && <div className="text-[10px] text-red-400" role="alert">{bioErr}</div>}
                  </form>
                )}
                {/* Read receipts: only ever sends opaque message ids, and only if ON.
                    MUST go through toggleReceipts (server-synced): receipts are
                    reciprocal and the server enforces it from ITS copy of this
                    setting — a local-only flip would let someone stop sending
                    receipts while still receiving everyone else's. */}
                <button
                  disabled={settingsBusy}
                  onClick={() => toggleReceipts(!receiptsOn)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all ${receiptsOn ? 'text-emerald-400 bg-emerald-500/5' : 'text-zinc-500 hover:bg-white/5'} ${settingsBusy ? 'opacity-50' : ''}`}>
                  <CheckCheck className="w-4 h-4 shrink-0" />
                  <span className="truncate text-sm">{receiptsOn ? 'Read Receipts On' : 'Read Receipts Off'}</span>
                </button>
                {/* Panic wipe: local stores + server backup + session, gone in one action. */}
                <button
                  onClick={async () => {
                    if (!confirm('PANIC WIPE — this permanently erases all message history, encryption state and the encrypted backup for this device and account session. This cannot be undone. Continue?')) return;
                    if (!confirm('Are you absolutely sure? Everything on this device is destroyed.')) return;
                    await onPanicWipe();
                  }}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all text-zinc-600 hover:text-red-400 hover:bg-red-500/5">
                  <Trash2 className="w-4 h-4 shrink-0" />
                  <span className="truncate text-sm">{t('status.panicWipe')}</span>
                </button>
                <p className="text-[9px] text-red-500 font-bold leading-relaxed px-3 pt-1">Arbor is still in development. Please send bug reports to bugreports@arborsecure.app</p>
             </div>
          </div>
      </div>

      <div className="flex-1 min-w-0 overflow-x-hidden flex flex-col h-full bg-[#0a0a0a] relative">
        {/* Fixed h-16 + safe-area padding was squeezing the header under the iPhone
            notch; height now GROWS by the inset (plus a small cushion) instead. */}
        <header className="flex items-end px-4 md:px-8 justify-between border-b border-white/5 bg-[#0d0d0d]/90 backdrop-blur-md shrink-0 z-50"
                style={{ paddingTop: 'calc(env(safe-area-inset-top, 0px) + 6px)', minHeight: 'calc(4rem + env(safe-area-inset-top, 0px))' }}>
           <div className="flex items-center gap-4 pb-3">
              <button onClick={() => setIsSidebarOpen(true)} className="md:hidden p-2 text-zinc-400"><MenuIcon className="w-6 h-6" /></button>
              {hubMode && isRootUser && activeTab === 'DESCENDANTS' && activeFilterId && (
                <button onClick={() => setActiveFilterId(null)} title="Back to all chats" className="p-2 -ml-2 text-zinc-400 hover:text-white transition-colors">
                  <ChevronLeft className="w-5 h-5" />
                </button>
              )}
              <h2 className="text-sm font-black uppercase tracking-widest text-white truncate max-w-[45vw]">
                {activeTab === 'ANCESTORS' && activeGroupId
                  ? ((((users.find(u => u.id === currentUser?.invitedBy) as any)?.myGroupLabels) || {})[activeGroupId] || 'Group')
                  : activeTab === 'DESCENDANTS' && activeGroupId && ((currentUser?.groupLinks || {}) as any)[activeGroupId]
                  ? ((currentUser?.groupLinks || {}) as any)[activeGroupId].name
                  : activeTab === 'DESCENDANTS' && activeGroupId && (((users.find(u => u.id === currentUser?.invitedBy) as any)?.myLinks || {})[activeGroupId])
                  ? ((users.find(u => u.id === currentUser?.invitedBy) as any).myLinks[activeGroupId].name)
                  : activeTab === 'DESCENDANTS' && activeGroupId && (currentUser?.groupLabels || {})[activeGroupId]
                  ? (currentUser?.groupLabels || {})[activeGroupId]
                  : hubMode && activeTab === 'DESCENDANTS'
                  ? (activeFilterId ? (usersById.get(activeFilterId)?.name || 'Chat') : 'Chats')
                  : dmMode && activeTab === 'DESCENDANTS'
                  ? (activeFilterId ? (usersById.get(activeFilterId)?.name || t('nav.myInvitees')) : t('nav.myInvitees'))
                  : hubMode && activeTab === 'ANCESTORS' ? 'Chat'
                  : dmMode && activeTab === 'ANCESTORS' ? (inviterName || activeTab)
                  : activeTab}
              </h2>
           </div>
           <div className="flex items-center gap-2 pb-2.5">
              {(activeTab === 'ANCESTORS' || activeTab === 'DESCENDANTS') && !(hubMode && activeTab === 'DESCENDANTS' && !activeFilterId) && (
                <>
                  <button
                    title="Search this conversation (on-device)"
                    onClick={() => { setSearchOpen(o => !o); setSearchQuery(''); }}
                    className={`p-2 rounded-lg transition-colors ${searchOpen ? 'text-emerald-400 bg-emerald-500/10' : 'text-zinc-500 hover:text-white'}`}>
                    <Search className="w-4 h-4" />
                  </button>
                  {!selecting && visibleMessages.length > 0 && (
                    <button
                      title="Select messages to delete"
                      onClick={() => setSelecting(true)}
                      className="p-2 rounded-lg text-zinc-500 hover:text-white transition-colors">
                      <CheckSquare className="w-4 h-4" />
                    </button>
                  )}
                  {callTargets.length > 0 && callState.phase === 'idle' && (
                    <button
                      title={callTargets.length === 1 ? `Encrypted call: ${callTargets[0].name}` : `Encrypted group call (${callTargets.length} people)`}
                      onClick={() => callActions.start(callTargets).catch((e: any) => alert(e?.message === 'Microphone unavailable' ? 'Microphone permission is needed to call.' : 'Could not reach anyone — they may need to open the app once so encryption keys exist.'))}
                      className="p-2 rounded-lg text-zinc-500 hover:text-emerald-400 hover:bg-emerald-500/10 transition-colors">
                      <Phone className="w-4 h-4" />
                    </button>
                  )}
                </>
              )}
           </div>
        </header>
        {searchOpen && (activeTab === 'ANCESTORS' || activeTab === 'DESCENDANTS') && (
            <div className="px-4 md:px-8 py-2 bg-[#0d0d0d] border-b border-white/5 z-40 animate-in slide-in-from-top-1">
                <input autoFocus type="text" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search this conversation…"
                    className="w-full max-w-4xl mx-auto block bg-black border border-white/10 rounded-xl px-4 py-2.5 text-xs text-white outline-none focus:border-emerald-500/40 placeholder:text-zinc-700" />
            </div>
        )}

        {selecting && (
            <div className="px-4 md:px-8 py-2.5 bg-emerald-500/10 border-b border-emerald-500/20 z-40 animate-in slide-in-from-top-1 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                    <button onClick={exitSelect} className="text-zinc-400 hover:text-white"><X className="w-4 h-4" /></button>
                    <span className="text-xs font-black uppercase tracking-widest text-white">{selectedMsgs.size} {t('sel.selected')}</span>
                </div>
                <div className="flex items-center gap-2">
                    {selectedMsgs.size === 1 && (() => {
                        const only = messages.find(x => x.id === [...selectedMsgs][0]);
                        const editable = only && only.senderId === currentUser?.id && (only.text != null) && !only.callLog
                            && !only.imageUrl && !only.audioUrl && !only.videoUrl && !(only.attachments?.length)
                            && (Date.now() - only.timestamp) < EDIT_WINDOW_MS;
                        if (!editable || !only) return null;
                        return (
                            <button
                                onClick={() => { setEditingMsg(only); setComposer(only.text || ''); exitSelect(); setTimeout(() => messageInputRef.current?.focus(), 0); }}
                                className="text-[10px] font-black uppercase tracking-widest px-3 py-2 rounded-lg bg-white/10 text-zinc-200 hover:bg-white/20 transition-colors flex items-center gap-1.5">
                                <Pencil className="w-3.5 h-3.5" /> {t('sel.edit')}
                            </button>
                        );
                    })()}
                    <button
                        onClick={async () => {
                            if (!currentUser || selectedMsgs.size === 0) return;
                            const ids = [...selectedMsgs];
                            await onDeleteForMe(ids);
                            exitSelect();
                        }}
                        className="text-[10px] font-black uppercase tracking-widest px-3 py-2 rounded-lg bg-white/10 text-zinc-200 hover:bg-white/20 transition-colors">
                        {t('sel.deleteForMe')}
                    </button>
                    {allSelectedMine && (
                        <button
                            onClick={async () => {
                                if (!currentUser || selectedMsgs.size === 0) return;
                                if (!confirm(`Delete ${selectedMsgs.size} message${selectedMsgs.size > 1 ? 's' : ''} for everyone? This removes ${selectedMsgs.size > 1 ? 'them' : 'it'} from all recipients too.`)) return;
                                const ids = [...selectedMsgs];
                                await onDeleteForAll(ids);
                                exitSelect();
                            }}
                            className="text-[10px] font-black uppercase tracking-widest px-3 py-2 rounded-lg bg-red-500 text-white hover:bg-red-400 transition-colors flex items-center gap-1.5">
                            <Trash2 className="w-3.5 h-3.5" /> {t('sel.deleteForAll')}
                        </button>
                    )}
                </div>
            </div>
        )}

        <div className="flex-1 overflow-hidden flex flex-col relative">
            {activeTab === 'BROADCAST' && canAnnounce && (
                <div className="p-3 bg-[#111] border-b border-white/5 animate-in slide-in-from-top-2 z-40">
                    <div className="bg-black/40 rounded-2xl border border-white/5 overflow-hidden">
                        {ackDashboard.length > 0 && (
                            <button onClick={() => setAckDashOpen(true)}
                                className="w-full flex items-center gap-2.5 px-3.5 py-2 text-left border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                                <CheckCheck className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                                <span className="text-[10px] font-black uppercase tracking-widest text-zinc-300 flex-1">{t('bc.ackDashboard')}</span>
                                <span className="text-[9px] font-bold text-zinc-500">{ackDashboard.length} {t('bc.sent')}</span>
                                <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
                            </button>
                        )}
                        {/* Compact summary row — tap to expand the tree picker. */}
                        <button onClick={() => setAnnOpen(o => !o)}
                            className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-left hover:bg-white/[0.02] transition-colors">
                            <Megaphone className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                            <div className="flex-1 min-w-0">
                                <div className="text-[10px] font-black uppercase text-emerald-500 tracking-widest">{t('bc.reach')}</div>
                                <div className="text-[10px] text-zinc-400 truncate">{annTargets === 'ALL'
                                    ? t('bc.everyoneBelow')
                                    : `${Array.from(annTargets).length} ${Array.from(annTargets).length === 1 ? 'person' : 'people'} + everyone above them`}</div>
                            </div>
                            <ChevronDown className={`w-4 h-4 text-zinc-500 shrink-0 transition-transform ${annOpen ? 'rotate-180' : ''}`} />
                        </button>

                        {annOpen && (
                        <div className="fixed inset-0 z-[90] bg-[#0a0a0a] flex flex-col animate-in fade-in duration-200" style={{ paddingTop: 'calc(4rem + env(safe-area-inset-top, 0px) + 6px)' }}>
                            <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 shrink-0">
                                <div className="flex items-center gap-2">
                                    <Megaphone className="w-4 h-4 text-emerald-500" />
                                    <span className="text-[11px] font-black uppercase tracking-widest text-white">{t('bc.reach')}</span>
                                </div>
                                <button onClick={() => setAnnOpen(false)} title="Done — selection saved"
                                    className="text-[10px] font-black uppercase tracking-widest px-3.5 py-1.5 rounded-lg bg-emerald-500 text-black active:scale-95 transition-transform">Done</button>
                            </div>
                            <div className="flex-1 min-h-0 flex flex-col gap-2.5 p-4">
                            <div className="flex items-center gap-2">
                                <button onClick={() => setAnnTargets('ALL')}
                                    className={`text-[9px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg transition-colors ${annTargets === 'ALL' ? 'bg-emerald-500 text-black' : 'bg-white/5 text-zinc-400 hover:bg-white/10'}`}>
                                    {t('bc.everyoneBelow')}
                                </button>
                                {annTargets !== 'ALL' && Array.from(annTargets).length > 0 && (
                                    <button onClick={() => setAnnTargets(new Set())}
                                        className="text-[9px] font-black uppercase tracking-widest px-3 py-1.5 rounded-lg bg-white/5 text-zinc-400 hover:bg-white/10 transition-colors">
                                        {t('bc.clear')}
                                    </button>
                                )}
                            </div>
                            {/* Group chips: when you've organized invitees into groups,
                                target whole groups at once instead of picking individuals.
                                Tapping a group selects all its direct members. */}
                            {currentUser?.inviteeGroups && Object.keys(currentUser.inviteeGroups).length > 0 && (() => {
                                const gmap = currentUser.inviteeGroups || {};
                                const glabels = currentUser.groupLabels || {};
                                const gids: string[] = [];
                                for (const cid of Object.keys(gmap)) for (const g of gidsOf(gmap[cid])) if (!gids.includes(g)) gids.push(g);
                                // Map a group's member node ids to their public ids as used in annTargets.
                                const membersOf = (gid: string) => childrenNodes.filter(u => gidsOf(gmap[u.id]).includes(gid)).map(u => u.id);
                                return (
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                        <span className="text-[9px] font-black uppercase tracking-widest text-zinc-600 mr-1">Groups:</span>
                                        {gids.map(gid => {
                                            const mem = membersOf(gid);
                                            const sel = annTargets !== 'ALL' && mem.length > 0 && mem.every(id => (annTargets as Set<string>).has(id));
                                            return (
                                                <button key={gid} onClick={() => setAnnTargets(prev => {
                                                    const next = new Set(prev === 'ALL' ? [] : prev);
                                                    if (sel) mem.forEach(id => next.delete(id));
                                                    else mem.forEach(id => next.add(id));
                                                    return next;
                                                })}
                                                className={`text-[9px] font-black uppercase tracking-widest px-2.5 py-1.5 rounded-lg transition-colors ${sel ? 'bg-emerald-500 text-black' : 'bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20'}`}>
                                                    {glabels[gid] || 'Group'} · {mem.length}
                                                </button>
                                            );
                                        })}
                                    </div>
                                );
                            })()}
                            {/* The picker IS the network tree: tap a person to target them.
                                The tapped node and everyone ABOVE it light up as "Receives" —
                                that's exactly who gets it. Nobody below the tapped node does. */}
                            {monitorTree.length === 0 ? (
                                <div className="text-[10px] text-zinc-600 italic py-2">{t('status.noOneBelow')}</div>
                            ) : mySubtreeData && annOpen && (
                                <div className="flex-1 min-h-0">
                                <MiniTreeCanvas
                                    root={mySubtreeData}
                                    selectedIds={annTargets === 'ALL' ? new Set<string>() : annTargets}
                                    selectableIds={announceTargetIds}
                                    onTapNode={(id) => setAnnTargets(prev => {
                                        const next = new Set(prev === 'ALL' ? [] : prev);
                                        if (next.has(id)) { next.delete(id); return next; }
                                        // Chain-exclusive: a new pick supersedes any already-selected
                                        // node that lies on the SAME chain (an ancestor or a
                                        // descendant of it), because their receiving sets overlap.
                                        // e.g. selecting user5 cancels a user3 selection above it.
                                        const isOnChain = (a: string, b: string) => {
                                            let cur: string | undefined = b;
                                            for (let h = 0; cur && h < 200; h++) { if (cur === a) return true; cur = usersById.get(cur)?.invitedBy || undefined; }
                                            return false;
                                        };
                                        for (const sel of Array.from(next)) {
                                            if (isOnChain(sel, id) || isOnChain(id, sel)) next.delete(sel);
                                        }
                                        next.add(id);
                                        return next;
                                    })}
                                    heightClass="h-full"
                                />
                                </div>
                            )}
                            <div className="text-[9px] text-zinc-600 leading-relaxed">{annTargets === 'ALL'
                                ? 'This announcement will reach everyone below you.'
                                : `Reaching ${Array.from(annTargets).length} selected ${Array.from(annTargets).length === 1 ? 'person' : 'people'} and everyone on the chain above them. People below a selected person won't receive it.`}</div>
                            </div>
                        </div>
                        )}
                    </div>
                </div>
            )}

            {activeTab === 'HIERARCHY' ? (
                <div className="flex-1 flex flex-col overflow-hidden">
                    <div className="px-4 md:px-8 pt-4 pb-2 shrink-0">
                        <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                            <Waypoints className="w-5 h-5 text-emerald-500" />
                            {hasTrueSight ? (networkName || 'Network') : 'Your Branch'}
                        </h3>
                        <p className="text-[10px] text-zinc-500 uppercase tracking-widest font-medium mt-1">
                            {hasTrueSight ? 'True Sight — full network' : 'Your inviter, you, and everyone you invited'}
                            <span className="text-zinc-700 normal-case tracking-normal"> · drag to pan, scroll or pinch to zoom, tap a bubble</span>
                        </p>
                    </div>
                    {treeData ? (
                        <NetworkTreeCanvas
                            root={treeData}
                            onOpenProfile={setProfileTarget}
                            viewerNodeId={currentUser.id}
                            isRootUser={currentUser.role === 'ROOT'}
                            hasTrueSight={hasTrueSight}
                            dmMode={dmMode}
                            onPrune={handlePrune}
                            onToggleTrueSight={handleToggleTrueSight}
                            onToggleAnnounce={handleToggleAnnounce}
                            canManageGroups={canManageGroups}
                            manageableNodeIds={manageableNodeIds}
                            inviteesOf={inviteesOf}
                            onCreateGroup={createGroup}
                            onRenameGroup={renameGroup}
                            onDeleteGroup={deleteGroup}
                            onAssignToGroup={assignToGroup}
                            onGetGroupInvite={getGroupInvite}
                            groupsOf={groupsOf}
                            linksOf={linksOf}
                            linkEdges={linkEdges}
                            crossLevelEdges={crossLevelEdges}
                            onLinkGroups={linkGroups}
                            rootNodeId={isRootUser ? currentUser.id : undefined}
                            rootCrossLinks={rootCrossLinks}
                            onCreateCrossLink={createCrossLink}
                            onUpdateCrossLink={updateCrossLink}
                            onUpdateLink={updateLink}
                            onArchiveLink={archiveLink}
                            onDeleteLink={deleteLink}
                            onMoveNode={onMoveNode}
                            onEditMemberGroups={editMemberGroups}
                            onSetGroupVisitors={(ownerId, visitors) => onSetGroups!(ownerId, undefined, undefined, undefined, undefined, visitors)}
                        />
                    ) : (
                        <div className="flex-1 flex items-center justify-center text-[10px] text-zinc-600 italic">{t('status.noNodes')}</div>
                    )}
                </div>
            ) : activeTab === 'DESCENDANTS' && hubMode && !activeFilterId ? (
                <HubChatsView
                    contacts={hubContacts}
                    messages={messages}
                    me={currentUser}
                    lastSeen={lastSeen}
                    seenFallback={firstLoadRef.current}
                    onOpenChat={(id) => setActiveFilterId(id)}
                    onCopyInvite={copyHubInvite}
                    inviteBusy={hubInviteBusy}
                    copiedTip={hubTip}
                    onOpenProfile={setProfileTarget}
                />
            ) : activeTab === 'DESCENDANTS' && dmMode && !activeFilterId ? (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center animate-in fade-in duration-500">
                    <ArrowDownRight className="w-8 h-8 text-zinc-700 mb-3" />
                    <h3 className="text-sm font-bold text-white mb-1">{t('nav.myInvitees')}</h3>
                    <p className="text-[11px] text-zinc-500 max-w-xs leading-relaxed">Pick someone under <span className="text-emerald-400 font-semibold">{t('nav.myInvitees')}</span> in the sidebar to open your 1:1 conversation with them.</p>
                </div>
            ) : activeTab === 'MONITOR' && !selectedMonitorNodeId ? (
                <div className="flex-1 flex flex-col p-4 md:p-8 space-y-4 animate-in fade-in duration-500 overflow-hidden">
                    <div className="text-center max-w-md mx-auto shrink-0">
                        <h3 className="text-lg font-bold text-white mb-2 tracking-tight flex items-center justify-center gap-2"><Monitor className="w-5 h-5 text-emerald-500" /> {t('mon.selectTarget')}</h3>
                        <p className="text-[10px] text-zinc-500 uppercase tracking-widest font-medium leading-relaxed">Tap someone on the tree to view their conversation with the people THEY invited. Monitoring reaches at most <span className="text-emerald-400">2 levels below you</span> — no one, including the founder, can monitor deeper.</p>
                    </div>
                    {monitorTree.length === 0 ? (
                        <div className="text-center text-[10px] text-zinc-600 italic py-8">{t('mon.noSubnodes')}</div>
                    ) : mySubtreeData && (
                        <div className="flex-1 min-h-0 max-w-3xl w-full mx-auto">
                            <MiniTreeCanvas
                                root={mySubtreeData}
                                selectedIds={new Set<string>()}
                                selectableIds={monitorableIds}
                                onTapNode={(id) => setSelectedMonitorNodeId(id)}
                                heightClass="h-full min-h-[280px]"
                                unselectableHint="Out of monitoring range (more than 2 levels below) or no invitees to monitor"
                            />
                        </div>
                    )}
                    <p className="text-[9px] text-zinc-600 text-center shrink-0">Dimmed people are either leaves (no invitees) or more than 2 levels below you — out of monitoring range.</p>
                </div>
            ) : activeTab === 'HOWTO' ? (
                <HowToView dmMode={dmMode} hubMode={hubMode} hasTrueSight={hasTrueSight} isRootUser={!!isRootUser} canAnnounce={canAnnounce} />
            ) : activeTab === 'SETTINGS' ? (
                <SettingsView
                    receiptsOn={receiptsOn} onToggleReceipts={toggleReceipts} settingsBusy={settingsBusy}
                    recoveryStatus={recoveryStatus}
                    accountUsername={state.account?.username || null}
                    onSetupRecovery={async (password) => {
                      const phrase = await api.setupRecovery(state.account!.username, password);
                      setRecoveryStatus(true);
                      return phrase;
                    }}
                    pushEnabled={pushEnabled} onToggleNotifications={onEnableNotifications} notifPermission={notifPermission}
                    notifyPref={notifyPref} onNotifyPref={updateNotifyPref}
                    isRootUser={!!isRootUser} onPanicWipe={onPanicWipe} onDeleteTree={onDeleteTree}
                    dmMode={dmMode} hubMode={hubMode}
                    networkNameVisible={nameVisibleToAll}
                    onUpdateTreeSettings={onUpdateTreeSettings}
                    onUpdateColor={onUpdateColor}
                    onUpdateName={onUpdateName}
                    onUpdateProfile={onUpdateProfile}
                    startTab={startTab}
                    startTabOptions={navItems.filter(n => n.id !== 'SETTINGS' && n.id !== 'HOWTO').map(n => ({ id: n.id, label: n.label }))}
                    onStartTab={(id) => { if (currentUser) writeStartTab(currentUser.id, id); setStartTab(id); }}
                    currentUser={currentUser} users={users} />
            ) : (
                <div ref={scrollRef} className="flex-1 overflow-y-auto overscroll-contain py-4 px-6 md:p-8 space-y-3 no-scrollbar relative"
                    onScroll={onListScroll}
                    onTouchStart={e => { if ((scrollRef.current?.scrollTop ?? 1) <= 0) composerTouchStart.current = e.touches[0]?.clientY ?? null; else composerTouchStart.current = null; }}
                    onTouchMove={e => {
                        // Swiping down at the top of the chat dismisses the keyboard —
                        // the natural mobile gesture, in addition to swiping the composer.
                        if (composerTouchStart.current !== null) {
                            const dy = (e.touches[0]?.clientY ?? 0) - composerTouchStart.current;
                            if (dy > 60) { messageInputRef.current?.blur(); composerTouchStart.current = null; }
                        }
                    }}
                    onTouchEnd={() => { composerTouchStart.current = null; }}>
                    {/* Pinned message banner — one per conversation, tap to jump */}
                    {pinnedMid && !['MONITOR', 'HIERARCHY', 'HOWTO', 'SETTINGS'].includes(activeTab) && (() => {
                      const pm = messages.find(x => x.id === pinnedMid);
                      if (!pm) return null;
                      const pName = usersById.get(pm.senderId)?.name || 'Unknown';
                      const preview = pm.text || (pm.callLog ? 'Call' : pm.audioUrl ? '🎤 Voice message' : pm.imageUrl ? '📷 Photo' : pm.videoUrl ? '🎬 Video' : '📎 Attachment');
                      return (
                        <div className="sticky top-0 z-20 flex items-center gap-2 bg-[#141414]/95 backdrop-blur-md px-3 py-2 rounded-2xl border border-amber-500/25 mb-6 shadow-xl">
                          <Pin className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <button onClick={() => jumpToMessage(pinnedMid!)} className="flex-1 min-w-0 text-left">
                            <div className="text-[9px] font-black uppercase tracking-widest text-amber-400/80">Pinned · {pName}</div>
                            <div className="text-[11px] text-zinc-400 truncate">{preview}</div>
                          </button>
                          <button onClick={() => pinMessage(null)} title="Unpin" className="shrink-0 text-zinc-600 hover:text-red-400 p-1"><X className="w-3.5 h-3.5" /></button>
                        </div>
                      );
                    })()}
                    {activeTab === 'MONITOR' && selectedMonitorNodeId && (() => {
                        const monTarget = users.find(u => u.id === selectedMonitorNodeId);
                        const monLabels = (monTarget as any)?.groupLabels as Record<string, string> | undefined;
                        const monGids = monLabels ? Object.keys(monLabels) : [];
                        const chip = (val: string | null, label: string) => (
                          <button key={val ?? 'ALL'} onClick={() => setMonGroup(val)}
                            className={`shrink-0 px-2.5 py-1 rounded-full text-[9px] font-black uppercase tracking-widest transition-colors ${monGroup === val ? 'bg-emerald-500 text-black' : 'bg-white/5 text-zinc-400 hover:text-white'}`}>
                            {label}
                          </button>
                        );
                        return (
                        <div className="sticky top-0 z-20 bg-[#111] backdrop-blur-md p-4 rounded-2xl border border-emerald-500/20 mb-8 shadow-2xl space-y-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3 min-w-0">
                                    <Activity className="w-4 h-4 text-emerald-500 animate-ping shrink-0" />
                                    <span className="text-[10px] font-black uppercase text-emerald-500 tracking-widest truncate">{t('mon.activeTrace')}: {monTarget?.name}</span>
                                </div>
                                <button onClick={() => setSelectedMonitorNodeId(null)} className="p-2 hover:bg-white/5 rounded-full transition-colors shrink-0"><X className="w-4 h-4 text-zinc-500 hover:text-white"/></button>
                            </div>
                            {monGids.length > 0 && (
                              <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar -mx-1 px-1">
                                <span className="text-[8px] font-black uppercase tracking-widest text-zinc-600 shrink-0 mr-1">Chat:</span>
                                {chip(null, 'All')}
                                {chip('MAIN', 'Main')}
                                {monGids.map(gid => chip(gid, monLabels![gid]))}
                              </div>
                            )}
                        </div>
                        );
                    })()}
                    
                    {hasOlderToLoad && (
                        <button onClick={loadOlder}
                            className="mx-auto mb-1 px-3 py-1.5 rounded-full bg-white/5 border border-white/10 text-[10px] font-black uppercase tracking-widest text-zinc-400 hover:text-white hover:border-emerald-500/40 transition-colors">
                            Load earlier messages
                        </button>
                    )}
                    {visibleMessages.length === 0 ? (
                        <div className="h-full flex flex-col items-center justify-center text-zinc-700 opacity-30 select-none">
                            <Layers className="w-12 h-12 mb-4" />
                            <span className="text-[10px] font-black uppercase tracking-[0.4em]">{searchOpen && searchQuery ? t('common.noMatchesShort') : t('common.noSignal')}</span>
                        </div>
                    ) : windowedMessages.map((m, idx) => {
                        const sender = usersById.get(m.senderId);
                        const mMid = m.id;
                        const prev = idx > 0 ? windowedMessages[idx - 1] : null;
                        const showDate = !prev || dayKey(prev.timestamp) !== dayKey(m.timestamp);
                        const showUnread = m.id === firstUnreadId;
                        // Group consecutive messages from the same sender sent close together
                        // (Signal-style): tighten the gap and hide the repeated name/avatar.
                        const GROUP_WINDOW_MS = 30 * 60 * 1000; // 30 minutes
                        const grouped = !!prev && !showDate && !showUnread
                            && prev.senderId === m.senderId
                            && !prev.callLog && !m.callLog
                            && (m.timestamp - prev.timestamp) < GROUP_WINDOW_MS;
                        // Look ahead: does the NEXT message continue this run? If so we flatten
                        // this bubble's bottom corners so the two visually fuse into one block.
                        const next = idx < windowedMessages.length - 1 ? windowedMessages[idx + 1] : null;
                        const groupedNext = !!next
                            && dayKey(next.timestamp) === dayKey(m.timestamp)
                            && next.id !== firstUnreadId
                            && next.senderId === m.senderId
                            && !m.callLog && !next.callLog
                            && (next.timestamp - m.timestamp) < GROUP_WINDOW_MS;
                        const node = <MessageItem key={m.id} message={mMid && ackedMids.has(mMid) && m.ackRequested ? { ...m, ackRequested: false } : m} isMe={m.senderId === currentUser.id} sender={sender} isInviterTag={sender?.id === currentUser?.invitedBy}
                            grouped={grouped} groupedNext={groupedNext}
                            selecting={selecting} selected={selectedMsgs.has(m.id)} onToggleSelect={toggleSelect} onLongPress={setActionSheetMid}
                            onReply={(msg) => { setReplyingTo(msg); messageInputRef.current?.focus(); }}
                            onJumpTo={jumpToMessage}
                            onReact={onReact}
                            onVerifyIdentity={handleVerifyIdentity}
                            myId={currentUser.id}
                            mentionNames={mentionNames} selfNames={selfNames}
                            animate={m.timestamp > convOpenedAt}
                            onAcknowledge={async (mid) => { setAckedMids(prev => new Set(prev).add(mid)); await onAcknowledge(mid); }} />;
                        if (showDate || showUnread) {
                            return (
                                <React.Fragment key={`f-${m.id}`}>
                                    {showDate && <DateDivider ts={m.timestamp} />}
                                    {showUnread && (
                                        <div className="flex items-center gap-2 my-2 select-none">
                                            <div className="flex-1 h-px bg-emerald-500/25" />
                                            <span className="text-[9px] font-black uppercase tracking-[0.2em] text-emerald-500">{t('msg.unread')}</span>
                                            <div className="flex-1 h-px bg-emerald-500/25" />
                                        </div>
                                    )}
                                    {node}
                                </React.Fragment>
                            );
                        }
                        return node;
                    })}
                </div>
            )}
        </div>

        {/* Typing indicator (1:1 conversations) */}
        {peerTyping && !['HIERARCHY', 'HOWTO', 'SETTINGS', 'MONITOR'].includes(activeTab) && !(hubMode && activeTab === 'DESCENDANTS' && !activeFilterId) && (
            <div className="px-5 md:px-8 pb-1 -mt-1 flex items-center gap-2 animate-in fade-in">
                <div className="flex items-center gap-1 bg-[#151515] border border-white/5 rounded-full px-2.5 py-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
                <span className="text-[10px] text-zinc-500 font-medium">{peerTyping} is typing…</span>
            </div>
        )}

        {/* Jump-to-bottom: appears when scrolled up; badges new messages that
            arrived below the fold. */}
        {!atBottom && !['HIERARCHY', 'HOWTO', 'SETTINGS', 'MONITOR'].includes(activeTab) && !(hubMode && activeTab === 'DESCENDANTS' && !activeFilterId) && (
            <button onClick={scrollToBottom}
                className="absolute right-4 md:right-8 bottom-28 z-30 flex items-center gap-1.5 pl-2.5 pr-3 py-2 rounded-full bg-[#1a1a1a] border border-white/10 shadow-2xl text-zinc-300 hover:text-white hover:border-emerald-500/40 transition-all active:scale-95 animate-in fade-in slide-in-from-bottom-2">
                <ChevronDown className="w-4 h-4" />
                {newBelow > 0 && <span className="text-[10px] font-black text-emerald-400">{newBelow > 99 ? '99+' : newBelow} new</span>}
            </button>
        )}

        {activeTab === 'BROADCAST' && !canAnnounce && (
            <div className="p-4 border-t border-white/5 bg-[#0d0d0d] text-center">
                <span className="text-[10px] text-zinc-600 uppercase tracking-widest font-bold">{t('bc.receiveOnly')}</span>
            </div>
        )}
        {activeLinkArchived && (
          <div className="px-4 py-3 text-center text-[10px] text-zinc-600 uppercase tracking-widest border-t border-white/5 shrink-0">Archived chat — read only. Re-link the groups to reopen it.</div>
        )}
        {activeTab !== 'HIERARCHY' && activeTab !== 'HOWTO' && activeTab !== 'SETTINGS' && activeTab !== 'MONITOR' && (activeTab !== 'BROADCAST' || canAnnounce) && !(hubMode && activeTab === 'DESCENDANTS' && !activeFilterId) && !activeLinkArchived && (
            archived ? (
              <div className="shrink-0 px-4 pt-1.5 pb-2 md:px-8 md:pt-4 md:pb-6 bg-[#0a0a0a] border-t border-red-500/20 z-50" style={{ paddingBottom: 'max(0.25rem, calc(env(safe-area-inset-bottom, 0px) - 1.25rem))' }}>
                <div className="max-w-4xl mx-auto p-4 rounded-2xl bg-red-500/10 border border-red-500/30 text-center space-y-1">
                  <div className="flex items-center justify-center gap-2 text-red-400">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-xs font-black uppercase tracking-widest">{t('plan.networkArchived')}</span>
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed">This network's subscription lapsed. Messaging and calls are suspended.{plan?.isRoot ? ' Restore it from the Network Plan panel in the sidebar, or delete it in Settings.' : ' The network root has been notified.'}</p>
                </div>
              </div>
            ) : (
            <div className="shrink-0 px-4 pt-1.5 pb-2 md:px-8 md:pt-4 md:pb-6 bg-[#0a0a0a] border-t border-white/5 z-50" style={{ paddingBottom: 'max(0.25rem, calc(env(safe-area-inset-bottom, 0px) - 1.25rem))' }}>
                <div className="max-w-4xl mx-auto space-y-2">
                    {/* Metadata-scrub status/feedback */}
                    {(mediaBusy || scrubNote) && (
                        <div className="px-1 text-[10px] font-black uppercase tracking-widest text-zinc-500 flex items-center gap-2 animate-in fade-in slide-in-from-bottom-1">
                            {mediaBusy ? (<><Loader2 className="w-3 h-3 animate-spin text-emerald-500 shrink-0" /> Processing media…</>) : (<><Info className="w-3 h-3 text-emerald-500 shrink-0" /> <span className="normal-case font-bold tracking-normal text-zinc-400">{scrubNote}</span></>)}
                        </div>
                    )}
                    {/* Pending-attachment previews */}
                    {(imagePayloads.length > 0 || videoPayload || audioPayload) && (
                        <div className="flex flex-wrap items-center gap-2 px-1">
                            {imagePayloads.map((img, i) => (
                                <div key={i} className="relative group">
                                    <img src={img} alt="" className="w-14 h-14 object-cover rounded-xl border border-white/10" />
                                    <button onClick={() => setImagePayloads(prev => prev.filter((_, j) => j !== i))}
                                        className="absolute -top-1.5 -right-1.5 bg-black border border-white/20 rounded-full p-0.5 text-zinc-400 hover:text-red-400">
                                        <X className="w-3 h-3" />
                                    </button>
                                </div>
                            ))}
                            {imagePayloads.length > 0 && (
                                <button title="Add more images" onClick={() => fileInputRef.current?.click()}
                                    className="w-14 h-14 rounded-xl border border-dashed border-white/15 text-zinc-600 hover:text-emerald-400 hover:border-emerald-500/30 flex items-center justify-center transition-colors">
                                    <ImageIcon className="w-5 h-5" />
                                </button>
                            )}
                            {videoPayload && (
                                <div className="flex items-center gap-2 bg-black/50 border border-white/10 rounded-xl px-3 py-1.5">
                                    <Film className="w-3.5 h-3.5 text-emerald-500" />
                                    <span className="text-[10px] text-zinc-400 uppercase tracking-widest font-black">Video</span>
                                    <button onClick={() => setVideoPayload(null)} className="text-zinc-600 hover:text-red-400"><X className="w-3.5 h-3.5" /></button>
                                </div>
                            )}
                            {audioPayload && (
                                <div className="flex items-center gap-2 bg-black/50 border border-white/10 rounded-2xl px-2 py-1.5 w-full sm:w-auto">
                                    <VoicePlayer url={audioPayload} peaks={audioPeaks || undefined} durMs={audioDurMs || undefined} />
                                    <button onClick={() => setAudioPayload(null)} title="Discard recording" className="shrink-0 text-zinc-600 hover:text-red-400 p-1"><X className="w-4 h-4" /></button>
                                </div>
                            )}
                        </div>
                    )}

                    {(() => {
                        // v72 B3: a 1:1 chat whose peer's security key changed is paused
                        // (the app won't encrypt to or call the new key) until re-trusted.
                        const pid = resolveTargetUserId();
                        const peer = pid ? usersById.get(pid) : undefined;
                        if (!peer || (peer as any).keyStatus !== 'changed' || reTrusted.has(peer.id)) return null;
                        return (
                            <div className="mb-2 flex items-center gap-2 bg-red-500/5 border border-red-500/30 rounded-2xl px-3 py-2">
                                <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                <div className="flex-1 min-w-0 text-[11px] text-red-200 leading-snug">{peer.name}’s security key changed. Messages and calls to them are paused until you compare your safety number and accept the new key.</div>
                                <button onClick={() => handleVerifyIdentity(peer.id)} className="shrink-0 text-[9px] font-black uppercase tracking-widest px-2.5 py-1.5 rounded-lg bg-red-500/15 text-red-300 hover:bg-red-500/25">Compare</button>
                            </div>
                        );
                    })()}

                    {(() => {
                        const mine = pendingScheduled.filter(s => s.tab === activeTab && (s.targetUserId || undefined) === (resolveTargetUserId() || undefined));
                        if (!mine.length) return null;
                        return (
                            <div className="mb-2 space-y-1">
                                {mine.map(s => (
                                    <div key={s.id} className="flex items-center gap-2 bg-[#121212] border border-emerald-500/20 rounded-2xl px-3 py-2 animate-in fade-in">
                                        <Clock className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-[9px] font-black uppercase tracking-wide text-emerald-400">{t('comp.scheduled')} · {new Date(s.fireAt).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                                            <div className="text-[11px] text-zinc-400 truncate">{s.text}</div>
                                        </div>
                                        <button onClick={async () => {
                                            if (s.serverId && currentUser) { try { await api.cancelScheduledServer(currentUser.id, s.serverId); } catch {} }
                                            scheduledStore.removeScheduled(s.id); refreshScheduled();
                                        }} className="text-zinc-600 hover:text-red-400 shrink-0 p-1"><X className="w-3.5 h-3.5" /></button>
                                    </div>
                                ))}
                            </div>
                        );
                    })()}
                    {editingMsg && (
                        <div className="flex items-center gap-2 bg-[#121212] border border-amber-500/30 rounded-2xl px-3 py-2 mb-2 animate-in fade-in slide-in-from-bottom-1">
                            <Pencil className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                            <div className="flex-1 min-w-0">
                                <div className="text-[9px] font-black uppercase tracking-wide text-amber-400">{t('comp.editing')}</div>
                                <div className="text-[11px] text-zinc-400 truncate">{editingMsg.text}</div>
                            </div>
                            <button onClick={() => { setEditingMsg(null); setComposer(''); }} className="text-zinc-600 hover:text-white shrink-0 p-1"><X className="w-3.5 h-3.5" /></button>
                        </div>
                    )}
                    {replyingTo && (
                        <div className="flex items-center gap-2 bg-[#121212] border border-emerald-500/20 rounded-2xl px-3 py-2 mb-2 animate-in fade-in slide-in-from-bottom-1">
                            <Reply className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                            <div className="flex-1 min-w-0">
                                <div className="text-[9px] font-black uppercase tracking-wide text-emerald-400">{usersById.get(replyingTo.senderId)?.name || 'Unknown'}</div>
                                <div className="text-[11px] text-zinc-400 line-clamp-2 break-words">{replyingTo.text || (replyingTo.attachments?.length ? '📎 Attachment' : '')}</div>
                            </div>
                            <button onClick={() => setReplyingTo(null)} className="text-zinc-600 hover:text-white shrink-0 p-1"><X className="w-3.5 h-3.5" /></button>
                        </div>
                    )}
                    {activeTab === 'BROADCAST' && (
                        <label className="flex items-center gap-2 px-3 pb-1.5 cursor-pointer w-fit">
                            <input type="checkbox" checked={reqAck} onChange={e => setReqAck(e.target.checked)} className="accent-emerald-500 w-3.5 h-3.5" />
                            <span className="text-[9px] font-black uppercase tracking-widest text-zinc-500">{t('comp.reqAck')}</span>
                        </label>
                    )}
                    {/* Compact control strip ABOVE the input so the message bar can be full-width */}
                    {!isRecording && (
                    <div className="flex items-center gap-2 px-2 pb-1.5">
                        {/* Metadata scrubbing: OFF -> STANDARD -> DEEP (cycles) */}
                        <button
                            title={scrubMeta === 'DEEP' ? 'DEEP scrub — photos & videos fully scrubbed (verified); voice notes re-synthesized too' : scrubMeta === 'STANDARD' ? 'Scrub ON — location, device & capture-time metadata removed from photos & MP4/MOV videos (verified); unscrubbable videos are blocked' : 'Scrubbing OFF — media sent as-is'}
                            onClick={() => setScrubMeta(v => {
                                const next = v === 'OFF' ? 'STANDARD' : v === 'STANDARD' ? 'DEEP' : 'OFF';
                                flashTip(next === 'STANDARD' ? 'Metadata scrub: ON — location, device and capture-time metadata is removed from photos and MP4/MOV videos, and checked before sending. Videos that can’t be scrubbed are blocked.'
                                  : next === 'DEEP' ? 'Metadata scrub: DEEP — same full photo/video scrub, plus voice notes are re-synthesized so no recording container survives.'
                                  : 'Metadata scrub: OFF — media will be sent exactly as-is, including any GPS/EXIF data.');
                                return next;
                            })}
                            className={`shrink-0 relative flex items-center gap-1 px-2 py-1 rounded-lg transition-colors ${scrubMeta === 'DEEP' ? 'text-emerald-300 bg-emerald-500/10' : scrubMeta === 'STANDARD' ? 'text-emerald-500 bg-emerald-500/5' : 'text-zinc-600 hover:text-zinc-400'}`}>
                            <Eraser className="w-4 h-4" />
                            <span className="text-[9px] font-black uppercase tracking-wide">{scrubMeta === 'OFF' ? 'Scrub' : scrubMeta}</span>
                        </button>

                        {/* Disappearing-message TTL */}
                        <div className="flex items-center gap-1 shrink-0">
                            <Timer className={`w-4 h-4 ${ttlSeconds > 0 ? 'text-amber-500' : 'text-zinc-600'}`} />
                            <select
                                value={ttlSeconds}
                                onChange={e => {
                                    const v = parseInt(e.target.value);
                                    setTtlSeconds(v);
                                    flashTip(v === 0 ? 'Disappearing messages: OFF — messages stay until deleted.'
                                      : `Disappearing messages: each message you send will self-destruct for everyone ${v === 30 ? '30 seconds' : v === 300 ? '5 minutes' : v === 3600 ? '1 hour' : '1 day'} after sending.`);
                                }}
                                title="Disappearing message timer"
                                className="bg-black border border-white/10 rounded-lg text-[10px] font-black uppercase tracking-widest text-zinc-300 py-1 px-1 outline-none focus:border-amber-500/40">
                                <option value={0}>Off</option>
                                <option value={30}>30s</option>
                                <option value={300}>5m</option>
                                <option value={3600}>1h</option>
                                <option value={86400}>1d</option>
                            </select>
                        </div>

                        {/* Scheduler */}
                        {!editingMsg && imagePayloads.length === 0 && !audioPayload && !videoPayload && (
                            <div className="relative shrink-0">
                                <button onClick={() => { setScheduleOpen(o => !o); if (!scheduleAt) { const d = new Date(Date.now() + 3600000); d.setSeconds(0, 0); setScheduleAt(toLocalInputValue(d)); } }}
                                    title="Schedule this message"
                                    className={`flex items-center gap-1 px-2 py-1 rounded-lg transition-colors ${scheduleOpen ? 'text-emerald-400 bg-emerald-500/10' : 'text-zinc-600 hover:text-zinc-400'}`}>
                                    <Clock className="w-4 h-4" />
                                    <span className="text-[9px] font-black uppercase tracking-wide">Schedule</span>
                                </button>
                                {scheduleOpen && (
                                  <>
                                    {/* Backdrop covers the CHAT area only — it stops above the
                                        composer so tapping the message box to type doesn't dismiss
                                        the scheduler. Close by tapping the chat, or the X. */}
                                    <div className="fixed inset-x-0 top-0 bottom-28 z-40" onClick={() => setScheduleOpen(false)} />
                                    <div className="fixed inset-x-4 bottom-36 mx-auto sm:absolute sm:inset-x-auto sm:bottom-10 sm:left-0 sm:mx-0 z-50 w-auto sm:w-64 max-w-[calc(100vw-2rem)] sm:max-w-sm box-border bg-[#141414] border border-white/10 rounded-2xl shadow-2xl p-3 space-y-2.5 animate-in fade-in slide-in-from-bottom-2" onClick={e => e.stopPropagation()}>
                                        <div className="flex items-center justify-between">
                                          <div className="text-[10px] font-black uppercase tracking-widest text-emerald-500">{t('comp.scheduleTitle')}</div>
                                          <button type="button" onClick={() => setScheduleOpen(false)} title="Close" className="text-zinc-500 hover:text-white p-1 -m-1"><X className="w-4 h-4" /></button>
                                        </div>
                                        <div className="flex gap-2 w-full">
                                            <input type="date"
                                                value={(scheduleAt || '').split('T')[0] || ''}
                                                min={toLocalInputValue(new Date()).split('T')[0]}
                                                onChange={e => { const time = (scheduleAt || '').split('T')[1] || '09:00'; setScheduleAt(`${e.target.value}T${time}`); }}
                                                style={{ minWidth: 0 }}
                                                className="flex-1 min-w-0 box-border bg-black border border-white/10 rounded-xl px-2 py-2 text-[11px] text-white outline-none focus:border-emerald-500/40 [color-scheme:dark] appearance-none" />
                                            <input type="time"
                                                value={(scheduleAt || '').split('T')[1] || ''}
                                                onChange={e => { const date = (scheduleAt || '').split('T')[0] || toLocalInputValue(new Date()).split('T')[0]; setScheduleAt(`${date}T${e.target.value}`); }}
                                                style={{ minWidth: 0 }}
                                                className="flex-1 min-w-0 box-border bg-black border border-white/10 rounded-xl px-2 py-2 text-[11px] text-white outline-none focus:border-emerald-500/40 [color-scheme:dark] appearance-none" />
                                        </div>
                                        <div className="flex gap-2">
                                            {[['+1h', 3600000], ['Tonight', -1], ['Tomorrow 9a', -2]].map(([label, val]) => (
                                                <button key={label as string} onClick={() => setScheduleAt(toLocalInputValue(presetDate(val as number)))}
                                                    className="flex-1 text-[9px] font-bold uppercase tracking-wide px-2 py-1.5 rounded-lg bg-white/5 text-zinc-400 hover:bg-white/10 transition-colors">{label}</button>
                                            ))}
                                        </div>
                                        <button onClick={scheduleMessage} disabled={!messageText.trim() || scheduling}
                                            className="w-full py-2 rounded-xl bg-emerald-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-40 flex items-center justify-center gap-1.5">
                                            {scheduling ? <><Loader2 className="w-3 h-3 animate-spin" /> {t('comp.sealing')}</> : t('comp.schedule')}
                                        </button>
                                        <div className="text-[9px] text-zinc-600 leading-relaxed">Encrypted now, released by the server at the chosen time — it sends even if the app is closed. The server only ever holds ciphertext.</div>
                                    </div>
                                  </>
                                )}
                            </div>
                        )}
                    </div>
                    )}
                    <div
                        className="relative bg-[#121212] border border-white/10 rounded-3xl p-1 flex items-center gap-1 shadow-2xl focus-within:border-emerald-500/30 transition-colors w-full"
                        onTouchStart={e => { composerTouchStart.current = e.touches[0]?.clientY ?? null; }}
                        onTouchMove={e => {
                            // A downward swipe on the composer dismisses the keyboard.
                            if (composerTouchStart.current !== null) {
                                const dy = (e.touches[0]?.clientY ?? 0) - composerTouchStart.current;
                                if (dy > 30) { messageInputRef.current?.blur(); composerTouchStart.current = null; }
                            }
                        }}
                        onTouchEnd={() => { composerTouchStart.current = null; }}>
                        {mentionMenu && mentionMenuOpts.length > 0 && (
                          <div className="absolute bottom-full left-2 right-2 mb-2 bg-[#161616] border border-emerald-500/30 rounded-xl shadow-2xl overflow-hidden z-30">
                            <div className="text-[8px] font-black uppercase tracking-widest text-zinc-600 px-3 pt-2 pb-1">Ping a group or person</div>
                            {mentionMenuOpts.map((g, idx) => (
                              <button key={(g.kind === 'user' ? 'u' : 'g') + g.id} onMouseDown={e => { e.preventDefault(); insertMention(g.name); }}
                                className={`w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-emerald-500/10 transition-colors ${idx === 0 ? 'bg-white/5' : ''}`}>
                                {g.kind === 'group'
                                  ? <Users className="w-3.5 h-3.5 text-emerald-500/70 shrink-0" />
                                  : <AtSign className="w-3.5 h-3.5 text-emerald-500/70 shrink-0" />}
                                <span className="text-sm text-white truncate">@{g.name}</span>
                                {g.kind === 'group'
                                  ? <span className="text-[9px] text-zinc-600 ml-auto shrink-0">{g.count ?? 0}</span>
                                  : <span className="text-[8px] uppercase tracking-widest text-zinc-700 ml-auto shrink-0">person</span>}
                              </button>
                            ))}
                          </div>
                        )}
                        <div className="md:hidden absolute -top-3 left-1/2 -translate-x-1/2 w-8 h-1 rounded-full bg-white/10" />
                        <button title="Attach image or video" onClick={() => fileInputRef.current?.click()} className="shrink-0 p-1.5 md:p-2 text-zinc-500 hover:text-white transition-colors"><ImageIcon className="w-5 h-5" /></button>
                        <input ref={fileInputRef} type="file" accept="image/*,video/*" multiple className="hidden" onChange={handleAttach} />
                        <button
                            title={isRecording ? 'Stop recording' : 'Record voice message'}
                            onClick={isRecording ? stopRecording : startRecording}
                            className={`shrink-0 p-1.5 md:p-2 transition-colors ${isRecording ? 'text-red-500 animate-pulse' : 'text-zinc-500 hover:text-white'}`}>
                            {isRecording ? <Square className="w-5 h-5" /> : <Mic className="w-5 h-5" />}
                        </button>
                        {isRecording && <RecordingMeter analyser={recAnalyserRef} />}
                        <textarea ref={messageInputRef} rows={1} placeholder={isRecording ? t('comp.recording') : t('comp.message')} disabled={isRecording} hidden={isRecording} className="flex-1 min-w-0 bg-transparent py-1.5 px-2 text-sm text-white focus:ring-0 outline-none placeholder:text-zinc-700 resize-none max-h-40 overflow-y-auto leading-snug" value={messageText} onInput={e => { const el = e.currentTarget; el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 160) + 'px'; }} onChange={e => onComposerChange(e.currentTarget)} onBlur={() => setTimeout(() => setMentionMenu(null), 150)} onTouchStart={e => { composerTouchStart.current = e.touches[0]?.clientY ?? null; }} onTouchMove={e => { if (composerTouchStart.current !== null) { const dy = (e.touches[0]?.clientY ?? 0) - composerTouchStart.current; if (dy > 30) { messageInputRef.current?.blur(); composerTouchStart.current = null; } } }} onKeyDown={e => { if (e.key === 'Escape' && mentionMenu) { setMentionMenu(null); return; } if (isCoarsePointer) return; /* mobile: Return = newline (default) */ if (e.key === 'Enter' && !e.shiftKey && mentionMenu && mentionMenuOpts.length) { e.preventDefault(); insertMention(mentionMenuOpts[0].name); return; } if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }} />
                        {/* send button slides in only when there's something to send */}
                        <div className={`shrink-0 overflow-hidden flex items-center transition-[width,margin,opacity] duration-200 ease-out ${hasSendContent ? 'w-9 md:w-10 ml-1 opacity-100' : 'w-0 ml-0 opacity-0'}`}>
                          <button onPointerDown={() => { keepFocusRef.current = document.activeElement === messageInputRef.current; }} onClick={() => handleSend()} disabled={isSending} tabIndex={hasSendContent ? 0 : -1}
                            className={`send-btn shrink-0 p-1.5 md:p-2 bg-emerald-500 text-black rounded-2xl shadow-xl shadow-emerald-500/20 transition-transform duration-200 ease-out disabled:opacity-70 ${hasSendContent ? 'scale-100' : 'scale-50'}`}>
                            <Send className="w-5 h-5" />
                          </button>
                        </div>
                    </div>
                </div>
            </div>
            )
        )}
      </div>

      {/* ---- v72 M4: password confirmation for destructive actions ---- */}
      <ReauthDialog username={state.account?.username || null} />

      {/* ---- Network Profile info view (photo, name history, bio, add-to-hub) ---- */}
      {profileTarget && currentUser && (
        <ProfileSheet
          viewerNodeId={currentUser.id}
          targetPid={profileTarget.pid}
          targetName={profileTarget.name}
          targetColor={profileTarget.color}
          targetAvatarAt={profileTarget.avatarAt}
          canAddToHub={!profileTarget.isMe && !!onHubConnect && currentUser?.treeMode !== 'HUB' /* already in the personal hub */}
          onHubConnect={onHubConnect}
          onClose={() => setProfileTarget(null)}
        />
      )}

      {/* ---- Key-change verification sheet (Signal safety number) ---- */}
      {verifyPeer && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={() => { if (!verifyBusy) { setVerifyPeer(null); setVerifySafety(null); } }}>
          <div className="w-full max-w-sm bg-[#141414] border border-white/10 rounded-2xl p-5 shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-2 text-red-400 mb-2">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-sm font-black uppercase tracking-widest">Identity changed</h3>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed mb-3">
              <span className="text-white font-bold">{verifyPeer.name}</span>'s security key is different from the one this device remembered. That happens if they reinstalled — but it can also mean someone is intercepting your messages. Compare the safety number below with them <span className="text-white">over a trusted channel (in person or a call)</span> before you re-trust.
            </p>
            <div className="rounded-xl bg-black/40 border border-white/10 p-3 mb-4">
              <div className="text-[9px] font-black uppercase tracking-widest text-zinc-500 mb-1.5">Safety number</div>
              {verifySafety === 'loading'
                ? <div className="flex items-center gap-2 text-zinc-500 text-xs"><Loader2 className="w-3.5 h-3.5 animate-spin" /> Computing…</div>
                : verifySafety
                  ? <div className="font-mono text-[13px] leading-relaxed text-emerald-300 tracking-wider break-all select-text">{verifySafety}</div>
                  : <div className="text-xs text-zinc-500">Not available yet — exchange a message first, then reopen.</div>}
            </div>
            <div className="flex gap-2">
              <button type="button" disabled={verifyBusy} onClick={() => { setVerifyPeer(null); setVerifySafety(null); }}
                className="flex-1 py-2.5 rounded-xl border border-white/10 text-zinc-300 text-xs font-black uppercase tracking-widest hover:bg-white/5 transition-colors disabled:opacity-50">Cancel</button>
              <button type="button" disabled={verifyBusy || !verifySafety || verifySafety === 'loading'} onClick={confirmVerify}
                className="flex-1 py-2.5 rounded-xl bg-emerald-500 text-black text-xs font-black uppercase tracking-widest hover:bg-emerald-400 transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5">
                {verifyBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />} Verify &amp; trust
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- Invitee group editor ---- */}
      {groupEditorOpen && onSetGroups && currentUser && (
        <GroupEditor
          childrenNodes={childrenNodes}
          inviteeGroups={(currentUser.inviteeGroups) || {}}
          groupLabels={(currentUser.groupLabels) || {}}
          onClose={() => setGroupEditorOpen(false)}
          onCommit={(a, l) => onSetGroups!(undefined, a, l)}
        />
      )}

      {/* ---- Long-press action sheet ---- */}
      {actionSheetMid && (() => {
        const m = messages.find(x => x.id === actionSheetMid);
        if (!m) return null;
        const isCallLog = !!m.callLog;
        return (
          <div className="fixed inset-0 z-[65] bg-black/60 backdrop-blur-sm flex items-end justify-center animate-in fade-in" onClick={() => setActionSheetMid(null)}>
            <div className="bg-[#141414] border border-white/10 rounded-t-3xl w-full max-w-md p-2 pb-6 animate-in slide-in-from-bottom-4" onClick={e => e.stopPropagation()}>
              <div className="w-10 h-1 rounded-full bg-white/15 mx-auto my-2" />
              {isCallLog ? (
                <button onClick={async () => { const id = actionSheetMid!; setActionSheetMid(null); try { await onDeleteForMe([id]); } catch {} }}
                  className="w-full flex items-center gap-3 px-4 py-3.5 rounded-2xl hover:bg-white/5 transition-colors text-left">
                  <Trash2 className="w-5 h-5 text-red-400" /><span className="text-sm text-white font-semibold">{t('sel.deleteForMe')}</span>
                </button>
              ) : (<>
              {m && m.text && (
                <button onClick={() => { const txt = m.text || ''; try { navigator.clipboard?.writeText(txt); } catch {} setActionSheetMid(null); }}
                  className="w-full flex items-center gap-3 px-4 py-3.5 rounded-2xl hover:bg-white/5 transition-colors text-left">
                  <Copy className="w-5 h-5 text-zinc-300" /><span className="text-sm text-white font-semibold">Copy</span>
                </button>
              )}
              <button onClick={() => { setInfoMid(actionSheetMid); setActionSheetMid(null); }}
                className="w-full flex items-center gap-3 px-4 py-3.5 rounded-2xl hover:bg-white/5 transition-colors text-left">
                <Info className="w-5 h-5 text-emerald-400" /><span className="text-sm text-white font-semibold">Info</span>
              </button>
              <button onClick={() => { pinMessage(pinnedMid === actionSheetMid ? null : actionSheetMid); setActionSheetMid(null); }}
                className="w-full flex items-center gap-3 px-4 py-3.5 rounded-2xl hover:bg-white/5 transition-colors text-left">
                <Pin className="w-5 h-5 text-amber-400" /><span className="text-sm text-white font-semibold">{pinnedMid === actionSheetMid ? 'Unpin message' : 'Pin message'}</span>
              </button>
              <button onClick={() => { const mm = messages.find(x => x.id === actionSheetMid); if (mm) { setReplyingTo(mm); messageInputRef.current?.focus(); } setActionSheetMid(null); }}
                className="w-full flex items-center gap-3 px-4 py-3.5 rounded-2xl hover:bg-white/5 transition-colors text-left">
                <Reply className="w-5 h-5 text-zinc-300" /><span className="text-sm text-white font-semibold">Reply</span>
              </button>
              <button onClick={() => { enterSelect(actionSheetMid!); setActionSheetMid(null); }}
                className="w-full flex items-center gap-3 px-4 py-3.5 rounded-2xl hover:bg-white/5 transition-colors text-left">
                <Check className="w-5 h-5 text-zinc-300" /><span className="text-sm text-white font-semibold">Select</span>
              </button>
              </>)}
            </div>
          </div>
        );
      })()}

      {/* ---- Message info modal ---- */}
      {infoMid && (() => {
        const m = messages.find(x => x.id === infoMid);
        if (!m) return null;
        const isMine = m.senderId === currentUser?.id;
        const reactions = m.reactions || {};
        const reactionEntries = Object.entries(reactions);
        const acks = m.acks || [];
        return (
          <div className="fixed inset-0 z-[65] bg-black/70 backdrop-blur-sm flex items-end md:items-center justify-center p-0 md:p-6 animate-in fade-in" onClick={() => setInfoMid(null)}>
            <div className="bg-[#0e0e0e] border border-white/10 rounded-t-3xl md:rounded-3xl w-full md:max-w-md max-h-[80vh] flex flex-col shadow-2xl animate-in slide-in-from-bottom-4" onClick={e => e.stopPropagation()}>
              <div className="flex items-center justify-between p-4 border-b border-white/5 shrink-0">
                <div className="flex items-center gap-2"><Info className="w-5 h-5 text-emerald-500" /><h3 className="text-sm font-black uppercase tracking-widest text-white">Message Info</h3></div>
                <button onClick={() => setInfoMid(null)} className="p-2 text-zinc-500 hover:text-white"><X className="w-5 h-5" /></button>
              </div>
              <div className="overflow-y-auto no-scrollbar p-4 space-y-4">
                {m.text && <div className="text-sm text-zinc-300 bg-white/[0.03] border border-white/5 rounded-2xl px-3 py-2 break-words">{m.text}</div>}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-500 font-bold uppercase tracking-wide">Sent</span>
                    <span className="text-zinc-300">{new Date(m.timestamp).toLocaleString(locale)}</span>
                  </div>
                  {m.editedAt && (
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-zinc-500 font-bold uppercase tracking-wide">Edited</span>
                      <span className="text-zinc-300">{new Date(m.editedAt).toLocaleString(locale)}</span>
                    </div>
                  )}
                  {isMine && (
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-zinc-500 font-bold uppercase tracking-wide">Read</span>
                      <span className={m.readAt ? 'text-emerald-400' : 'text-zinc-500'}>
                        {m.readAt ? new Date(m.readAt).toLocaleString(locale) : 'Not yet'}
                      </span>
                    </div>
                  )}
                  {!isMine && !m.callLog && (
                    <div className="flex items-center justify-between text-xs gap-3">
                      <span className="text-zinc-500 font-bold uppercase tracking-wide shrink-0">Integrity</span>
                      <span className={`text-right ${m.keyChanged ? 'text-red-400' : m.verified ? 'text-emerald-400' : 'text-zinc-500'}`}>
                        {m.keyChanged ? 'Sender’s safety number changed'
                          : m.verified ? 'Verified: sealed by a verified member, unaltered'
                          : 'Not verified (older app version, or the sender’s membership isn’t signed yet)'}
                      </span>
                    </div>
                  )}
                </div>
                {isMine && m.sentTo && m.sentTo.length > 0 && (
                  <div>
                    {/* V8 H-2 transparency: exactly who this message's key was
                        encrypted to — including monitoring ancestors — so the
                        audience of every message is auditable by its sender. */}
                    <div className="text-[10px] font-black uppercase tracking-widest text-sky-400 mb-2">Encrypted to ({m.sentTo.length})</div>
                    <div className="flex flex-wrap gap-1.5">
                      {m.sentTo.map((r, i) => (
                        <span key={i} title={r.verified === false ? 'Membership not verified by a signed certificate (existing contact / transition period)' : 'Verified member'}
                          className={`text-[11px] px-2 py-1 rounded-full border ${r.verified === false ? 'bg-amber-500/10 border-amber-500/30 text-amber-200' : 'bg-sky-500/10 border-sky-500/25 text-sky-200'}`}>
                          {r.name || r.id.slice(0, 10)}{r.verified === false ? ' · unverified' : ''}
                        </span>
                      ))}
                    </div>
                    {/* V8 phase 2 (H-2): recipients the server listed that this app
                        refused because no signed membership vouched for them. */}
                    {(m.keyChangedWithheld || 0) > 0 && (
                      <div className="text-[10px] text-red-400/90 mt-1.5">Not sent to {m.keyChangedWithheld} recipient{m.keyChangedWithheld === 1 ? '' : 's'} whose security key changed. Compare your safety number with them to include them again.</div>
                    )}
                    {(m.withheld || 0) > 0 && (
                      <div className="text-[10px] text-amber-400/90 mt-1.5">Not sent to {m.withheld} listed recipient{m.withheld === 1 ? '' : 's'} whose membership couldn’t be verified.</div>
                    )}
                    <div className="text-[10px] text-zinc-600 mt-1.5">Everyone who can read this message. Anyone you don’t expect here is worth a safety-number check.</div>
                  </div>
                )}
                {acks.length > 0 && (
                  <div>
                    <div className="text-[10px] font-black uppercase tracking-widest text-emerald-500 mb-2">Acknowledged by</div>
                    <div className="flex flex-wrap gap-1.5">
                      {acks.map((a, i) => (
                        <span key={i} className="text-[11px] px-2 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/25 text-emerald-300">{a.name}</span>
                      ))}
                    </div>
                  </div>
                )}
                {reactionEntries.length > 0 && (
                  <div>
                    <div className="text-[10px] font-black uppercase tracking-widest text-amber-500 mb-2">Reactions</div>
                    <div className="space-y-1.5">
                      {reactionEntries.map(([em, people]) => (
                        <div key={em} className="flex items-center gap-2">
                          <span className="text-lg">{em}</span>
                          <span className="text-xs text-zinc-400">{people.map(p => p.name).join(', ')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {!isMine && acks.length === 0 && reactionEntries.length === 0 && (
                  <div className="text-xs text-zinc-600 text-center py-2">No reactions or acknowledgments yet.</div>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* ---- Broadcast acknowledgment dashboard ---- */}
      {ackDashOpen && (
        <div className="fixed inset-0 z-[60] bg-black/70 backdrop-blur-sm flex items-end md:items-center justify-center p-0 md:p-6 animate-in fade-in" onClick={() => setAckDashOpen(false)}>
          <div className="bg-[#0e0e0e] border border-white/10 rounded-t-3xl md:rounded-3xl w-full md:max-w-2xl max-h-[85vh] flex flex-col shadow-2xl animate-in slide-in-from-bottom-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-white/5 shrink-0">
              <div className="flex items-center gap-2">
                <CheckCheck className="w-5 h-5 text-emerald-500" />
                <h3 className="text-sm font-black uppercase tracking-widest text-white">{t('bc.acknowledgments')}</h3>
              </div>
              <button onClick={() => setAckDashOpen(false)} className="p-2 text-zinc-500 hover:text-white transition-colors"><X className="w-5 h-5" /></button>
            </div>
            <div className="overflow-y-auto no-scrollbar p-4 space-y-3">
              {ackDashboard.length === 0 ? (
                <div className="text-center text-[11px] text-zinc-600 italic py-8">{t('status.noAckAnnouncements')}</div>
              ) : ackDashboard.map(row => (
                <div key={row.id} className="bg-black/40 border border-white/5 rounded-2xl p-3.5 space-y-2.5">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[13px] text-white font-medium truncate">{row.text}</div>
                      <div className="text-[9px] text-zinc-600 font-mono mt-0.5">{new Date(row.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                    </div>
                    <div className="shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/25">
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-[11px] font-black text-emerald-400 tabular-nums">{row.acked.length}</span>
                    </div>
                  </div>
                  {row.acked.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {row.acked.map((a, i) => (
                        <span key={i} title={new Date(a.ts).toLocaleString()} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-white/[0.04] border border-white/10 text-[10px] text-zinc-300">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />{a.name}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[10px] text-zinc-600 italic">{t('status.awaitingAckEllipsis')}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Audio sinks stay mounted independent of minimize so audio never cuts. */}
      {callState.phase !== 'idle' && callState.peers.map(p => p.stream ? (
        <CallAudioSink key={p.id} stream={p.stream}
          sinkId={sinkSupported ? (speakerOn && speakerSink ? speakerSink : '') : undefined}
          forceLoudspeaker={speakerOn && (!sinkSupported || !speakerSink)} />
      ) : null)}

      {callState.phase === 'active' && callMinimized && (
        <button onClick={() => setCallMinimized(false)}
          className="fixed left-1/2 -translate-x-1/2 z-[100] bg-emerald-500 text-black rounded-full shadow-2xl shadow-emerald-500/30 px-5 py-2.5 flex items-center gap-3 animate-in slide-in-from-top-2 active:scale-95 transition-transform"
          style={{ top: 'calc(env(safe-area-inset-top, 0px) + 10px)' }}>
          <Phone className="w-4 h-4" />
          <span className="text-xs font-black tracking-tight">{callState.peers.length === 1 ? callState.peers[0].name : `${callState.peers.length} on call`}</span>
          <span className="text-[10px] font-black tabular-nums"><CallTimer startedAt={callState.startedAt} /></span>
        </button>
      )}

      {callState.phase !== 'idle' && !(callState.phase === 'active' && callMinimized) && (
        <div className="fixed inset-0 z-[100] bg-black/85 backdrop-blur-md flex flex-col items-center justify-center p-6 animate-in fade-in" style={{ paddingTop: 'calc(env(safe-area-inset-top, 0px) + 1.5rem)' }}>
          {callState.phase === 'active' && (
            <button onClick={() => setCallMinimized(true)} className="absolute top-4 right-4 text-zinc-400 hover:text-white text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5" style={{ top: 'calc(env(safe-area-inset-top, 0px) + 1rem)' }}>
              <ChevronDown className="w-4 h-4" /> Minimize
            </button>
          )}

          {(() => {
            // Show a video grid whenever the local camera is on or any peer is
            // sending video. Tiles: local preview first, then each peer's stream.
            const peerVideos = callState.peers.filter(p => p.stream && p.stream.getVideoTracks().some(t => t.readyState === 'live'));
            const showVideo = callState.phase === 'active' && (callState.videoOn || peerVideos.length > 0);
            if (!showVideo) return null;
            const cols = (peerVideos.length + (callState.videoOn ? 1 : 0)) > 1 ? 'grid-cols-2' : 'grid-cols-1';
            return (
              <div className={`grid ${cols} gap-2 w-full max-w-md mb-4`}>
                {callState.videoOn && callState.localStream && (
                  <VideoTile stream={callState.localStream} name="You" muted mirror />
                )}
                {peerVideos.map(p => (
                  <VideoTile key={p.id} stream={p.stream!} name={p.name} />
                ))}
              </div>
            );
          })()}

          <div className="w-20 h-20 rounded-3xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center mb-6">
            {callState.phase === 'incoming'
              ? <PhoneIncoming className="w-9 h-9 text-emerald-400 animate-pulse" />
              : <Phone className={`w-9 h-9 text-emerald-400 ${callState.phase === 'outgoing' ? 'animate-pulse' : ''}`} />}
          </div>

          <div className="text-center mb-2">
            <div className="text-xl font-black text-white tracking-tight">
              {callState.phase === 'incoming' ? (callState.fromName || 'Incoming call')
                : callState.peers.length === 1 ? callState.peers[0].name
                : `Group call · ${callState.peers.length} people`}
            </div>
            <div className="text-[10px] font-black uppercase tracking-[0.3em] text-emerald-500/80 mt-2">
              {callState.phase === 'incoming' ? 'Incoming encrypted call'
                : callState.phase === 'outgoing' ? 'Ringing…'
                : <CallTimer startedAt={callState.startedAt} />}
            </div>
            <div className="text-[9px] text-zinc-600 uppercase tracking-widest mt-1.5 flex items-center justify-center gap-1.5">
              <ShieldCheck className="w-3 h-3 text-emerald-600" /> End-to-end encrypted · signaling sealed by Signal ratchet
            </div>
          </div>

          {callState.phase !== 'incoming' && callState.peers.length > 0 && (
            <div className="flex flex-wrap justify-center gap-2 my-3 max-w-sm">
              {callState.peers.map(p => (
                <span key={p.id} className={`text-[10px] font-bold px-2.5 py-1 rounded-lg border ${p.status === 'connected' ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' : p.status === 'ringing' || p.status === 'connecting' ? 'text-zinc-400 border-white/10 animate-pulse' : 'text-red-400/70 border-red-500/20'}`}>
                  {p.name}{p.status !== 'connected' ? ` · ${p.status === 'failed' ? 'no route' : p.status}` : ''}
                </span>
              ))}
            </div>
          )}

          <div className="flex items-center gap-5 mt-8">
            {callState.phase === 'incoming' ? (
              <>
                <button onClick={() => callActions.decline()} className="w-16 h-16 rounded-full bg-red-500 text-white flex items-center justify-center shadow-xl shadow-red-500/25 active:scale-95 transition-all"><PhoneOff className="w-7 h-7" /></button>
                <button onClick={() => callActions.accept().catch(() => alert('Microphone access is required to join the call.'))} className="w-16 h-16 rounded-full bg-emerald-500 text-black flex items-center justify-center shadow-xl shadow-emerald-500/25 active:scale-95 transition-all animate-bounce"><Phone className="w-7 h-7" /></button>
              </>
            ) : (
              <>
                <button onClick={() => callActions.toggleMute()} className={`w-14 h-14 rounded-full flex items-center justify-center transition-all active:scale-95 border ${callState.muted ? 'bg-amber-500 text-black border-amber-400' : 'bg-white/10 text-white border-white/10'}`}>
                  {callState.muted ? <MicOff className="w-6 h-6" /> : <Mic className="w-6 h-6" />}
                </button>
                <button onClick={() => callActions.toggleVideo().catch(() => alert('Camera unavailable or permission denied.'))} title={callState.videoOn ? 'Turn camera off' : 'Turn camera on'}
                  className={`w-14 h-14 rounded-full flex items-center justify-center transition-all active:scale-95 border ${callState.videoOn ? 'bg-emerald-500 text-black border-emerald-400' : 'bg-white/10 text-white border-white/10'}`}>
                  <Video className="w-6 h-6" />
                </button>
                {callState.videoOn && (
                  <button onClick={() => callActions.switchCamera().catch(() => alert('Could not switch camera.'))} title="Flip camera"
                    className="w-14 h-14 rounded-full flex items-center justify-center transition-all active:scale-95 border bg-white/10 text-white border-white/10">
                    <SwitchCamera className="w-6 h-6" />
                  </button>
                )}
                <button onClick={toggleSpeaker} title={speakerOn ? 'Speaker on' : 'Speaker off'}
                  className={`w-14 h-14 rounded-full flex items-center justify-center transition-all active:scale-95 border ${speakerOn ? 'bg-emerald-500 text-black border-emerald-400' : 'bg-white/10 text-white border-white/10'}`}>
                  <Volume2 className="w-6 h-6" />
                </button>
                <button onClick={() => callActions.hangup()} className="w-16 h-16 rounded-full bg-red-500 text-white flex items-center justify-center shadow-xl shadow-red-500/25 active:scale-95 transition-all"><PhoneOff className="w-7 h-7" /></button>
              </>
            )}
          </div>

          {/* Diagnostics: iPhones have no easy console, so surface the [call] log
              from inside the app. Shown whenever a call isn't (yet) connected. */}
          {callState.phase !== 'incoming' && callState.peers.some(p => p.status !== 'connected') && (
            <div className="mt-6 flex flex-col items-center gap-2">
              {callState.peers.some(p => p.status === 'failed') && (
                <p className="text-[9px] text-zinc-500 text-center max-w-[260px] leading-relaxed">
                  No route to a participant usually means their network or yours blocks direct connections. Arbor doesn’t relay calls yet (planned for Premium), so a call like this can’t connect for now.
                </p>
              )}
              <button
                onClick={async () => {
                  const log = callActions.getDiag() || '(no call log yet)';
                  try { await navigator.clipboard.writeText(log); alert('Call log copied — paste it in a bug report.'); }
                  catch { prompt('Copy the call log:', log); }
                }}
                className="text-[9px] font-black uppercase tracking-widest text-zinc-500 hover:text-white transition-colors underline underline-offset-4 decoration-zinc-700">
                Copy call log
              </button>
            </div>
          )}
        </div>
      )}

      {/* ---- Donate modal ---- */}
      {donateOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center px-4 py-12 overflow-y-auto overscroll-contain bg-black/70 backdrop-blur-sm animate-in fade-in" onClick={() => !donateBusy && setDonateOpen(false)}>
          <div className="w-full max-w-md bg-[#111] border border-white/10 rounded-3xl p-6 shadow-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-lg font-black text-white tracking-tight">Support Arbor</h2>
              <button onClick={() => !donateBusy && setDonateOpen(false)} className="text-zinc-500 hover:text-white text-2xl leading-none">&times;</button>
            </div>
            <p className="text-[12px] text-zinc-400 leading-relaxed mb-4">Arbor is almost entirely supported by donations from the community. It has been an ongoing project for years and is paid for solely out of my pocket, all services and hosting included. This is a passion project that I hope can change the world, but it isn't possible without your support. If you choose to donate, I greatly appreciate your generosity and commitment to keeping Arbor accessible, open-source, and functioning.</p>
            <label className="block text-[10px] font-bold uppercase tracking-widest text-zinc-500 mb-1">Custom amount (USD)</label>
            <div className="relative mb-3">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500">$</span>
              <input type="number" min={1} max={10000} value={donateCustom} onChange={e => setDonateCustom(e.target.value)} placeholder="Enter an amount"
                className="w-full bg-black border border-white/10 rounded-xl pl-7 pr-3 py-2.5 text-white focus:border-emerald-500/50 outline-none" />
            </div>
            <div className="grid grid-cols-3 gap-2 mb-4">
              {[5, 10, 20, 50, 150].map(a => (
                <button key={a} onClick={() => { setDonateAmt(a); setDonateCustom(''); }}
                  className={`py-2.5 rounded-xl border font-bold transition-all ${!donateCustom && donateAmt === a ? 'border-emerald-500 bg-emerald-500/15 text-emerald-300' : 'border-white/10 bg-black text-zinc-300 hover:border-white/25'}`}>${a}</button>
              ))}
            </div>
            {donateErr && <p className="text-[11px] text-red-400 mb-3">{donateErr}</p>}
            <div className="space-y-2">
              {(!donateCfg || donateCfg.card) && (
                <button disabled={donateBusy} onClick={() => donate('card')}
                  className="w-full py-3 rounded-xl bg-emerald-500 text-black font-black uppercase tracking-widest text-xs hover:bg-emerald-400 active:scale-95 transition-all disabled:opacity-50">{donateBusy ? 'Starting…' : 'Donate with card'}</button>
              )}
              {(!donateCfg || donateCfg.crypto) && (
                <button disabled={donateBusy} onClick={() => donate('crypto')}
                  className="w-full py-3 rounded-xl bg-white/5 border border-white/10 text-white font-black uppercase tracking-widest text-xs hover:bg-white/10 active:scale-95 transition-all disabled:opacity-50">Donate with crypto (Monero &amp; more)</button>
              )}
            </div>
            <p className="text-[9px] text-zinc-600 text-center mt-3">You'll be redirected to a secure checkout. This is a one-time donation.</p>
          </div>
        </div>
      )}

      {/* ---- Upgrade / paywall modal (root only) — DORMANT ----
           Nothing calls setUpgradeOpen(true) while the paywall is disabled (the
           server's growthGate returns null). This modal + the billing API methods
           are kept intact on purpose; to re-enable premium, re-add an "Upgrade"
           trigger that calls setUpgradeOpen(true) AND re-enable growthGate server-side. */}
      {upgradeOpen && plan && (
        <div className="fixed inset-0 z-[95] bg-black/70 backdrop-blur-sm flex items-start sm:items-center justify-center px-4 py-12 sm:py-14 overflow-y-auto overscroll-contain animate-in fade-in" onClick={() => setUpgradeOpen(false)}>
          <div className="relative bg-[#111] border border-emerald-500/20 rounded-3xl p-5 sm:p-7 max-w-sm w-full shrink-0 shadow-2xl space-y-4" onClick={e => e.stopPropagation()}>
            <button onClick={() => setUpgradeOpen(false)} aria-label="Close" className="absolute top-3 right-3 z-10 text-zinc-500 hover:text-white transition-colors"><X className="w-5 h-5" /></button>
            <div>
              <div className="text-lg font-black text-white tracking-tight">{t('plan.premium')}</div>
              <p className="text-xs text-zinc-400 leading-relaxed mt-1">${plan.priceUsd}/month lifts the {plan.limit}-member limit and raises your storage &amp; retention. Pay by card, or by Monero if you prefer not to link a payment identity.</p>
            </div>
            {!xmrReq && (
              <div className="rounded-2xl border border-white/10 overflow-hidden text-[11px]">
                <div className="grid grid-cols-[1.15fr_0.9fr_1fr]">
                  <div className="px-3 py-2 bg-white/[0.03]"></div>
                  <div className="px-2 py-2 bg-white/[0.03] text-[8px] font-black uppercase tracking-widest text-zinc-500 text-center">Free</div>
                  <div className="px-2 py-2 bg-emerald-500/10 text-[8px] font-black uppercase tracking-widest text-emerald-300 text-center">Premium</div>
                  {[['Members', String(plan.limit), String(plan.premiumLimit || 2000)], ['Message history', fmtDays(LIM.freeHistoryDays), fmtDays(LIM.premiumHistoryDays)], ['Media storage', fmtBytes(LIM.freeMediaBytes), '500 MB (20+GB Soon!)'], ['Attachments', fmtBytes(LIM.attachmentBytes), '20 MB (50 MB Soon!)'], ['Relayed (TURN) calls', plan.relayCalls ? 'Yes' : '—', plan.relayCalls ? 'Yes' : '(Very Soon)']].map(([k, f, p], i) => (
                    <React.Fragment key={k}>
                      <div className={`px-3 py-1.5 text-zinc-400 ${i % 2 ? 'bg-white/[0.02]' : ''}`}>{k}</div>
                      <div className={`px-2 py-1.5 text-center text-zinc-500 font-mono ${i % 2 ? 'bg-white/[0.02]' : ''}`}>{f}</div>
                      <div className={`px-2 py-1.5 text-center text-emerald-300 font-mono ${i % 2 ? 'bg-emerald-500/[0.05]' : 'bg-emerald-500/[0.07]'}`}>{p}</div>
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}
            {!xmrReq && (
              <div className="rounded-2xl border border-emerald-500/15 bg-emerald-500/[0.04] p-3">
                <div className="text-[8px] font-black uppercase tracking-widest text-emerald-400/80 mb-1.5">Coming to Premium</div>
                <ul className="space-y-1 text-[10px] text-zinc-400 leading-relaxed">
                  {!plan.relayCalls && <li>• <span className="text-zinc-200">Relayed (TURN) calls</span> — calls that connect on any network, through Arbor’s own relay</li>}
                  <li>• <span className="text-zinc-200">Onion routing</span> — hides your IP address from the server and from the people you talk to</li>
                  <li>• <span className="text-zinc-200">Mesh networking</span> (exploring) — messaging nearby without the internet</li>
                  <li>• More storage and longer history as they grow</li>
                </ul>
                <p className="text-[9px] text-zinc-600 mt-1.5">Planned, not promised dates — your subscription funds the work.</p>
              </div>
            )}
            {!xmrReq && plan.premium && (
              <div className="text-[10px] text-emerald-300/90 text-center">You’re on Premium{plan.premiumUntil ? ` — ${plan.cardSubscription?.renews ? 'renews' : 'active until'} ${new Date(plan.premiumUntil).toLocaleDateString()}` : ''}.</div>
            )}
            {/* A renewing card subscription already pays: no second checkout. (A
                Monero payer on Premium can pay again to add the next 30 days.) */}
            {!xmrReq && !(plan.premium && plan.cardSubscription) && (
              <div className="space-y-2">
                <button disabled={billingBusy || !plan.cardConfigured}
                  onClick={async () => {
                    if (!currentUser) return;
                    setBillingBusy(true); setBillingMsg(null);
                    try { const { url } = await api.billingCheckout(currentUser.id); window.location.href = url; }
                    catch (e: any) { setBillingMsg(e?.message || 'Card checkout failed.'); }
                    setBillingBusy(false);
                  }}
                  className="w-full bg-emerald-500 text-black font-black text-[10px] uppercase tracking-widest py-3 rounded-xl hover:bg-emerald-400 active:scale-95 transition-all disabled:opacity-40">
                  {plan.cardConfigured ? 'Pay by card (Stripe)' : 'Card payments not configured'}
                </button>
                {plan.cardConfigured && (
                  <p className="text-[9px] text-zinc-400 leading-relaxed text-center">Card payments renew automatically: ${plan.priceUsd} is charged every month until you cancel. Cancel any time in the Network Plan panel (Cancel card subscription) — Premium stays until the end of the month you’ve paid for. <a href="/terms" target="_blank" rel="noopener" className="underline">Terms</a></p>
                )}
                <button disabled={billingBusy || !plan.moneroConfigured}
                  onClick={async () => {
                    if (!currentUser) return;
                    setBillingBusy(true); setBillingMsg(null);
                    try { setXmrReq(await api.moneroCreate(currentUser.id)); }
                    catch (e: any) { setBillingMsg(e?.message || 'Could not create a Monero payment request.'); }
                    setBillingBusy(false);
                  }}
                  className="w-full bg-white/5 text-zinc-200 font-black text-[10px] uppercase tracking-widest py-3 rounded-xl hover:bg-white/10 active:scale-95 transition-all disabled:opacity-40">
                  {plan.moneroConfigured ? 'Pay with Monero (XMR)' : 'Monero payments not configured'}
                </button>
                {plan.moneroConfigured && (
                  <p className="text-[9px] text-amber-400/80 leading-relaxed text-center">Monero payments don’t renew: each one buys 30 days, so pay again every month to keep Premium. Monero payments can’t be refunded.</p>
                )}
              </div>
            )}
            {xmrReq && (
              <div className="space-y-2.5">
                <p className="text-[10px] text-zinc-400 leading-relaxed">Send <strong className="text-white">{xmrReq.amountXmr} XMR</strong> (≈ ${xmrReq.usd}, buys 30 days) to this address. It confirms automatically after 10 network confirmations (~20 min).</p>
                <p className="text-[10px] text-amber-400/90 leading-relaxed">This is a one-time payment, not a subscription: pay again each month to keep Premium. Monero payments can’t be refunded.</p>
                <div className="p-2.5 rounded-xl bg-black border border-white/10 text-[10px] font-mono text-emerald-400 break-all select-all">{xmrReq.address}</div>
                <div className="flex gap-1.5">
                  <button onClick={() => { navigator.clipboard?.writeText(xmrReq.address).catch(() => {}); setBillingMsg('Address copied'); }}
                    className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-white/5 text-zinc-300 hover:bg-white/10 transition-colors">{t('plan.copyAddress')}</button>
                  <button disabled={billingBusy}
                    onClick={async () => {
                      setBillingBusy(true); setBillingMsg(null);
                      try {
                        const r = await api.moneroCheck(xmrReq.requestId);
                        if (r.status === 'paid') { setBillingMsg('Payment confirmed — Premium is active!'); setUpgradeOpen(false); if (currentUser) api.billingStatus(currentUser.id).then(setPlan).catch(() => {}); }
                        else setBillingMsg(`Not confirmed yet — received ${r.receivedXmr ?? 0} XMR (${r.confirmedXmr ?? 0} confirmed of ${r.neededXmr} needed).`);
                      } catch (e: any) { setBillingMsg(e?.message || 'Check failed.'); }
                      setBillingBusy(false);
                    }}
                    className="flex-1 text-[9px] font-black uppercase tracking-widest py-2 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50">{billingBusy ? '…' : "I've paid — check"}</button>
                </div>
              </div>
            )}
            {billingMsg && <div className="text-[10px] font-bold text-amber-400 text-center">{billingMsg}</div>}
            <div className="rounded-xl bg-black/40 border border-white/10 p-3 space-y-2">
              <p className="text-[10px] text-zinc-500 leading-relaxed">Premium features cost money because they cost <span className="text-zinc-300">me</span> more to run — more storage, longer retention{plan.relayCalls ? '' : ', and (planned) relayed calls'}. Prefer to just chip in? <span className="text-zinc-300">Donating still helps cover operating costs</span> and buys me the time to keep building Arbor.</p>
              <button onClick={() => { setUpgradeOpen(false); setDonateOpen(true); setDonateErr(null); }}
                className="w-full text-[10px] font-black uppercase tracking-widest py-2.5 rounded-lg bg-white/5 text-zinc-200 border border-white/10 hover:bg-white/10 active:scale-95 transition-all">Donate instead</button>
            </div>
            <button onClick={() => setUpgradeOpen(false)} className="w-full text-[10px] font-black uppercase tracking-widest text-zinc-500 hover:text-white transition-colors py-1">{t('plan.close')}</button>
          </div>
        </div>
      )}

      {/* ---- First-run pointer to the guide ---- */}
      {showHowtoPrompt && (
        <div className="fixed inset-0 z-[90] bg-black/70 backdrop-blur-sm flex items-center justify-center p-6 animate-in fade-in">
          <div className="bg-[#111] border border-emerald-500/20 rounded-3xl p-7 max-w-sm w-full shadow-2xl">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center mb-4">
              <BookOpen className="w-6 h-6 text-emerald-400" />
            </div>
            <div className="text-lg font-black text-white tracking-tight mb-2">{t('onboard.welcome')}</div>
            <p className="text-xs text-zinc-400 leading-relaxed mb-5">Arbor works a little differently from other messengers — everyone joins through the person who invited them, forming an encrypted tree. The two-minute guide covers inviting people, calls, disappearing messages and the privacy tools.</p>
            <div className="flex gap-2">
              <button onClick={() => dismissHowtoPrompt(true)} className="flex-1 bg-emerald-500 text-black font-black text-[10px] uppercase tracking-widest py-3 rounded-xl hover:bg-emerald-400 active:scale-95 transition-all">{t('onboard.readGuide')}</button>
              <button onClick={() => dismissHowtoPrompt(false)} className="px-4 text-[10px] font-black uppercase tracking-widest text-zinc-500 hover:text-white transition-colors">{t('onboard.skip')}</button>
            </div>
            <p className="text-[10px] text-red-500 font-bold leading-relaxed mt-4 text-center">Arbor is still in development. Please send bug reports to bugreports@arborsecure.app</p>
          </div>
        </div>
      )}
    </div>
  );
};

/** Plays a remote call stream. srcObject can't be set via JSX attributes. */
const CallAudioSink: React.FC<{ stream: MediaStream; sinkId?: string; forceLoudspeaker?: boolean }> = ({ stream, sinkId, forceLoudspeaker }) => {
  const ref = useRef<HTMLAudioElement>(null);
  const ctxRef = useRef<{ ctx: AudioContext; src: MediaStreamAudioSourceNode } | null>(null);
  useEffect(() => {
    if (ref.current && ref.current.srcObject !== stream) {
      ref.current.srcObject = stream;
      ref.current.play().catch(() => {});
    }
  }, [stream]);
  // Route output. Two strategies:
  //  - setSinkId (Chrome/Edge/Android): pick the output device directly.
  //  - WebAudio (iOS): Safari routes WebRTC <audio> like a phone call (receiver),
  //    but WebAudio always plays through the LOUDSPEAKER — so "speaker on" pipes
  //    the stream through an AudioContext and mutes the element.
  useEffect(() => {
    const el = ref.current as any;
    if (el && typeof el.setSinkId === 'function' && sinkId !== undefined && !forceLoudspeaker) {
      el.setSinkId(sinkId).catch(() => {});
    }
  }, [sinkId, forceLoudspeaker]);
  useEffect(() => {
    const el = ref.current;
    if (forceLoudspeaker && el) {
      try {
        const AC: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
        const ctx = new AC();
        const src = ctx.createMediaStreamSource(stream);
        src.connect(ctx.destination);
        ctx.resume().catch(() => {});
        ctxRef.current = { ctx, src };
        el.muted = true; // element stays mounted (keeps the track alive), WebAudio does the playing
      } catch { /* fall back to element playback */ }
      return () => {
        if (el) el.muted = false;
        try { ctxRef.current?.src.disconnect(); ctxRef.current?.ctx.close(); } catch {}
        ctxRef.current = null;
      };
    }
  }, [forceLoudspeaker, stream]);
  return <audio ref={ref} autoPlay playsInline className="hidden" />;
};

/** Renders one participant's video stream. Muted for the local preview (its
 *  audio is handled by CallAudioSink for remote peers; the local one has none). */
const VideoTile: React.FC<{ stream: MediaStream; name: string; muted?: boolean; mirror?: boolean }> = ({ stream, name, muted, mirror }) => {
  const ref = useRef<HTMLVideoElement>(null);
  useEffect(() => {
    if (ref.current && ref.current.srcObject !== stream) {
      ref.current.srcObject = stream;
      ref.current.play().catch(() => {});
    }
  }, [stream]);
  return (
    <div className="relative rounded-2xl overflow-hidden bg-[#111] border border-white/10 aspect-[4/3]">
      <video ref={ref} autoPlay playsInline muted={muted}
        className={`w-full h-full object-cover ${mirror ? '-scale-x-100' : ''}`} />
      <div className="absolute bottom-1.5 left-1.5 px-2 py-0.5 rounded-md bg-black/60 text-[9px] font-black uppercase tracking-widest text-white">{name}</div>
    </div>
  );
};

/** Pick the device to use for "speakerphone": an output whose label says speaker,
 *  else the default output. Returns null when the browser can't switch outputs. */
async function findSpeakerSinkId(): Promise<string | null> {
  try {
    if (!('setSinkId' in HTMLMediaElement.prototype)) return null;
    const devs = await navigator.mediaDevices.enumerateDevices();
    const outs = devs.filter(d => d.kind === 'audiooutput');
    if (!outs.length) return null;
    const sp = outs.find(d => /speaker/i.test(d.label));
    return (sp || outs[0]).deviceId || 'default';
  } catch { return null; }
}

const CallTimer: React.FC<{ startedAt?: number }> = ({ startedAt }) => {
  const [, force] = useState(0);
  useEffect(() => { const t = setInterval(() => force(x => x + 1), 1000); return () => clearInterval(t); }, []);
  if (!startedAt) return <>Connecting…</>;
  const s = Math.floor((Date.now() - startedAt) / 1000);
  return <>{String(Math.floor(s / 60)).padStart(2, '0')}:{String(s % 60).padStart(2, '0')}</>;
};

export default Dashboard;
