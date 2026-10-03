import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import * as keyStore from '../services/keyStore';
import * as appLock from '../services/appLock';

/**
 * v70 H5 — the app opens locked whenever the account key isn't in memory (every
 * cold start; after an App Lock re-lock). The key is never stored in the clear,
 * so unlocking really needs something: this device's biometrics (which open the
 * key sealed under the authenticator's PRF secret) or the account password.
 */
const UnlockScreen: React.FC<{ username: string; onUnlocked: () => void; onSignOut: () => void }> = ({ username, onUnlocked, onSignOut }) => {
  const [hasBio, setHasBio] = useState(false);
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { appLock.hasKeyUnlock().then(setHasBio).catch(() => {}); }, []);

  const bio = async () => {
    setBusy(true); setErr(null);
    try {
      const k = await appLock.unlock();
      if (k) { keyStore.setWrapKey(k); onUnlocked(); return; }
      setErr('Biometric unlock didn’t work. Enter your password instead.');
    } finally { setBusy(false); }
  };
  const password = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pw) return;
    setBusy(true); setErr(null);
    try { await api.login(username, pw); setPw(''); onUnlocked(); }
    catch (x: any) { setErr(/401|invalid|credentials/i.test(x?.message || '') ? 'Wrong password.' : (x?.message || 'Couldn’t unlock.')); }
    finally { setBusy(false); }
  };

  return (
    <div className="h-[100dvh] w-full bg-[#0a0a0a] flex flex-col items-center justify-center gap-6 text-zinc-300 p-8">
      <div className="w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center">
        <svg viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </div>
      <div className="text-center">
        <div className="text-lg font-bold text-white tracking-tight">Arbor is locked</div>
        <div className="text-[11px] text-zinc-500 mt-1">Your messages and keys on this device stay encrypted until you unlock.</div>
      </div>
      {hasBio && (
        <button onClick={bio} disabled={busy}
          className="bg-emerald-500 text-black font-black text-xs uppercase tracking-widest px-8 py-3.5 rounded-xl hover:bg-emerald-400 active:scale-95 transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50">
          Unlock with biometrics
        </button>
      )}
      <form onSubmit={password} className="w-full max-w-xs flex flex-col gap-3">
        <div className="text-[11px] text-zinc-500 text-center">{hasBio ? 'or enter the password for' : 'Enter the password for'} <span className="text-zinc-300 font-bold">{username}</span></div>
        <input type="password" autoComplete="current-password" value={pw} onChange={e => setPw(e.target.value)} placeholder="Password"
          className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-emerald-500/50" />
        <button type="submit" disabled={busy || !pw}
          className={`${hasBio ? 'bg-white/10 text-zinc-200 hover:bg-white/20' : 'bg-emerald-500 text-black hover:bg-emerald-400'} font-black text-xs uppercase tracking-widest px-8 py-3 rounded-xl transition-all disabled:opacity-50`}>
          {busy ? 'Unlocking…' : 'Unlock'}
        </button>
      </form>
      {err && <div className="text-xs text-red-400 text-center max-w-xs" role="alert">{err}</div>}
      <button onClick={onSignOut} className="text-[10px] font-black uppercase tracking-widest text-zinc-600 hover:text-zinc-300 transition-colors">Sign out</button>
    </div>
  );
};

export default UnlockScreen;
