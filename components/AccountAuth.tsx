
import React, { useState } from 'react';
import { Account } from '../types';
import { Shield, Loader2, ArrowRight, Eye, EyeOff, Copy, Check, KeyRound } from 'lucide-react';
import { api } from '../services/api';
import DefaultProfileEditor from './DefaultProfileEditor';
import { assessPassphrase, generateSeedPhrase } from '../services/cryptoService';

interface AccountAuthProps {
  // isNew = this account was just created (signup), so the app can start the
  // user off with a personal hub. Existing logins/recoveries pass it falsy.
  onAccountLogin: (account: Account, isNew?: boolean) => void;
}

const NetworkLogo = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 text-emerald-500">
    <rect x="9" y="2" width="6" height="6" rx="1"/>
    <path d="M12 8v4"/>
    <path d="M5 12h14"/>
    <path d="M5 12v4"/>
    <path d="M19 12v4"/>
    <rect x="2" y="16" width="6" height="6" rx="1"/>
    <rect x="16" y="16" width="6" height="6" rx="1"/>
  </svg>
);

// Auth modes:
//  login / signup       — the normal flows
//  seedShow             — after signup, present the recovery phrase to save
//  recover              — "forgot username/password": type a seed phrase
//  recovered            — show the recovered username/password, then sign in
type Mode = 'login' | 'signup' | 'seedShow' | 'defaultProfile' | 'recover' | 'recovered';

const AccountAuth: React.FC<AccountAuthProps> = ({ onAccountLogin }) => {
  const [mode, setMode] = useState<Mode>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [wantRecovery, setWantRecovery] = useState(true);   // opt-in seed phrase at signup
  const [seed, setSeed] = useState('');                     // generated (signup) or entered (recover)
  const [copied, setCopied] = useState(false);
  const [recovered, setRecovered] = useState<{ username: string; password: string } | null>(null);
  const [pendingAccount, setPendingAccount] = useState<Account | null>(null);

  const strength = (mode === 'signup' && password) ? assessPassphrase(password) : null;
  const strengthLabel = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];

  const resetTo = (m: Mode) => { setMode(m); setError(null); setPassword(''); setSeed(''); setCopied(false); setRecovered(null); };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) return;
    setIsLoading(true); setError(null);
    try {
      if (mode === 'login') {
        const account = await api.login(username, password);
        onAccountLogin(account);
      } else {
        // Sign up, then (if opted in) store an encrypted recovery blob and show
        // the seed phrase before entering the app.
        const account = await api.signup(username, password);
        if (wantRecovery) {
          const phrase = generateSeedPhrase(12);
          try {
            await api.setRecovery(phrase, username, password);
            setSeed(phrase);
            setPendingAccount(account);
            setMode('seedShow');
            setIsLoading(false);
            return;
          } catch {
            // If storing recovery fails, don't block sign-in — offer the profile step.
            setPendingAccount(account); setMode('defaultProfile'); setIsLoading(false); return;
          }
        } else {
          setPendingAccount(account); setMode('defaultProfile'); setIsLoading(false); return;
        }
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsLoading(false);
    }
  };

  const doRecover = async (e: React.FormEvent) => {
    e.preventDefault();
    const phrase = seed.trim();
    const user = username.trim();
    if (!user) { setError('Enter your username.'); return; }
    if (!phrase) { setError('Enter your recovery phrase.'); return; }
    setIsLoading(true); setError(null);
    try {
      const creds = await api.recoverCredentials(phrase, user);
      setRecovered(creds);
      setMode('recovered');
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsLoading(false);
    }
  };

  const copySeed = async () => {
    try { await navigator.clipboard.writeText(seed); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch {}
  };

  return (
    <div className="h-[100dvh] overflow-y-auto flex flex-col items-center p-6 bg-[#0a0a0a] relative">
       <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent"></div>

       <div className="w-full max-w-sm bg-[#111] border border-white/10 rounded-3xl p-8 shadow-2xl z-10 my-auto">
          <div className="flex justify-center mb-8">
             <div className="w-16 h-16 bg-emerald-500/10 rounded-2xl flex items-center justify-center border border-emerald-500/20">
                <NetworkLogo />
             </div>
          </div>

          <h2 className="text-2xl font-bold text-center text-white mb-1">
              {mode === 'login' && 'Welcome Back'}
              {mode === 'signup' && 'Secure Access'}
              {mode === 'seedShow' && 'Save Your Recovery Phrase'}
              {mode === 'defaultProfile' && 'Set Up Your Profile'}
              {mode === 'recover' && 'Account Recovery'}
              {mode === 'recovered' && 'Credentials Recovered'}
          </h2>
          <p className="text-center text-zinc-500 text-xs uppercase tracking-widest">
              Arbor Terminal
          </p>
          <p className="text-center text-zinc-500 text-[11px] tracking-widest mt-1 mb-8">
              v1.0.0
          </p>

          {/* ---- Login / Signup ---- */}
          {(mode === 'login' || mode === 'signup') && (
          <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                  <input type="text" placeholder="Username"
                    className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors"
                    value={username} onChange={e => setUsername(e.target.value)} />
              </div>
              <div className="relative">
                  <input type={showPassword ? 'text' : 'password'} placeholder="Password"
                    className="w-full bg-black border border-white/10 rounded-xl pl-4 pr-12 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors"
                    value={password} onChange={e => setPassword(e.target.value)} />
                  <button type="button" onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-emerald-500 transition-colors">
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
              </div>

              {mode === 'signup' && (
                <>
                  <div className="space-y-1.5">
                    <div className="flex gap-1">
                      {[0, 1, 2, 3].map(i => (
                        <div key={i} className={`h-1 flex-1 rounded-full transition-colors ${strength && strength.score > i ? (strength.score >= 3 ? 'bg-emerald-500' : strength.score === 2 ? 'bg-amber-500' : 'bg-red-500') : 'bg-zinc-800'}`} />
                      ))}
                    </div>
                    <p className="text-[10px] text-zinc-500 leading-tight px-1">
                      {strength ? (strength.ok ? `${strengthLabel[strength.score]} passphrase` : strength.reason)
                        : 'Use at least 12 characters — several random words (e.g. “maple orbit velvet crane”) are strongest. This protects your private keys and cannot be reset.'}
                    </p>
                  </div>
                  <div className="text-[10px] font-black uppercase tracking-widest text-emerald-500/80 px-1">Optional, but recommended</div>
                  <label className="flex items-start gap-2.5 p-3 rounded-xl bg-black/40 border border-white/10 cursor-pointer">
                    <input type="checkbox" checked={wantRecovery} onChange={e => setWantRecovery(e.target.checked)}
                      className="mt-0.5 accent-emerald-500 w-4 h-4" />
                    <span className="text-[11px] text-zinc-400 leading-relaxed">
                      Generate a <strong className="text-emerald-400">recovery phrase</strong> — the only way to recover this account if you forget your credentials. Highly recommended.
                    </span>
                  </label>
                </>
              )}

              {error && <div className="text-red-500 text-xs text-center font-bold">{error}</div>}

              <button type="submit" disabled={isLoading}
                className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2">
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : (
                      <>{mode === 'login' ? 'Authenticate' : 'Establish ID'}<ArrowRight className="w-4 h-4" /></>
                  )}
              </button>
              {mode === 'signup' && (
                <p className="text-[10px] text-zinc-500 text-center leading-relaxed">
                  By creating an account you agree to our{' '}
                  <a href="/terms" target="_blank" rel="noopener" className="text-emerald-400 hover:underline">Terms</a>{' '}and{' '}
                  <a href="/privacy" target="_blank" rel="noopener" className="text-emerald-400 hover:underline">Privacy Policy</a>.
                </p>
              )}
          </form>
          )}

          {(mode === 'login' || mode === 'signup') && (
          <div className="mt-6 text-center space-y-2">
              <button onClick={() => resetTo(mode === 'login' ? 'signup' : 'login')}
                className="block w-full text-zinc-500 hover:text-white text-xs font-bold uppercase tracking-wide transition-colors">
                  {mode === 'login' ? 'Need an account? Sign Up' : 'Have an account? Login'}
              </button>
              {mode === 'login' && (
                <button onClick={() => resetTo('recover')}
                  className="block w-full text-zinc-600 hover:text-emerald-400 text-[10px] font-bold uppercase tracking-wide transition-colors">
                  Forgot username / password?
                </button>
              )}
          </div>
          )}

          {/* ---- Seed phrase display (after signup) ---- */}
          {mode === 'seedShow' && (
            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30">
                <p className="text-[11px] text-red-400 font-bold leading-relaxed">
                  Write these 12 words down and store them physically. This is the ONLY failsafe way to access your account if you forget your credentials. Passwords cannot be reset. Anyone with this phrase can recover your login — keep it secret.
                </p>
              </div>
              <div className="grid grid-cols-3 gap-2">
                {seed.split(' ').map((w, i) => (
                  <div key={i} className="flex items-center gap-1.5 px-2 py-2 rounded-lg bg-black border border-white/10">
                    <span className="text-[9px] text-zinc-600 font-mono">{i + 1}</span>
                    <span className="text-xs text-emerald-400 font-mono">{w}</span>
                  </div>
                ))}
              </div>
              <button onClick={copySeed}
                className="w-full flex items-center justify-center gap-2 text-[10px] font-black uppercase tracking-widest py-2.5 rounded-lg bg-white/5 text-zinc-300 hover:bg-white/10 transition-colors">
                {copied ? <><Check className="w-3.5 h-3.5" /> Copied</> : <><Copy className="w-3.5 h-3.5" /> Copy phrase</>}
              </button>
              <button onClick={() => setMode('defaultProfile')}
                className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3 rounded-xl transition-all">
                I've saved it — Continue
              </button>
            </div>
          )}

          {/* ---- Optional default profile (right after signup) ---- */}
          {mode === 'defaultProfile' && (
            <div className="space-y-4">
              <DefaultProfileEditor
                ctaLabel="Save & continue"
                onDone={() => { if (pendingAccount) onAccountLogin(pendingAccount, true); }}
                onSkip={() => { if (pendingAccount) onAccountLogin(pendingAccount, true); }}
              />
            </div>
          )}

          {/* ---- Recover: enter seed phrase ---- */}
          {mode === 'recover' && (
            <form onSubmit={doRecover} className="space-y-4">
              <p className="text-xs text-zinc-400 leading-relaxed">
                Enter your username and 12-word recovery phrase to retrieve your password.
              </p>
              <input type="text" placeholder="Username"
                className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors text-sm"
                value={username} onChange={e => setUsername(e.target.value)} />
              <textarea placeholder="Enter your recovery phrase, words separated by spaces"
                className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors text-sm font-mono h-24 resize-none"
                value={seed} onChange={e => setSeed(e.target.value)} />
              {error && <div className="text-red-500 text-xs text-center font-bold">{error}</div>}
              <button type="submit" disabled={isLoading}
                className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2">
                {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <><KeyRound className="w-4 h-4" /> Recover Account</>}
              </button>
              <button type="button" onClick={() => resetTo('login')}
                className="w-full text-zinc-500 hover:text-white text-xs font-bold uppercase tracking-wide transition-colors">Back to login</button>
            </form>
          )}

          {/* ---- Recovered: show credentials ---- */}
          {mode === 'recovered' && recovered && (
            <div className="space-y-4">
              <p className="text-xs text-emerald-400 font-bold text-center">Here are your account credentials.</p>
              <div className="space-y-2">
                <div className="p-3 rounded-xl bg-black border border-white/10">
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1">Username</div>
                  <div className="text-sm text-white font-mono break-all select-all">{recovered.username}</div>
                </div>
                <div className="p-3 rounded-xl bg-black border border-white/10">
                  <div className="text-[9px] text-zinc-600 uppercase tracking-widest mb-1">Password</div>
                  <div className="text-sm text-emerald-400 font-mono break-all select-all">{recovered.password}</div>
                </div>
              </div>
              <p className="text-[10px] text-zinc-500 leading-relaxed">Save these somewhere safe. We recommend a password manager.</p>
              <button disabled={isLoading}
                onClick={async () => {
                  setIsLoading(true); setError(null);
                  try { const account = await api.login(recovered.username, recovered.password); onAccountLogin(account); }
                  catch (e: any) { setError(e.message); setIsLoading(false); }
                }}
                className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2">
                {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Sign In Now'}
              </button>
              {error && <div className="text-red-500 text-xs text-center font-bold">{error}</div>}
              <button onClick={() => resetTo('login')}
                className="w-full text-zinc-500 hover:text-white text-xs font-bold uppercase tracking-wide transition-colors">Back to login</button>
            </div>
          )}
       </div>
    </div>
  );
};

export default AccountAuth;
