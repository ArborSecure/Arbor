
import React, { useState, useEffect, useRef } from 'react';
import { User } from '../types';
import LanguagePicker from './LanguagePicker';
import DefaultProfileEditor from './DefaultProfileEditor';
import { api } from '../services/api';
import { useT } from '../services/LocaleContext';
import { Key, Sprout, ArrowRight, Loader2, Globe, Lock, LogOut, ChevronRight, UserCircle, UserPlus, Network, ShieldCheck, MessageCircle, QrCode } from 'lucide-react';
import QrScanner from './QrScanner';

interface AuthScreenProps {
  onLogin: (user: User) => void;
  onRegister: (name: string, inviteCode?: string, treeName?: string, treeMode?: 'HIERARCHICAL' | 'DM' | 'HUB', treeNameVisible?: boolean, color?: string, monitorEnabled?: boolean, referralOpen?: boolean, globalChat?: boolean, useDefaultProfile?: boolean, inviteFragment?: string) => Promise<void>;
  myNodes: User[];
  onLogoutAccount: () => void;
}

// The one Arbor logo, everywhere: this is the same lucide "Network" glyph the
// app header/sidebar uses — the home/auth screen must not drift from it.
const NetworkLogo = () => <Network className="w-8 h-8 text-emerald-500" strokeWidth={2} />;

// Shared icon-color palette (also offered in Settings). Strict #rrggbb hex —
// the server validates against the same shape before storing.
export const ICON_COLORS = [
  '#ef4444', '#f97316', '#f59e0b', '#eab308', '#84cc16', '#22c55e',
  '#10b981', '#14b8a6', '#06b6d4', '#3b82f6', '#6366f1', '#8b5cf6',
  '#a855f7', '#d946ef', '#ec4899', '#f43f5e',
];

const AuthScreen: React.FC<AuthScreenProps> = ({ onLogin, onRegister, myNodes, onLogoutAccount }) => {
  const t = useT();
  const [mode, setMode] = useState<'JOIN' | 'ROOT' | 'SELECT'>(myNodes.length > 0 ? 'SELECT' : 'ROOT');
  const userNavigated = useRef(false);
  // Nodes load asynchronously after sign-in; once they arrive, land the user on
  // the network CHOOSER (the default page) — unless they've already navigated away.
  useEffect(() => {
    if (myNodes.length > 0 && !userNavigated.current) setMode('SELECT');
  }, [myNodes.length]);
  const pickMode = (m: 'JOIN' | 'ROOT' | 'SELECT') => {
    userNavigated.current = true;
    // Pre-fill the nickname from the account's default profile (the photo + bio are
    // applied by the server only if "Use my default photo & bio here" is ticked —
    // V8 M-8). Only when the field is still empty, so a half-typed name is never clobbered.
    if (m === 'ROOT' || m === 'JOIN') setName(prev => prev || defaultName);
    setMode(m);
  };
  const [name, setName] = useState('');
  const [defaultName, setDefaultName] = useState('');
  const [showDefault, setShowDefault] = useState(false);
  useEffect(() => { api.getAccountProfile().then(p => setDefaultName(p.name || '')).catch(() => {}); }, []);
  const [color, setColor] = useState(() => ICON_COLORS[Math.floor(Math.random() * ICON_COLORS.length)]);
  const [inviteCode, setInviteCode] = useState('');
  // V8 phase 2: the part of an invite link after '#'. It carries the link's
  // signing key, the network key and the network owner's pin — never sent to the
  // server (browsers don't transmit fragments). A bare code can't be verified.
  const [inviteFrag, setInviteFrag] = useState('');
  const fragOf = (raw: string): string => { const i = (raw || '').indexOf('#'); return i >= 0 ? raw.slice(i + 1).trim() : ''; };
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  // Pull an invite code out of whatever the QR encoded: an app link
  // (…/?invite=CODE), a bare code, or a code embedded in some other text. Returns
  // the normalized code, or null if nothing that looks like one is present.
  const extractInviteCode = (raw: string): string | null => {
    const text = (raw || '').trim();
    try { const c = new URL(text).searchParams.get('invite'); if (c && /^[A-Z0-9]{4,64}$/i.test(c)) return c.toUpperCase(); } catch { /* not a URL */ }
    if (/^[A-Z0-9]{4,64}$/i.test(text)) return text.toUpperCase();
    const m = text.match(/[A-Z0-9]{6,64}/i);
    return m ? m[0].toUpperCase() : null;
  };
  const handleScanResult = (raw: string) => {
    const code = extractInviteCode(raw);
    if (!code) { setScanError('That QR code isn’t an Arbor invite.'); return; }
    setInviteCode(code);
    setInviteFrag(fragOf(raw));
    setScanError(null);
    setScanning(false);
  };
  // Deep link from an invite QR: /?invite=CODE prefills the code and routes
  // straight to the join flow (the scan → install → join path).
  useEffect(() => {
    try {
      const code = new URLSearchParams(window.location.search).get('invite');
      if (code && /^[A-Z0-9]{4,64}$/i.test(code)) {
        setInviteCode(code.toUpperCase());
        setInviteFrag((window.location.hash || '').replace(/^#/, ''));
        userNavigated.current = true;
        setMode('JOIN');
        window.history.replaceState({}, '', window.location.pathname); // don't leave the code in the URL bar
      }
    } catch {}
    // eslint-disable-next-line
  }, []);
  const [treeName, setTreeName] = useState('');
  const [treeMode, setTreeMode] = useState<'HIERARCHICAL' | 'DM' | 'HUB'>('HIERARCHICAL');
  const [treeNameVisible, setTreeNameVisible] = useState(false);
  const [monitorEnabled, setMonitorEnabled] = useState(false);
  const [referralOpen, setReferralOpen] = useState(false);
  const [globalChat, setGlobalChat] = useState(true);
  const [useDefaultProfile, setUseDefaultProfile] = useState(false); // V8 M-8: opt-in, per network
  const [isSubmitting, setIsSubmitting] = useState(false);
  // Only one personal hub per account — hide the Personal option once you have one.
  const hasHub = myNodes.some(u => u.treeMode === 'HUB');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setIsSubmitting(true);
    try {
      await onRegister(
        name,
        mode === 'JOIN' ? inviteCode.trim().toUpperCase() : undefined,
        mode === 'ROOT' ? (treeName || `${name}'s Network`) : undefined,
        mode === 'ROOT' ? treeMode : undefined,
        mode === 'ROOT' && treeMode !== 'HUB' ? treeNameVisible : undefined,
        color,
        mode === 'ROOT' && treeMode === 'HIERARCHICAL' ? monitorEnabled : undefined,
        mode === 'ROOT' && treeMode === 'DM' ? referralOpen : undefined,
        mode === 'ROOT' && treeMode === 'HIERARCHICAL' ? globalChat : undefined,
        useDefaultProfile,
        mode === 'JOIN' ? inviteFrag : undefined,
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="h-[100dvh] overflow-y-auto flex flex-col items-center p-4 sm:p-6 bg-[#0a0a0a] relative">
       {scanning && <QrScanner onResult={handleScanResult} onClose={() => setScanning(false)} />}
       <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent"></div>
       
       <div className="w-full max-w-sm bg-[#111] border border-white/10 rounded-3xl p-6 sm:p-8 shadow-2xl z-10 my-auto">
          <div className="flex justify-center mb-6 relative">
             <button onClick={onLogoutAccount} className="absolute -top-4 -right-4 text-zinc-600 hover:text-red-400 p-2 transition-colors" title="Logout Account">
                <LogOut className="w-4 h-4" />
             </button>
             <div className="w-16 h-16 bg-emerald-500/10 rounded-2xl flex items-center justify-center border border-emerald-500/20">
                <NetworkLogo />
             </div>
          </div>
          
          <h2 className="text-2xl font-bold text-center text-white mb-8">
              Identity Hub
          </h2>

          {mode === 'SELECT' ? (
            <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
               {(() => {
                  // Nodes are grouped by network type: your Personal Chats (hubs,
                  // yours AND any you were added to) on top, then hierarchical
                  // Networks, then Direct-Only (1:1) networks — each in its own
                  // labelled section.
                  const personal = myNodes.filter(u => u.treeMode === 'HUB');
                  const direct = myNodes.filter(u => u.treeMode === 'DM');
                  const networks = myNodes.filter(u => u.treeMode !== 'HUB' && u.treeMode !== 'DM');
                  const NodeRow = ({ u, sub }: { u: User; sub: string }) => (
                    <button
                      key={u.id}
                      onClick={() => onLogin(u)}
                      className="w-full flex items-center gap-3 p-4 bg-black border border-white/5 rounded-2xl hover:border-emerald-500/50 transition-all group text-left relative overflow-hidden active:scale-95"
                    >
                      <div className="w-10 h-10 rounded-xl flex items-center justify-center text-white font-bold text-sm shrink-0 shadow-lg" style={{ backgroundColor: u.color }}>
                        {u.name[0].toUpperCase()}
                      </div>
                      <div className="flex-1 overflow-hidden">
                        <div className="text-white font-bold truncate group-hover:text-emerald-400 transition-colors">{u.name}</div>
                        <div className="text-zinc-600 text-[9px] uppercase tracking-tighter font-mono truncate">{sub}</div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-zinc-700 group-hover:text-emerald-500 transition-all" />
                    </button>
                  );
                  return (
                    <div className="space-y-4 max-h-[300px] overflow-y-auto no-scrollbar pr-1">
                      {personal.length > 0 && (
                        <div className="space-y-2">
                          <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-widest flex items-center gap-2 px-1">
                            <MessageCircle className="w-3 h-3 text-emerald-500" /> Personal Chats
                          </div>
                          {personal.map(u => (
                            <NodeRow key={u.id} u={u}
                              sub={u.role === 'ROOT' ? 'Your chats' : (u.treeName || 'Personal chat')} />
                          ))}
                        </div>
                      )}
                      {networks.length > 0 && (
                        <div className="space-y-2">
                          <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-widest flex items-center gap-2 px-1">
                            <ShieldCheck className="w-3 h-3 text-emerald-500" /> Networks
                          </div>
                          {networks.map(u => <NodeRow key={u.id} u={u} sub={u.role} />)}
                        </div>
                      )}
                      {direct.length > 0 && (
                        <div className="space-y-2">
                          <div className="text-[10px] font-bold text-zinc-600 uppercase tracking-widest flex items-center gap-2 px-1">
                            <UserCircle className="w-3 h-3 text-emerald-500" /> Direct Only
                          </div>
                          {direct.map(u => <NodeRow key={u.id} u={u} sub={u.role === 'ROOT' ? 'Owner' : 'Member'} />)}
                        </div>
                      )}
                    </div>
                  );
               })()}

               <div className="pt-4 space-y-3">
                  <button 
                    onClick={() => pickMode('JOIN')} 
                    className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3.5 rounded-xl transition-all flex items-center justify-center gap-2 text-sm shadow-lg shadow-emerald-500/10"
                  >
                    <UserPlus className="w-4 h-4" /> {t('auth.joinByInvite')}
                  </button>
                  <button
                    onClick={() => pickMode('ROOT')}
                    className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3.5 rounded-xl transition-all flex items-center justify-center gap-2 text-sm shadow-lg shadow-emerald-500/10"
                  >
                    <Sprout className="w-4 h-4" /> {t('auth.createRootNode')}
                  </button>
                  <button
                    onClick={() => setShowDefault(true)}
                    className="w-full bg-white/[0.04] hover:bg-white/[0.08] text-zinc-300 font-bold py-3 rounded-xl transition-all flex items-center justify-center gap-2 text-[12px] border border-white/5"
                  >
                    <UserCircle className="w-4 h-4 text-emerald-500" /> Default profile
                  </button>
               </div>

               <div className="pt-5 mt-1 border-t border-white/5">
                  <div className="text-[9px] font-black uppercase tracking-[0.2em] text-zinc-600 mb-2 px-1">{t('auth.language')}</div>
                  <LanguagePicker />
                  <p className="text-[9px] text-zinc-600 leading-relaxed mt-2 px-1">{t('auth.languageHint')}</p>
               </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4 animate-in fade-in zoom-in-95 duration-300">
               <div>
                  <input 
                    type="text" 
                    placeholder={mode === 'ROOT' ? t('auth.orgNickname') : t('auth.alias')}
                    className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors"
                    value={name}
                    onChange={e => setName(e.target.value)}
                    required
                  />
                  {mode === 'JOIN' && (
                    <p className="text-[10px] text-zinc-500 leading-relaxed mt-2 px-1">
                      Pick an alias your inviter will <span className="text-emerald-400 font-bold">recognize you by</span> — they have to accept your request before you're connected.
                    </p>
                  )}
                  {/* V8 M-8: the account's default photo + bio are copied into this
                      network ONLY if the person opts in here. Reusing one face and
                      bio everywhere links you across otherwise-separate networks. */}
                  <label className="flex items-start gap-2 mt-2.5 px-1 cursor-pointer">
                    <input type="checkbox" checked={useDefaultProfile} onChange={e => setUseDefaultProfile(e.target.checked)} className="accent-emerald-500 mt-0.5" />
                    <span className="text-[10px] text-zinc-400 leading-relaxed">
                      Use my default photo &amp; bio here
                      <span className="block text-zinc-600">Off keeps this network unlinked from your others — you can add a photo later.</span>
                    </span>
                  </label>
               </div>

               <div>
                  <span className="text-[10px] text-zinc-500 font-black uppercase tracking-widest px-1">Icon color</span>
                  <div className="mt-2 flex items-center gap-3">
                     <div className="w-10 h-10 rounded-xl flex items-center justify-center text-white font-bold text-sm shrink-0 shadow-lg" style={{ backgroundColor: color }}>
                        {(name.trim()[0] || '?').toUpperCase()}
                     </div>
                     <div className="flex flex-wrap gap-1.5">
                        {ICON_COLORS.map(c => (
                          <button
                            key={c}
                            type="button"
                            onClick={() => setColor(c)}
                            aria-label={`Use color ${c}`}
                            className={`w-6 h-6 rounded-full transition-transform ${color === c ? 'ring-2 ring-white ring-offset-2 ring-offset-[#0a0a0a] scale-110' : 'hover:scale-110'}`}
                            style={{ backgroundColor: c }}
                          />
                        ))}
                     </div>
                  </div>
                  <p className="text-[10px] text-zinc-500 leading-relaxed mt-2 px-1">This is how your icon appears to everyone on the network. You can change it later in Settings.</p>
               </div>

               {mode === 'JOIN' && (
                 <div className="space-y-2.5">
                    <div className="relative">
                      <input
                        type="text"
                        placeholder={t('auth.inviteCode')}
                        className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors text-center font-mono uppercase tracking-[0.2em] placeholder:tracking-normal"
                        value={inviteCode}
                        onChange={e => {
                          const v = e.target.value;
                          // A pasted full link: keep the code AND its #fragment.
                          if (/invite=|#/.test(v)) { const c = extractInviteCode(v.split('#')[0]); if (c) setInviteCode(c); setInviteFrag(fragOf(v)); }
                          else { setInviteCode(v.toUpperCase()); }
                          if (scanError) setScanError(null);
                        }}
                        required
                      />
                    </div>
                    {inviteCode && !inviteFrag && (
                      <p className="text-[10px] text-amber-400/80 leading-relaxed px-1">Paste the full invite link (or scan its QR code). The code on its own can’t prove which network it belongs to.</p>
                    )}
                    <div className="flex items-center gap-3 px-1">
                      <div className="flex-1 h-px bg-white/10" />
                      <span className="text-[10px] text-zinc-600 font-black uppercase tracking-widest">or</span>
                      <div className="flex-1 h-px bg-white/10" />
                    </div>
                    <button
                      type="button"
                      onClick={() => { setScanError(null); setScanning(true); }}
                      className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[11px] font-black uppercase tracking-widest hover:bg-emerald-500/20 hover:border-emerald-500/50 active:scale-[0.99] transition-all"
                    >
                      <QrCode className="w-4 h-4" /> {t('auth.scanQr')}
                    </button>
                    {scanError && <p className="text-[11px] text-red-400/90 text-center px-1">{scanError}</p>}
                 </div>
               )}

               {mode === 'ROOT' && (
                 <div className="space-y-4">
                    <input 
                      type="text" 
                      placeholder={t('auth.networkName')}
                      className="w-full bg-black border border-white/10 rounded-xl px-4 py-3 text-white focus:border-emerald-500/50 outline-none transition-colors"
                      value={treeName}
                      onChange={e => setTreeName(e.target.value)}
                    />
                    {treeMode !== 'HUB' && (
                      <div className="flex items-start gap-3 px-1">
                        <button
                          type="button"
                          onClick={() => setTreeNameVisible(v => !v)}
                          role="switch"
                          aria-checked={treeNameVisible}
                          className={`mt-0.5 shrink-0 w-10 h-6 rounded-full transition-colors relative ${treeNameVisible ? 'bg-emerald-500' : 'bg-white/10'}`}
                        >
                          <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${treeNameVisible ? 'translate-x-4' : ''}`} />
                        </button>
                        <div>
                          <div className="text-[11px] font-bold text-white">{t('auth.showNameToEveryone')}</div>
                          <div className="text-[10px] text-zinc-500 leading-relaxed">
                            {t('auth.showNameHint')}
                          </div>
                        </div>
                      </div>
                    )}
                    <div className="space-y-2">
                       <span className="text-[10px] text-zinc-500 font-black uppercase tracking-widest px-1">Network Type</span>
                       <div className={`grid gap-2 ${hasHub ? 'grid-cols-2' : 'grid-cols-3'}`}>
                          <button
                            type="button"
                            onClick={() => setTreeMode('HIERARCHICAL')}
                            className={`p-3 rounded-xl border text-left transition-all ${treeMode === 'HIERARCHICAL' ? 'border-emerald-500/50 bg-emerald-500/10' : 'border-white/10 bg-black hover:border-white/20'}`}
                          >
                             <div className="text-xs font-bold text-white">Network</div>
                             <div className="text-[9px] text-zinc-500 leading-tight mt-1">Cascading orgs with divided sectors</div>
                          </button>
                          <button
                            type="button"
                            onClick={() => setTreeMode('DM')}
                            className={`p-3 rounded-xl border text-left transition-all ${treeMode === 'DM' ? 'border-emerald-500/50 bg-emerald-500/10' : 'border-white/10 bg-black hover:border-white/20'}`}
                          >
                             <div className="text-xs font-bold text-white">Direct Only</div>
                             <div className="text-[9px] text-zinc-500 leading-tight mt-1">Private client & small-business 1:1s</div>
                          </button>
                          {!hasHub && (
                          <button
                            type="button"
                            onClick={() => setTreeMode('HUB')}
                            className={`p-3 rounded-xl border text-left transition-all ${treeMode === 'HUB' ? 'border-emerald-500/50 bg-emerald-500/10' : 'border-white/10 bg-black hover:border-white/20'}`}
                          >
                             <div className="text-xs font-bold text-white">Personal</div>
                             <div className="text-[9px] text-zinc-500 leading-tight mt-1">Day-to-day chats with people</div>
                          </button>
                          )}
                       </div>
                       <p className="text-[10px] text-zinc-500 leading-relaxed px-1 pt-1">
                         {treeMode === 'HIERARCHICAL'
                           ? <><span className="text-emerald-400 font-bold">Chain-of-command network.</span> Anyone you accept can invite people beneath them. Talk up or down your chain, announce, monitor, and prune branches.</>
                           : treeMode === 'DM'
                           ? <><span className="text-emerald-400 font-bold">Private 1:1 roster.</span> By default only you invite people, and each talks 1:1 with you. Members never see each other. Turn on referral mode below to let members invite too.</>
                           : <><span className="text-emerald-400 font-bold">Your personal chats.</span> Share your link and anyone who joins gets a 1:1 with you. No structure.</>}
                       </p>
                       {treeMode === 'HIERARCHICAL' && (
                         <div className="flex items-start gap-3 px-1 pt-1">
                           <button
                             type="button"
                             onClick={() => setMonitorEnabled(v => !v)}
                             role="switch"
                             aria-checked={monitorEnabled}
                             className={`mt-0.5 shrink-0 w-10 h-6 rounded-full transition-colors relative ${monitorEnabled ? 'bg-emerald-500' : 'bg-white/10'}`}
                           >
                             <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${monitorEnabled ? 'translate-x-4' : ''}`} />
                           </button>
                           <div>
                             <div className="text-[11px] font-bold text-white">Enable monitoring</div>
                             <div className="text-[10px] text-zinc-500 leading-relaxed">Lets members oversee the two levels below them. You can change this later in Settings.</div>
                           </div>
                         </div>
                       )}
                       {treeMode === 'HIERARCHICAL' && (
                         <div className="flex items-start gap-3 px-1 pt-1">
                           <button
                             type="button"
                             onClick={() => setGlobalChat(v => !v)}
                             role="switch"
                             aria-checked={globalChat}
                             className={`mt-0.5 shrink-0 w-10 h-6 rounded-full transition-colors relative ${globalChat ? 'bg-emerald-500' : 'bg-white/10'}`}
                           >
                             <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${globalChat ? 'translate-x-4' : ''}`} />
                           </button>
                           <div>
                             <div className="text-[11px] font-bold text-white">Enable global chat</div>
                             <div className="text-[10px] text-zinc-500 leading-relaxed">One network-wide channel any member can read and post to; everyone in it sees each other’s name, photo and bio. It doesn’t connect people anywhere else. You can change this later in Settings.</div>
                           </div>
                         </div>
                       )}
                       {treeMode === 'DM' && (
                         <div className="flex items-start gap-3 px-1 pt-1">
                           <button
                             type="button"
                             onClick={() => setReferralOpen(v => !v)}
                             role="switch"
                             aria-checked={referralOpen}
                             className={`mt-0.5 shrink-0 w-10 h-6 rounded-full transition-colors relative ${referralOpen ? 'bg-emerald-500' : 'bg-white/10'}`}
                           >
                             <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${referralOpen ? 'translate-x-4' : ''}`} />
                           </button>
                           <div>
                             <div className="text-[11px] font-bold text-white">Let members invite (referral mode)</div>
                             <div className="text-[10px] text-zinc-500 leading-relaxed">Anyone you accept can share their own invite link. Everyone who joins connects 1:1 with you — never with each other — so your roster grows as a flat referral tree. You approve everyone a member brings in. Change this later in Settings.</div>
                           </div>
                         </div>
                       )}
                    </div>
                 </div>
               )}

               <button 
                type="submit" 
                disabled={isSubmitting}
                className="w-full bg-emerald-500 hover:bg-emerald-400 text-black font-bold py-3.5 rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-emerald-500/20 active:scale-95"
               >
                  {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : (
                      <>
                        {mode === 'JOIN' ? t('auth.initializeNode') : t('auth.createTree')}
                        <ArrowRight className="w-4 h-4" />
                      </>
                  )}
               </button>

               <div className="pt-4 flex flex-col items-center gap-4">
                  <button 
                    type="button" 
                    onClick={() => pickMode(mode === 'JOIN' ? 'ROOT' : 'JOIN')}
                    className="text-zinc-500 hover:text-white text-[10px] font-bold uppercase tracking-widest transition-colors"
                  >
                    {mode === 'JOIN' ? t('auth.switchToCreate') : t('auth.switchToJoin')}
                  </button>
                  {myNodes.length > 0 && (
                     <button 
                        type="button" 
                        onClick={() => pickMode('SELECT')}
                        className="text-emerald-500 hover:text-emerald-400 text-xs font-bold uppercase tracking-wide transition-colors"
                     >
                        Cancel
                     </button>
                  )}
               </div>
            </form>
          )}
       </div>

       {showDefault && (
         <div className="fixed inset-0 z-[90] bg-black/75 backdrop-blur-sm flex items-end sm:items-center justify-center p-0 sm:p-6 animate-in fade-in" onClick={() => setShowDefault(false)}>
           <div className="w-full sm:max-w-sm bg-[#111] border border-white/10 rounded-t-3xl sm:rounded-3xl p-6 max-h-[90dvh] overflow-y-auto no-scrollbar"
             onClick={e => e.stopPropagation()} style={{ paddingBottom: 'calc(env(safe-area-inset-bottom,0px) + 1.5rem)' }}>
             <DefaultProfileEditor ctaLabel="Save" onDone={() => { api.getAccountProfile().then(p => setDefaultName(p.name || '')).catch(() => {}); setShowDefault(false); }} />
           </div>
         </div>
       )}
    </div>
  );
};

export default AuthScreen;
