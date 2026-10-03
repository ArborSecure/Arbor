import React, { useState, useRef, useEffect } from 'react';
import { Globe, Check, ChevronDown } from 'lucide-react';
import { LOCALES, LocaleCode } from '../services/i18n';
import { useLocale } from '../services/LocaleContext';

/** A compact language dropdown. Shows the current language's native name and,
 *  when opened, the full list with a check on the active one. Used both during
 *  account setup and in Settings — same control, so the two stay consistent. */
const LanguagePicker: React.FC<{ compact?: boolean }> = ({ compact }) => {
  const { locale, setLocale } = useLocale();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = LOCALES.find(l => l.code === locale) || LOCALES[0];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const pick = (code: LocaleCode) => { setLocale(code); setOpen(false); };

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className={`w-full flex items-center gap-2.5 bg-black border border-white/10 rounded-xl px-3.5 ${compact ? 'py-2.5' : 'py-3'} text-left hover:border-emerald-500/40 transition-colors`}
      >
        <Globe className="w-4 h-4 text-emerald-500 shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="text-sm text-white font-bold truncate">{current.native}</div>
          {!compact && current.native !== current.name && (
            <div className="text-[9px] text-zinc-600 uppercase tracking-widest">{current.name}</div>
          )}
        </div>
        <ChevronDown className={`w-4 h-4 text-zinc-500 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="absolute z-50 mt-2 left-0 right-0 max-h-64 overflow-y-auto no-scrollbar bg-[#0e0e0e] border border-white/10 rounded-2xl shadow-2xl shadow-black/60 p-1.5 animate-in fade-in slide-in-from-top-1 duration-150">
          {LOCALES.map(l => (
            <button
              key={l.code}
              type="button"
              onClick={() => pick(l.code)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-colors ${l.code === locale ? 'bg-emerald-500/10' : 'hover:bg-white/[0.04]'}`}
            >
              <div className="flex-1 min-w-0">
                <div className={`text-sm truncate ${l.code === locale ? 'text-emerald-400 font-bold' : 'text-white font-medium'}`}>{l.native}</div>
                <div className="text-[9px] text-zinc-600 uppercase tracking-widest">{l.name}</div>
              </div>
              {l.code === locale && <Check className="w-4 h-4 text-emerald-500 shrink-0" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default LanguagePicker;
