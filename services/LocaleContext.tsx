import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { LocaleCode, translate, getStoredLocale, storeLocale, isRTL } from './i18n';

interface LocaleCtx {
  locale: LocaleCode;
  setLocale: (c: LocaleCode) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const Ctx = createContext<LocaleCtx | null>(null);

export const LocaleProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [locale, setLocaleState] = useState<LocaleCode>(() => getStoredLocale());

  const setLocale = useCallback((c: LocaleCode) => {
    storeLocale(c);
    setLocaleState(c);
  }, []);

  // Keep the document's lang + direction in sync (helps a11y and RTL layout).
  useEffect(() => {
    try {
      document.documentElement.lang = locale;
      document.documentElement.dir = isRTL(locale) ? 'rtl' : 'ltr';
    } catch { /* ignore */ }
  }, [locale]);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => translate(locale, key, vars),
    [locale],
  );

  return <Ctx.Provider value={{ locale, setLocale, t }}>{children}</Ctx.Provider>;
};

/** Access the current locale + t() helper. Safe to call anywhere under the provider. */
export function useLocale(): LocaleCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useLocale must be used within LocaleProvider');
  return c;
}

/** Convenience: just the translate function. */
export function useT() {
  return useLocale().t;
}
