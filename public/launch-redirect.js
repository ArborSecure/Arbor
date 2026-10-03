// Installed home-screen icons launch '/' in standalone display mode. The app now
// lives at /launch, so forward standalone launches there (with a one-time flag so
// the app can show a "re-add to home screen" notice). Ordinary browser visits fall
// through to the marketing page. This is an external file, loaded early in <head>,
// because the site CSP is script-src 'self' (inline scripts are blocked).
(function () {
  try {
    var qsEarly = window.location.search || '';
    // Invite links historically pointed at '/?invite=CODE'. '/' is now the marketing
    // page, so forward any invite link (including ones already shared) to the app at
    // /launch, preserving the code — AuthScreen reads ?invite= from the search string.
    if (new URLSearchParams(qsEarly).get('invite')) { window.location.replace('/launch' + qsEarly + (window.location.hash || '')); return; } // keep the #fragment: it carries the link's keys (V8 phase 2)
    var mm = window.matchMedia && window.matchMedia('(display-mode: standalone)');
    var standalone = (mm && mm.matches) || window.navigator.standalone === true;
    if (!standalone) return;
    var qs = window.location.search || '';
    window.location.replace('/launch' + (qs ? qs + '&' : '?') + 'migrated=1');
  } catch (e) { /* never block the page on a redirect check */ }
})();
