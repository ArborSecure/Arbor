// Lightweight i18n for Arbor. No external deps: a flat key→string dictionary per
// locale, a detection step that reads the browser's preferred languages, and a
// tiny interpolation helper ({name} placeholders). The chosen locale is a device
// UI preference persisted in localStorage — it works before login and never
// leaves the device.

export type LocaleCode =
  | 'en' | 'es' | 'fr' | 'de' | 'pt' | 'it' | 'nl'
  | 'ru' | 'uk' | 'pl' | 'tr' | 'ar' | 'hi' | 'id'
  | 'ja' | 'ko' | 'zh' | 'vi' | 'th';

export interface LocaleMeta { code: LocaleCode; name: string; native: string; rtl?: boolean; }

// Display order roughly by global reach. `native` is what shows in the picker so
// people recognize their own language even if the UI is currently in another.
export const LOCALES: LocaleMeta[] = [
  { code: 'en', name: 'English',    native: 'English' },
  { code: 'es', name: 'Spanish',    native: 'Español' },
  { code: 'zh', name: 'Chinese',    native: '中文' },
  { code: 'hi', name: 'Hindi',      native: 'हिन्दी' },
  { code: 'ar', name: 'Arabic',     native: 'العربية', rtl: true },
  { code: 'pt', name: 'Portuguese', native: 'Português' },
  { code: 'ru', name: 'Russian',    native: 'Русский' },
  { code: 'ja', name: 'Japanese',   native: '日本語' },
  { code: 'de', name: 'German',     native: 'Deutsch' },
  { code: 'fr', name: 'French',     native: 'Français' },
  { code: 'ko', name: 'Korean',     native: '한국어' },
  { code: 'it', name: 'Italian',    native: 'Italiano' },
  { code: 'tr', name: 'Turkish',    native: 'Türkçe' },
  { code: 'vi', name: 'Vietnamese', native: 'Tiếng Việt' },
  { code: 'pl', name: 'Polish',     native: 'Polski' },
  { code: 'uk', name: 'Ukrainian',  native: 'Українська' },
  { code: 'nl', name: 'Dutch',      native: 'Nederlands' },
  { code: 'id', name: 'Indonesian', native: 'Bahasa Indonesia' },
  { code: 'th', name: 'Thai',       native: 'ไทย' },
];

const SUPPORTED = new Set(LOCALES.map(l => l.code));
const STORAGE_KEY = 'arbor_locale';

export function isRTL(code: LocaleCode): boolean {
  return !!LOCALES.find(l => l.code === code)?.rtl;
}

/** Map a raw BCP-47 tag ("pt-BR", "zh-Hans-CN") to a supported base locale. */
function normalize(tag: string): LocaleCode | null {
  const base = tag.toLowerCase().split('-')[0];
  return SUPPORTED.has(base as LocaleCode) ? (base as LocaleCode) : null;
}

/** Best-guess locale from the browser's ordered language preferences. */
export function detectLocale(): LocaleCode {
  const prefs: string[] = (typeof navigator !== 'undefined'
    ? (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language])
    : []) as string[];
  for (const p of prefs) { const m = p && normalize(p); if (m) return m; }
  return 'en';
}

/** The persisted choice if any, else the auto-detected locale. */
export function getStoredLocale(): LocaleCode {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && SUPPORTED.has(saved as LocaleCode)) return saved as LocaleCode;
  } catch { /* ignore */ }
  return detectLocale();
}

export function storeLocale(code: LocaleCode) {
  try { localStorage.setItem(STORAGE_KEY, code); } catch { /* ignore */ }
}

/** True when the user has never explicitly chosen (so we can auto-detect). */
export function hasStoredLocale(): boolean {
  try { return !!localStorage.getItem(STORAGE_KEY); } catch { return false; }
}

// ---------------------------------------------------------------------------
// Dictionaries. English is the source of truth and the fallback for any missing
// key in another locale. Only user-facing UI strings live here (not console/log
// text). Placeholders use {name} style and are filled by t()'s second arg.
// ---------------------------------------------------------------------------
type Dict = Record<string, string>;

const en: Dict = {
  // Auth / onboarding
  'auth.tagline': 'Encrypted networks that grow like trees.',
  'auth.joinByInvite': 'Join by Invite',
  'auth.createRootNode': 'Create Network',
  'auth.orgNickname': 'Nickname',
  'auth.alias': 'Operational Alias',
  'auth.inviteCode': 'Invite Code',
  'auth.scanQr': 'Scan QR code',
  'auth.networkName': 'Network Name',
  'auth.showNameToEveryone': 'Show name to everyone',
  'auth.showNameHint': 'When on, every member sees this name in their header. When off, only you and True Sight holders do. This can always be changed in settings.',
  'auth.createTree': 'Create Network Tree',
  'auth.initializeNode': 'Join Existing Tree',
  'auth.switchToCreate': 'Create Network Tree',
  'auth.switchToJoin': 'Join Existing Tree',
  'auth.back': 'Back',
  'auth.language': 'Language',
  'auth.languageHint': 'Auto-detected from your device. You can change it anytime in settings.',

  // Tabs / nav
  'nav.ancestors': 'Ancestors',
  'nav.descendants': 'Descendants',
  'nav.chats': 'Chats',
  'nav.myInvitees': 'My Invitees',
  'nav.broadcast': 'Announcements',
  'nav.networkTree': 'Network Tree',
  'nav.monitor': 'Monitor Hub',
  'nav.howto': 'How To Use',
  'nav.settings': 'Settings',
  'nav.menu': 'Menu',
  'nav.protocols': 'Protocols',

  // Composer / messages
  'composer.placeholder': 'Type a message…',
  'composer.send': 'Send',
  'composer.reply': 'Reply',
  'composer.replyingTo': 'Replying to {name}',
  'msg.acknowledge': 'Acknowledge',
  'msg.acknowledged': 'Acknowledged',
  'msg.announcementFromLevel': 'Announcement from level {level}',
  'msg.you': 'You',
  'msg.today': 'Today',
  'msg.yesterday': 'Yesterday',

  // Calls
  'call.outgoing': 'Outgoing call',
  'call.incoming': 'Incoming call',
  'call.missed': 'Missed call',
  'call.declined': 'Call declined',
  'call.noAnswer': 'No answer',

  // Settings
  'settings.title': 'Settings',
  'settings.language': 'Language',
  'settings.languageDesc': 'Choose the language for the Arbor interface. This applies to this device.',
  'settings.readReceipts': 'Read receipts',
  'settings.notifications': 'Notifications',
  'settings.network': 'Network',
  'settings.networkNameLabel': 'Network Name',
  'settings.showNameToEveryone': 'Show name to everyone',
  'settings.showNameToEveryoneDesc': 'When on, every member sees this name in their header. When off, only you and True Sight holders see it. This is separate from True Sight, which only controls who can see the whole network tree.',
  'settings.save': 'Save',
  'settings.saved': 'Saved',

  // Sidebar
  'side.directLinks': 'Direct Links',
  'side.isolatedNode': 'Isolated Node',
  'side.joinRequests': 'Join Requests',
  'side.contactRequests': 'Contact Requests',
  'side.networkPlan': 'Network Plan',
  'side.device': 'Device',
  'side.personalChats': 'Personal Chats',
  'side.encrypted': 'ENCRYPTED',
  'side.gridNetwork': 'Grid Network',

  // Hub chat list
  'hub.searchAll': 'Search all chats…',
  'hub.noChatsTitle': 'No chats yet',
  'hub.results': 'Results in all chats',
  'hub.noMatches': 'No matches in any chat.',
  'hub.sayHi': 'No messages yet — say hi',
  'hub.waiting': 'Request sent — waiting for them to accept',
  'hub.chats': 'Chats',
  'hub.chat': 'Chat',

  // Selection bar
  'sel.selected': 'selected',
  'sel.deleteForMe': 'Delete for me',
  'sel.deleteForAll': 'Delete for all',
  'sel.edit': 'Edit',

  // Message labels
  'msg.unread': 'Unread',
  'msg.edited': 'edited',
  'msg.disappears': 'Disappears',
  'msg.translate': 'Translate',
  'msg.translating': 'Translating…',
  'msg.showOriginal': 'Show original',
  'msg.showTranslation': 'Show translation',
  'msg.awaitingAck': 'Awaiting acknowledgment',
  'msg.ackedBy': 'Acknowledged by {names}',

  // Composer
  'comp.message': 'Message…',
  'comp.recording': 'Recording…',
  'comp.reqAck': 'Request acknowledgment',
  'comp.editing': 'Editing message',
  'comp.scheduleTitle': 'Schedule message',
  'comp.schedule': 'Schedule',
  'comp.sealing': 'Sealing…',
  'comp.scheduled': 'Scheduled',

  // Broadcast
  'bc.reach': 'Announcement reach',
  'bc.everyoneBelow': 'Everyone below me',
  'bc.clear': 'Clear',
  'bc.ackDashboard': 'Acknowledgment dashboard',
  'bc.acknowledgments': 'Acknowledgments',
  'bc.sent': 'sent',
  'bc.receiveOnly': 'Receive-only — the network root can grant you announcement rights from the Network Tree.',

  // Monitor
  'mon.selectTarget': 'Select Monitoring Target',
  'mon.activeTrace': 'Active Trace',
  'mon.noSubnodes': 'No sub-nodes available to monitor',

  // Settings extras
  'settings.privacy': 'Privacy',
  'settings.autoTranslate': 'Auto-translate messages',
  'settings.autoTranslateDesc': "Automatically translate incoming messages into your language, on this device. Uses your browser's built-in on-device translator — nothing is sent to a server.",
  'settings.member': 'Member',
  'settings.networkRoot': 'Network Root',

  // Common
  'common.cancel': 'Cancel',
  'common.confirm': 'Confirm',
  'common.copy': 'Copy',
  'common.copied': 'Copied',
  'common.search': 'Search',
  'common.back': 'Back',
  'common.noSignal': 'No Signal Detected',
  'common.noMatchesShort': 'No Matches',

  // Settings — sections & rows
  'settings.readReceiptsDesc': "Let others see when you've read their messages. Reciprocal — you only receive read receipts from people if you send yours too.",
  'settings.notificationsBlocked': 'Blocked in your browser/OS settings.',
  'settings.notificationsDesc': 'Push alerts for new messages and calls on this device.',
  'settings.oneOnOneSettings': '1:1 Settings',
  'settings.oneOnOneName': '1:1 Name',
  'settings.networkName': 'Network Name',
  'settings.showNameEveryone': 'Show name to everyone',
  'settings.showNameEveryoneDesc': 'When on, every member sees this name in their header. When off, only you and True Sight holders see it. This is separate from True Sight, which only controls who can see the whole network tree.',
  'settings.accountRecovery': 'Account Recovery',
  'settings.recoveryWarn': 'Write these 12 words down and store them physically. This is the ONLY failsafe way to access your account if you forget your credentials. Passwords cannot be reset. Anyone with this phrase can recover your login — keep it secret.',
  'settings.copyPhrase': 'Copy phrase',
  'settings.savedItDone': "I've saved it — Done",
  'settings.checkingRecovery': 'Checking recovery status…',
  'settings.recoverySet': 'Recovery phrase is set up',
  'settings.confirmPwToGenerate': 'Confirm the password for {user} to generate a recovery phrase. The phrase is created on this device — the server only ever stores it encrypted.',
  'settings.currentPassword': 'Current password',
  'settings.verifying': 'Verifying…',
  'settings.generatePhrase': 'Generate phrase',
  'settings.noRecoveryOnFile': 'No recovery phrase on file. Without one, a forgotten password means permanent loss of access — passwords cannot be reset.',
  'settings.generateRecovery': 'Generate recovery phrase',
  'settings.dangerZone': 'Danger Zone',
  'settings.panicConfirm': 'Panic Wipe erases all local data on THIS device and logs you out. Your account and messages on the server are unaffected. Continue?',
  'settings.panicWipe': 'Panic Wipe (this device)',
  'settings.deleteNetworkConfirm': 'Permanently DELETE this entire network ({count})? Every message, invite, and member node is removed for everyone. This cannot be undone.',
  'settings.deleteNetworkConfirm2': 'Are you absolutely sure? This is irreversible.',
  'settings.deleteNetwork': 'Delete Entire Network',
  'settings.member_one': '{count} member',
  'settings.member_other': '{count} members',
  'settings.devNotice': 'Arbor is still in development. Please send bug reports to bugreports@arborsecure.app',

  // Media / message states
  'media.videoUnsupported': "This device can't decode this video format",
  'media.downloadInstead': 'Download instead',
  'media.audioBlocked': 'Audio blocked',

  // Billing / plan
  'plan.upgradePrompt': 'Upgrade to Arbor Premium to keep growing.',
  'plan.upgradeNow': 'Upgrade now',
  'plan.dismiss': 'Dismiss',
  'plan.upgrade': 'Upgrade',
  'plan.premium': 'Arbor Premium',
  'plan.send': 'Send',
  'plan.copyAddress': 'Copy address',
  'plan.copyLink': 'Copy link',
  'plan.close': 'Close',
  'plan.retry': 'Retry',
  'plan.scanToJoin': 'Scan to install & join',
  'plan.networkArchived': 'Network Archived',

  // Empty / status
  'status.isolatedNode': 'Isolated Node',
  'status.panicWipe': 'Panic Wipe',
  'status.protocolActive': 'Protocol Active',
  'status.noOneBelow': 'No one below you yet.',
  'status.noNodes': 'No nodes to display.',
  'status.connecting': 'Connecting…',
  'status.noAckAnnouncements': 'No acknowledgment-requested announcements yet.',
  'status.awaitingAckEllipsis': 'Awaiting acknowledgment…',

  // Call
  'call.video': 'Video',
  'call.voice': 'Voice',

  // Onboarding
  'onboard.welcome': 'Welcome to Arbor',
  'onboard.readGuide': 'Read the guide',
  'onboard.skip': 'Skip',

  // How-To guide
  'howto.title': 'How To Use Arbor',
  'howto.flavorsIntro': 'Arbor spaces come in three flavors, chosen when the space is created:',
  'howto.flavorNetwork': 'Network',
  'howto.flavorDirect': 'Direct Only',
  'howto.flavorPersonal': 'Personal',
  'howto.ancestorsTitle': 'Ancestors',
  'howto.descendantsTitle': 'Descendants',
  'howto.chatTitle': 'Chat',
  'howto.chatsTitle': 'Chats',
  'howto.broadcastTitle': 'Announcements',
  'howto.trueSightTitle': 'Network Tree & True Sight',
  'howto.monitorTitle': 'Monitor Hub',
  'howto.growTitle': 'Growing your space',
  'howto.disappearTitle': 'Disappearing messages',
  'howto.lockTitle': 'App Lock',
};

// For locales without full coverage yet, we provide the highest-traffic strings
// (auth, nav, composer, calls, settings headers) and fall back to English for
// the rest. This keeps the app usable in each language immediately while leaving
// room to expand coverage without code changes.
const es: Dict = {
  'settings.title': 'Ajustes', 'settings.language': 'Idioma',
  'settings.languageDesc': 'Cambia el idioma de toda la app en este dispositivo.',
  'settings.readReceipts': 'Confirmaciones de lectura',
  'settings.readReceiptsDesc': 'Permite que otros vean cuándo leíste sus mensajes. Es recíproco: solo recibes confirmaciones si también envías las tuyas.',
  'settings.notifications': 'Notificaciones', 'settings.notificationsBlocked': 'Bloqueadas en los ajustes del navegador o del sistema.',
  'settings.notificationsDesc': 'Alertas push de nuevos mensajes y llamadas en este dispositivo.',
  'settings.oneOnOneSettings': 'Ajustes 1:1', 'settings.network': 'Red',
  'settings.oneOnOneName': 'Nombre 1:1', 'settings.networkName': 'Nombre de la red',
  'settings.save': 'Guardar', 'settings.saved': 'Guardado',
  'settings.showNameEveryone': 'Mostrar el nombre a todos',
  'settings.showNameEveryoneDesc': 'Si está activado, cada miembro ve este nombre en su encabezado. Si está desactivado, solo tú y quienes tengan Visión Verdadera lo ven. Es independiente de Visión Verdadera, que solo controla quién ve todo el árbol de la red.',
  'settings.accountRecovery': 'Recuperación de cuenta',
  'settings.recoveryWarn': 'Anota estas 12 palabras y guárdalas físicamente. Es la ÚNICA forma segura de acceder a tu cuenta si olvidas tus credenciales. Las contraseñas no se pueden restablecer. Cualquiera con esta frase puede recuperar tu acceso — mantenla en secreto.',
  'settings.copyPhrase': 'Copiar frase', 'settings.savedItDone': 'Ya la guardé — Listo',
  'settings.checkingRecovery': 'Comprobando estado de recuperación…', 'settings.recoverySet': 'La frase de recuperación está configurada',
  'settings.confirmPwToGenerate': 'Confirma la contraseña de {user} para generar una frase de recuperación. La frase se crea en este dispositivo — el servidor solo la almacena cifrada.',
  'settings.currentPassword': 'Contraseña actual', 'settings.verifying': 'Verificando…', 'settings.generatePhrase': 'Generar frase',
  'settings.noRecoveryOnFile': 'No hay frase de recuperación. Sin ella, olvidar la contraseña significa perder el acceso para siempre — las contraseñas no se pueden restablecer.',
  'settings.generateRecovery': 'Generar frase de recuperación', 'settings.dangerZone': 'Zona de peligro',
  'settings.panicConfirm': 'El Borrado de Emergencia elimina todos los datos locales en ESTE dispositivo y cierra tu sesión. Tu cuenta y tus mensajes en el servidor no se ven afectados. ¿Continuar?',
  'settings.panicWipe': 'Borrado de emergencia (este dispositivo)',
  'settings.deleteNetworkConfirm': '¿ELIMINAR permanentemente toda esta red ({count})? Cada mensaje, invitación y nodo de miembro se elimina para todos. Esto no se puede deshacer.',
  'settings.deleteNetworkConfirm2': '¿Estás completamente seguro? Esto es irreversible.', 'settings.deleteNetwork': 'Eliminar toda la red',
  'settings.member_one': '{count} miembro', 'settings.member_other': '{count} miembros',
  'settings.devNotice': 'Arbor aún está en desarrollo. Envía informes de errores a bugreports@arborsecure.app',
  'media.videoUnsupported': 'Este dispositivo no puede decodificar este formato de vídeo', 'media.downloadInstead': 'Descargar', 'media.audioBlocked': 'Audio bloqueado',
  'plan.upgradePrompt': 'Mejora a Arbor Premium para seguir creciendo.', 'plan.upgradeNow': 'Mejorar ahora', 'plan.dismiss': 'Descartar',
  'plan.upgrade': 'Mejorar', 'plan.premium': 'Arbor Premium', 'plan.send': 'Enviar', 'plan.copyAddress': 'Copiar dirección',
  'plan.copyLink': 'Copiar enlace', 'plan.close': 'Cerrar', 'plan.retry': 'Reintentar', 'plan.scanToJoin': 'Escanea para instalar y unirte', 'plan.networkArchived': 'Red archivada',
  'status.isolatedNode': 'Nodo aislado', 'status.panicWipe': 'Borrado de emergencia', 'status.protocolActive': 'Protocolo activo',
  'status.noOneBelow': 'Aún no hay nadie por debajo de ti.', 'status.noNodes': 'No hay nodos para mostrar.', 'status.connecting': 'Conectando…',
  'status.noAckAnnouncements': 'Aún no hay anuncios que requieran confirmación.', 'status.awaitingAckEllipsis': 'Esperando confirmación…',
  'call.video': 'Vídeo', 'call.voice': 'Voz',
  'onboard.welcome': 'Bienvenido a Arbor', 'onboard.readGuide': 'Leer la guía', 'onboard.skip': 'Omitir',
  'howto.title': 'Cómo usar Arbor',

  'auth.tagline': 'Redes cifradas que crecen como árboles.',
  'auth.joinByInvite': 'Unirse por invitación',
  'auth.createRootNode': 'Crear red',
  'auth.orgNickname': 'Apodo',
  'auth.alias': 'Alias operativo',
  'auth.inviteCode': 'Código de invitación',
  'auth.networkName': 'Nombre de la red',
  'auth.showNameToEveryone': 'Mostrar el nombre a todos',
  'auth.showNameHint': 'Si está activado, todos los miembros ven este nombre en su cabecera. Si no, solo tú y quienes tienen Visión Verdadera. Se puede cambiar en ajustes.',
  'auth.createTree': 'Crear árbol de red',
  'auth.initializeNode': 'Unirse a un árbol existente',
  'auth.switchToCreate': 'Crear árbol de red',
  'auth.switchToJoin': 'Unirse a un árbol existente',
  'auth.back': 'Atrás',
  'auth.language': 'Idioma',
  'auth.languageHint': 'Detectado automáticamente de tu dispositivo. Puedes cambiarlo cuando quieras en ajustes.',
  'nav.ancestors': 'Ascendientes', 'nav.descendants': 'Descendientes', 'nav.chats': 'Chats',
  'nav.myInvitees': 'Mis invitados', 'nav.broadcast': 'Anuncios', 'nav.networkTree': 'Árbol de red',
  'nav.monitor': 'Centro de monitoreo', 'nav.howto': 'Cómo usar', 'nav.settings': 'Ajustes',
  'nav.menu': 'Menú', 'nav.protocols': 'Protocolos',
  'composer.placeholder': 'Escribe un mensaje…', 'composer.send': 'Enviar', 'composer.reply': 'Responder',
  'composer.replyingTo': 'Respondiendo a {name}',
  'msg.acknowledge': 'Confirmar', 'msg.acknowledged': 'Confirmado',
  'msg.announcementFromLevel': 'Anuncio del nivel {level}', 'msg.you': 'Tú',
  'msg.today': 'Hoy', 'msg.yesterday': 'Ayer',
  'call.outgoing': 'Llamada saliente', 'call.incoming': 'Llamada entrante', 'call.missed': 'Llamada perdida',
  'call.declined': 'Llamada rechazada', 'call.noAnswer': 'Sin respuesta',
  'settings.showNameToEveryone': 'Mostrar el nombre a todos',
  'settings.showNameToEveryoneDesc': 'Si está activado, todos los miembros ven este nombre en su cabecera. Si no, solo tú y quienes tienen Visión Verdadera. Es independiente de la Visión Verdadera, que solo controla quién ve todo el árbol de la red.',
  'common.cancel': 'Cancelar', 'common.confirm': 'Confirmar', 'common.copy': 'Copiar',
  'common.copied': 'Copiado', 'common.search': 'Buscar', 'common.back': 'Atrás',
  'common.noSignal': 'Sin señal detectada', 'common.noMatchesShort': 'Sin resultados',
  'side.directLinks': 'Enlaces directos', 'side.isolatedNode': 'Nodo aislado',
  'side.joinRequests': 'Solicitudes de ingreso', 'side.contactRequests': 'Solicitudes de contacto',
  'side.networkPlan': 'Plan de red', 'side.device': 'Dispositivo',
  'side.personalChats': 'Chats personales', 'side.encrypted': 'CIFRADO', 'side.gridNetwork': 'Red',
  'hub.searchAll': 'Buscar en todos los chats…',
  'hub.noChatsTitle': 'Aún no hay chats', 'hub.results': 'Resultados en todos los chats',
  'hub.noMatches': 'Sin coincidencias en ningún chat.', 'hub.sayHi': 'Sin mensajes — saluda',
  'hub.waiting': 'Solicitud enviada — esperando que acepte', 'hub.chats': 'Chats', 'hub.chat': 'Chat',
  'sel.selected': 'seleccionados', 'sel.deleteForMe': 'Borrar para mí', 'sel.deleteForAll': 'Borrar para todos', 'sel.edit': 'Editar',
  'msg.unread': 'No leídos', 'msg.edited': 'editado', 'msg.disappears': 'Desaparece',
  'msg.translate': 'Traducir', 'msg.translating': 'Traduciendo…', 'msg.showOriginal': 'Ver original',
  'msg.showTranslation': 'Ver traducción', 'msg.awaitingAck': 'Esperando confirmación',
  'msg.ackedBy': 'Confirmado por {names}',
  'comp.message': 'Mensaje…', 'comp.recording': 'Grabando…', 'comp.reqAck': 'Pedir confirmación',
  'comp.editing': 'Editando mensaje', 'comp.scheduleTitle': 'Programar mensaje',
  'comp.schedule': 'Programar', 'comp.sealing': 'Cifrando…', 'comp.scheduled': 'Programado',
  'bc.reach': 'Alcance del anuncio', 'bc.everyoneBelow': 'Todos por debajo de mí', 'bc.clear': 'Limpiar',
  'bc.ackDashboard': 'Panel de confirmaciones', 'bc.acknowledgments': 'Confirmaciones', 'bc.sent': 'enviados',
  'bc.receiveOnly': 'Solo recepción — la raíz de la red puede concederte derechos de anuncio desde el Árbol de red.',
  'mon.selectTarget': 'Elegir objetivo de monitoreo', 'mon.activeTrace': 'Rastreo activo',
  'mon.noSubnodes': 'No hay subnodos para monitorear',
  'settings.privacy': 'Privacidad', 'settings.autoTranslate': 'Traducir mensajes automáticamente',
  'settings.autoTranslateDesc': 'Traduce automáticamente los mensajes entrantes a tu idioma, en este dispositivo. Usa el traductor integrado del navegador — nada se envía a un servidor.',
  'settings.member': 'Miembro', 'settings.networkRoot': 'Raíz de la red',
};

const fr: Dict = {
  'settings.title': 'Paramètres', 'settings.language': 'Langue',
  'settings.languageDesc': "Change la langue de toute l'application sur cet appareil.",
  'settings.readReceipts': 'Accusés de lecture',
  'settings.readReceiptsDesc': "Permet aux autres de voir quand vous avez lu leurs messages. Réciproque : vous ne recevez d'accusés que si vous envoyez les vôtres.",
  'settings.notifications': 'Notifications', 'settings.notificationsBlocked': 'Bloquées dans les réglages du navigateur ou du système.',
  'settings.notificationsDesc': 'Alertes push pour les nouveaux messages et appels sur cet appareil.',
  'settings.oneOnOneSettings': 'Paramètres 1:1', 'settings.network': 'Réseau',
  'settings.oneOnOneName': 'Nom 1:1', 'settings.networkName': 'Nom du réseau',
  'settings.save': 'Enregistrer', 'settings.saved': 'Enregistré',
  'settings.showNameEveryone': 'Montrer le nom à tous',
  'settings.showNameEveryoneDesc': "Si activé, chaque membre voit ce nom dans son en-tête. Sinon, seuls vous et les détenteurs de la Vraie Vue le voient. C'est distinct de la Vraie Vue, qui contrôle seulement qui voit tout l'arbre du réseau.",
  'settings.accountRecovery': 'Récupération du compte',
  'settings.recoveryWarn': "Notez ces 12 mots et conservez-les physiquement. C'est le SEUL moyen sûr d'accéder à votre compte si vous oubliez vos identifiants. Les mots de passe ne peuvent pas être réinitialisés. Quiconque possède cette phrase peut récupérer votre accès — gardez-la secrète.",
  'settings.copyPhrase': 'Copier la phrase', 'settings.savedItDone': "Je l'ai enregistrée — Terminé",
  'settings.checkingRecovery': 'Vérification du statut de récupération…', 'settings.recoverySet': 'La phrase de récupération est configurée',
  'settings.confirmPwToGenerate': "Confirmez le mot de passe de {user} pour générer une phrase de récupération. Elle est créée sur cet appareil — le serveur ne la stocke que chiffrée.",
  'settings.currentPassword': 'Mot de passe actuel', 'settings.verifying': 'Vérification…', 'settings.generatePhrase': 'Générer la phrase',
  'settings.noRecoveryOnFile': "Aucune phrase de récupération enregistrée. Sans elle, un mot de passe oublié signifie une perte d'accès définitive — les mots de passe ne peuvent pas être réinitialisés.",
  'settings.generateRecovery': 'Générer une phrase de récupération', 'settings.dangerZone': 'Zone de danger',
  'settings.panicConfirm': "L'Effacement d'Urgence supprime toutes les données locales sur CET appareil et vous déconnecte. Votre compte et vos messages sur le serveur ne sont pas affectés. Continuer ?",
  'settings.panicWipe': "Effacement d'urgence (cet appareil)",
  'settings.deleteNetworkConfirm': 'SUPPRIMER définitivement tout ce réseau ({count}) ? Chaque message, invitation et nœud membre est retiré pour tout le monde. Ceci est irréversible.',
  'settings.deleteNetworkConfirm2': 'Êtes-vous absolument sûr ? Ceci est irréversible.', 'settings.deleteNetwork': 'Supprimer tout le réseau',
  'settings.member_one': '{count} membre', 'settings.member_other': '{count} membres',
  'settings.devNotice': 'Arbor est encore en développement. Envoyez vos rapports de bugs à bugreports@arborsecure.app',
  'media.videoUnsupported': 'Cet appareil ne peut pas décoder ce format vidéo', 'media.downloadInstead': 'Télécharger', 'media.audioBlocked': 'Audio bloqué',
  'plan.upgradePrompt': 'Passez à Arbor Premium pour continuer à grandir.', 'plan.upgradeNow': 'Mettre à niveau', 'plan.dismiss': 'Ignorer',
  'plan.upgrade': 'Mettre à niveau', 'plan.premium': 'Arbor Premium', 'plan.send': 'Envoyer', 'plan.copyAddress': "Copier l'adresse",
  'plan.copyLink': 'Copier le lien', 'plan.close': 'Fermer', 'plan.retry': 'Réessayer', 'plan.scanToJoin': 'Scannez pour installer et rejoindre', 'plan.networkArchived': 'Réseau archivé',
  'status.isolatedNode': 'Nœud isolé', 'status.panicWipe': "Effacement d'urgence", 'status.protocolActive': 'Protocole actif',
  'status.noOneBelow': 'Personne en dessous de vous pour l’instant.', 'status.noNodes': 'Aucun nœud à afficher.', 'status.connecting': 'Connexion…',
  'status.noAckAnnouncements': 'Aucune annonce à confirmer pour l’instant.', 'status.awaitingAckEllipsis': 'En attente de confirmation…',
  'call.video': 'Vidéo', 'call.voice': 'Voix',
  'onboard.welcome': 'Bienvenue sur Arbor', 'onboard.readGuide': 'Lire le guide', 'onboard.skip': 'Passer',
  'howto.title': 'Comment utiliser Arbor',

  'auth.tagline': 'Des réseaux chiffrés qui poussent comme des arbres.',
  'auth.joinByInvite': 'Rejoindre par invitation',
  'auth.createRootNode': 'Créer un réseau',
  'auth.orgNickname': 'Surnom',
  'auth.alias': 'Alias opérationnel',
  'auth.inviteCode': "Code d'invitation",
  'auth.networkName': 'Nom du réseau',
  'auth.showNameToEveryone': 'Afficher le nom à tous',
  'auth.showNameHint': "Si activé, tous les membres voient ce nom dans leur en-tête. Sinon, seuls vous et les détenteurs de la Vraie Vue le voient. Modifiable à tout moment dans les paramètres.",
  'auth.createTree': "Créer l'arbre réseau",
  'auth.initializeNode': 'Rejoindre un arbre existant',
  'auth.switchToCreate': "Créer l'arbre réseau",
  'auth.switchToJoin': 'Rejoindre un arbre existant',
  'auth.back': 'Retour',
  'auth.language': 'Langue',
  'auth.languageHint': 'Détectée automatiquement depuis votre appareil. Modifiable à tout moment dans les paramètres.',
  'nav.ancestors': 'Ascendants', 'nav.descendants': 'Descendants', 'nav.chats': 'Discussions',
  'nav.myInvitees': 'Mes invités', 'nav.broadcast': 'Annonces', 'nav.networkTree': 'Arbre du réseau',
  'nav.monitor': 'Centre de suivi', 'nav.howto': 'Mode d\u2019emploi', 'nav.settings': 'Paramètres',
  'nav.menu': 'Menu', 'nav.protocols': 'Protocoles',
  'composer.placeholder': 'Écrire un message…', 'composer.send': 'Envoyer', 'composer.reply': 'Répondre',
  'composer.replyingTo': 'En réponse à {name}',
  'msg.acknowledge': 'Accuser réception', 'msg.acknowledged': 'Reçu',
  'msg.announcementFromLevel': 'Annonce du niveau {level}', 'msg.you': 'Vous',
  'msg.today': "Aujourd'hui", 'msg.yesterday': 'Hier',
  'call.outgoing': 'Appel sortant', 'call.incoming': 'Appel entrant', 'call.missed': 'Appel manqué',
  'call.declined': 'Appel refusé', 'call.noAnswer': 'Pas de réponse',
  'settings.showNameToEveryone': 'Afficher le nom à tous',
  'settings.showNameToEveryoneDesc': "Si activé, tous les membres voient ce nom dans leur en-tête. Sinon, seuls vous et les détenteurs de la Vraie Vue. C'est indépendant de la Vraie Vue, qui contrôle seulement qui voit tout l'arbre du réseau.",
  'common.cancel': 'Annuler', 'common.confirm': 'Confirmer', 'common.copy': 'Copier',
  'common.copied': 'Copié', 'common.search': 'Rechercher', 'common.back': 'Retour',
  'common.noSignal': 'Aucun signal détecté', 'common.noMatchesShort': 'Aucun résultat',
  'side.directLinks': 'Liens directs', 'side.isolatedNode': 'Nœud isolé',
  'side.joinRequests': "Demandes d'adhésion", 'side.contactRequests': 'Demandes de contact',
  'side.networkPlan': 'Forfait réseau', 'side.device': 'Appareil',
  'side.personalChats': 'Discussions personnelles', 'side.encrypted': 'CHIFFRÉ', 'side.gridNetwork': 'Réseau',
  'hub.searchAll': 'Rechercher dans toutes les discussions…',
  'hub.noChatsTitle': 'Aucune discussion', 'hub.results': 'Résultats dans toutes les discussions',
  'hub.noMatches': 'Aucune correspondance.', 'hub.sayHi': 'Aucun message — dites bonjour',
  'hub.waiting': "Demande envoyée — en attente d'acceptation", 'hub.chats': 'Discussions', 'hub.chat': 'Discussion',
  'sel.selected': 'sélectionné(s)', 'sel.deleteForMe': 'Supprimer pour moi', 'sel.deleteForAll': 'Supprimer pour tous', 'sel.edit': 'Modifier',
  'msg.unread': 'Non lus', 'msg.edited': 'modifié', 'msg.disappears': 'Éphémère',
  'msg.translate': 'Traduire', 'msg.translating': 'Traduction…', 'msg.showOriginal': "Voir l'original",
  'msg.showTranslation': 'Voir la traduction', 'msg.awaitingAck': 'En attente de confirmation',
  'msg.ackedBy': 'Confirmé par {names}',
  'comp.message': 'Message…', 'comp.recording': 'Enregistrement…', 'comp.reqAck': 'Demander une confirmation',
  'comp.editing': 'Modification du message', 'comp.scheduleTitle': 'Programmer le message',
  'comp.schedule': 'Programmer', 'comp.sealing': 'Chiffrement…', 'comp.scheduled': 'Programmé',
  'bc.reach': "Portée de l'annonce", 'bc.everyoneBelow': 'Tous en dessous de moi', 'bc.clear': 'Effacer',
  'bc.ackDashboard': 'Tableau des confirmations', 'bc.acknowledgments': 'Confirmations', 'bc.sent': 'envoyées',
  'bc.receiveOnly': "Réception seule — la racine du réseau peut vous accorder le droit d'annoncer depuis l'Arbre du réseau.",
  'mon.selectTarget': 'Choisir la cible à suivre', 'mon.activeTrace': 'Suivi actif',
  'mon.noSubnodes': 'Aucun sous-nœud à suivre',
  'settings.privacy': 'Confidentialité', 'settings.autoTranslate': 'Traduire automatiquement',
  'settings.autoTranslateDesc': "Traduit automatiquement les messages entrants dans votre langue, sur cet appareil. Utilise le traducteur intégré du navigateur — rien n'est envoyé à un serveur.",
  'settings.member': 'Membre', 'settings.networkRoot': 'Racine du réseau',
};

const de: Dict = {
  'settings.title': 'Einstellungen', 'settings.language': 'Sprache',
  'settings.languageDesc': 'Ändert die Sprache der gesamten App auf diesem Gerät.',
  'settings.readReceipts': 'Lesebestätigungen',
  'settings.readReceiptsDesc': 'Andere sehen, wann du ihre Nachrichten gelesen hast. Gegenseitig — du erhältst nur Bestätigungen, wenn du selbst welche sendest.',
  'settings.notifications': 'Benachrichtigungen', 'settings.notificationsBlocked': 'In den Browser-/Systemeinstellungen blockiert.',
  'settings.notificationsDesc': 'Push-Hinweise für neue Nachrichten und Anrufe auf diesem Gerät.',
  'settings.oneOnOneSettings': '1:1-Einstellungen', 'settings.network': 'Netzwerk',
  'settings.oneOnOneName': '1:1-Name', 'settings.networkName': 'Netzwerkname',
  'settings.save': 'Speichern', 'settings.saved': 'Gespeichert',
  'settings.showNameEveryone': 'Namen allen zeigen',
  'settings.showNameEveryoneDesc': 'Wenn aktiv, sieht jedes Mitglied diesen Namen in seiner Kopfzeile. Wenn aus, sehen ihn nur du und Inhaber der Wahren Sicht. Das ist getrennt von der Wahren Sicht, die nur steuert, wer den gesamten Netzwerkbaum sieht.',
  'settings.accountRecovery': 'Kontowiederherstellung',
  'settings.recoveryWarn': 'Schreibe diese 12 Wörter auf und bewahre sie physisch auf. Das ist der EINZIGE sichere Weg, auf dein Konto zuzugreifen, falls du deine Zugangsdaten vergisst. Passwörter können nicht zurückgesetzt werden. Wer diese Phrase hat, kann deinen Zugang wiederherstellen — halte sie geheim.',
  'settings.copyPhrase': 'Phrase kopieren', 'settings.savedItDone': 'Gespeichert — Fertig',
  'settings.checkingRecovery': 'Wiederherstellungsstatus wird geprüft…', 'settings.recoverySet': 'Wiederherstellungsphrase ist eingerichtet',
  'settings.confirmPwToGenerate': 'Bestätige das Passwort für {user}, um eine Wiederherstellungsphrase zu erzeugen. Sie wird auf diesem Gerät erstellt — der Server speichert sie nur verschlüsselt.',
  'settings.currentPassword': 'Aktuelles Passwort', 'settings.verifying': 'Wird überprüft…', 'settings.generatePhrase': 'Phrase erzeugen',
  'settings.noRecoveryOnFile': 'Keine Wiederherstellungsphrase hinterlegt. Ohne sie bedeutet ein vergessenes Passwort dauerhaften Zugriffsverlust — Passwörter können nicht zurückgesetzt werden.',
  'settings.generateRecovery': 'Wiederherstellungsphrase erzeugen', 'settings.dangerZone': 'Gefahrenzone',
  'settings.panicConfirm': 'Die Notlöschung entfernt alle lokalen Daten auf DIESEM Gerät und meldet dich ab. Dein Konto und deine Nachrichten auf dem Server bleiben unberührt. Fortfahren?',
  'settings.panicWipe': 'Notlöschung (dieses Gerät)',
  'settings.deleteNetworkConfirm': 'Dieses gesamte Netzwerk ({count}) dauerhaft LÖSCHEN? Jede Nachricht, Einladung und jeder Mitgliedsknoten wird für alle entfernt. Das kann nicht rückgängig gemacht werden.',
  'settings.deleteNetworkConfirm2': 'Bist du ganz sicher? Das ist unwiderruflich.', 'settings.deleteNetwork': 'Gesamtes Netzwerk löschen',
  'settings.member_one': '{count} Mitglied', 'settings.member_other': '{count} Mitglieder',
  'settings.devNotice': 'Arbor ist noch in Entwicklung. Bitte sende Fehlerberichte an bugreports@arborsecure.app',
  'media.videoUnsupported': 'Dieses Gerät kann dieses Videoformat nicht dekodieren', 'media.downloadInstead': 'Herunterladen', 'media.audioBlocked': 'Audio blockiert',
  'plan.upgradePrompt': 'Wechsle zu Arbor Premium, um weiter zu wachsen.', 'plan.upgradeNow': 'Jetzt upgraden', 'plan.dismiss': 'Verwerfen',
  'plan.upgrade': 'Upgrade', 'plan.premium': 'Arbor Premium', 'plan.send': 'Senden', 'plan.copyAddress': 'Adresse kopieren',
  'plan.copyLink': 'Link kopieren', 'plan.close': 'Schließen', 'plan.retry': 'Erneut versuchen', 'plan.scanToJoin': 'Scannen zum Installieren & Beitreten', 'plan.networkArchived': 'Netzwerk archiviert',
  'status.isolatedNode': 'Isolierter Knoten', 'status.panicWipe': 'Notlöschung', 'status.protocolActive': 'Protokoll aktiv',
  'status.noOneBelow': 'Noch niemand unter dir.', 'status.noNodes': 'Keine Knoten anzuzeigen.', 'status.connecting': 'Verbinde…',
  'status.noAckAnnouncements': 'Noch keine bestätigungspflichtigen Ankündigungen.', 'status.awaitingAckEllipsis': 'Warte auf Bestätigung…',
  'call.video': 'Video', 'call.voice': 'Sprache',
  'onboard.welcome': 'Willkommen bei Arbor', 'onboard.readGuide': 'Anleitung lesen', 'onboard.skip': 'Überspringen',
  'howto.title': 'So verwendest du Arbor',

  'auth.tagline': 'Verschlüsselte Netzwerke, die wie Bäume wachsen.',
  'auth.joinByInvite': 'Per Einladung beitreten',
  'auth.createRootNode': 'Netzwerk erstellen',
  'auth.orgNickname': 'Spitzname',
  'auth.alias': 'Operativer Alias',
  'auth.inviteCode': 'Einladungscode',
  'auth.networkName': 'Netzwerkname',
  'auth.showNameToEveryone': 'Namen für alle anzeigen',
  'auth.showNameHint': 'Wenn aktiviert, sehen alle Mitglieder diesen Namen in ihrer Kopfzeile. Sonst nur du und Inhaber der Wahren Sicht. Jederzeit in den Einstellungen änderbar.',
  'auth.createTree': 'Netzwerkbaum erstellen',
  'auth.initializeNode': 'Bestehendem Baum beitreten',
  'auth.switchToCreate': 'Netzwerkbaum erstellen',
  'auth.switchToJoin': 'Bestehendem Baum beitreten',
  'auth.back': 'Zurück',
  'auth.language': 'Sprache',
  'auth.languageHint': 'Automatisch von deinem Gerät erkannt. Jederzeit in den Einstellungen änderbar.',
  'nav.ancestors': 'Vorfahren', 'nav.descendants': 'Nachkommen', 'nav.chats': 'Chats',
  'nav.myInvitees': 'Meine Eingeladenen', 'nav.broadcast': 'Ankündigungen', 'nav.networkTree': 'Netzwerkbaum',
  'nav.monitor': 'Überwachung', 'nav.howto': 'Anleitung', 'nav.settings': 'Einstellungen',
  'nav.menu': 'Menü', 'nav.protocols': 'Protokolle',
  'composer.placeholder': 'Nachricht schreiben…', 'composer.send': 'Senden', 'composer.reply': 'Antworten',
  'composer.replyingTo': 'Antwort an {name}',
  'msg.acknowledge': 'Bestätigen', 'msg.acknowledged': 'Bestätigt',
  'msg.announcementFromLevel': 'Ankündigung von Ebene {level}', 'msg.you': 'Du',
  'msg.today': 'Heute', 'msg.yesterday': 'Gestern',
  'call.outgoing': 'Ausgehender Anruf', 'call.incoming': 'Eingehender Anruf', 'call.missed': 'Verpasster Anruf',
  'call.declined': 'Anruf abgelehnt', 'call.noAnswer': 'Keine Antwort',
  'settings.showNameToEveryone': 'Namen für alle anzeigen',
  'settings.showNameToEveryoneDesc': 'Wenn aktiviert, sehen alle Mitglieder diesen Namen. Sonst nur du und Inhaber der Wahren Sicht. Unabhängig von der Wahren Sicht, die nur steuert, wer den ganzen Netzwerkbaum sieht.',
  'common.cancel': 'Abbrechen', 'common.confirm': 'Bestätigen', 'common.copy': 'Kopieren',
  'common.copied': 'Kopiert', 'common.search': 'Suchen', 'common.back': 'Zurück',
  'common.noSignal': 'Kein Signal erkannt', 'common.noMatchesShort': 'Keine Treffer',
  'side.directLinks': 'Direkte Kontakte', 'side.isolatedNode': 'Isolierter Knoten',
  'side.joinRequests': 'Beitrittsanfragen', 'side.contactRequests': 'Kontaktanfragen',
  'side.networkPlan': 'Netzwerk-Tarif', 'side.device': 'Gerät',
  'side.personalChats': 'Persönliche Chats', 'side.encrypted': 'VERSCHLÜSSELT', 'side.gridNetwork': 'Netzwerk',
  'hub.searchAll': 'Alle Chats durchsuchen…',
  'hub.noChatsTitle': 'Noch keine Chats', 'hub.results': 'Ergebnisse in allen Chats',
  'hub.noMatches': 'Keine Treffer in irgendeinem Chat.', 'hub.sayHi': 'Keine Nachrichten — sag Hallo',
  'hub.waiting': 'Anfrage gesendet — wartet auf Annahme', 'hub.chats': 'Chats', 'hub.chat': 'Chat',
  'sel.selected': 'ausgewählt', 'sel.deleteForMe': 'Für mich löschen', 'sel.deleteForAll': 'Für alle löschen', 'sel.edit': 'Bearbeiten',
  'msg.unread': 'Ungelesen', 'msg.edited': 'bearbeitet', 'msg.disappears': 'Verschwindet',
  'msg.translate': 'Übersetzen', 'msg.translating': 'Übersetze…', 'msg.showOriginal': 'Original anzeigen',
  'msg.showTranslation': 'Übersetzung anzeigen', 'msg.awaitingAck': 'Wartet auf Bestätigung',
  'msg.ackedBy': 'Bestätigt von {names}',
  'comp.message': 'Nachricht…', 'comp.recording': 'Aufnahme…', 'comp.reqAck': 'Bestätigung anfordern',
  'comp.editing': 'Nachricht bearbeiten', 'comp.scheduleTitle': 'Nachricht planen',
  'comp.schedule': 'Planen', 'comp.sealing': 'Verschlüssele…', 'comp.scheduled': 'Geplant',
  'bc.reach': 'Reichweite der Ankündigung', 'bc.everyoneBelow': 'Alle unter mir', 'bc.clear': 'Leeren',
  'bc.ackDashboard': 'Bestätigungs-Übersicht', 'bc.acknowledgments': 'Bestätigungen', 'bc.sent': 'gesendet',
  'bc.receiveOnly': 'Nur Empfang — die Netzwerk-Wurzel kann dir im Netzwerkbaum Ankündigungsrechte geben.',
  'mon.selectTarget': 'Überwachungsziel wählen', 'mon.activeTrace': 'Aktive Überwachung',
  'mon.noSubnodes': 'Keine Unterknoten zum Überwachen',
  'settings.privacy': 'Datenschutz', 'settings.autoTranslate': 'Nachrichten automatisch übersetzen',
  'settings.autoTranslateDesc': 'Übersetzt eingehende Nachrichten automatisch in deine Sprache, auf diesem Gerät. Nutzt den eingebauten Browser-Übersetzer — nichts wird an einen Server gesendet.',
  'settings.member': 'Mitglied', 'settings.networkRoot': 'Netzwerk-Wurzel',
};

const pt: Dict = {
  'settings.title': 'Configurações', 'settings.language': 'Idioma',
  'settings.languageDesc': 'Altera o idioma de todo o app neste dispositivo.',
  'settings.readReceipts': 'Confirmações de leitura',
  'settings.readReceiptsDesc': 'Permite que outros vejam quando você leu as mensagens deles. É recíproco — você só recebe confirmações se também enviar as suas.',
  'settings.notifications': 'Notificações', 'settings.notificationsBlocked': 'Bloqueadas nas configurações do navegador ou do sistema.',
  'settings.notificationsDesc': 'Alertas push de novas mensagens e chamadas neste dispositivo.',
  'settings.oneOnOneSettings': 'Configurações 1:1', 'settings.network': 'Rede',
  'settings.oneOnOneName': 'Nome 1:1', 'settings.networkName': 'Nome da rede',
  'settings.save': 'Salvar', 'settings.saved': 'Salvo',
  'settings.showNameEveryone': 'Mostrar o nome a todos',
  'settings.showNameEveryoneDesc': 'Quando ativado, cada membro vê este nome no cabeçalho. Quando desativado, só você e quem tem Visão Verdadeira o veem. É separado da Visão Verdadeira, que controla apenas quem vê toda a árvore da rede.',
  'settings.accountRecovery': 'Recuperação de conta',
  'settings.recoveryWarn': 'Anote estas 12 palavras e guarde-as fisicamente. Esta é a ÚNICA forma segura de acessar sua conta se você esquecer suas credenciais. As senhas não podem ser redefinidas. Qualquer pessoa com esta frase pode recuperar seu acesso — mantenha-a em segredo.',
  'settings.copyPhrase': 'Copiar frase', 'settings.savedItDone': 'Já guardei — Concluído',
  'settings.checkingRecovery': 'Verificando status de recuperação…', 'settings.recoverySet': 'A frase de recuperação está configurada',
  'settings.confirmPwToGenerate': 'Confirme a senha de {user} para gerar uma frase de recuperação. A frase é criada neste dispositivo — o servidor só a armazena criptografada.',
  'settings.currentPassword': 'Senha atual', 'settings.verifying': 'Verificando…', 'settings.generatePhrase': 'Gerar frase',
  'settings.noRecoveryOnFile': 'Nenhuma frase de recuperação registrada. Sem ela, esquecer a senha significa perda permanente de acesso — as senhas não podem ser redefinidas.',
  'settings.generateRecovery': 'Gerar frase de recuperação', 'settings.dangerZone': 'Zona de perigo',
  'settings.panicConfirm': 'A Limpeza de Emergência apaga todos os dados locais NESTE dispositivo e encerra sua sessão. Sua conta e mensagens no servidor não são afetadas. Continuar?',
  'settings.panicWipe': 'Limpeza de emergência (este dispositivo)',
  'settings.deleteNetworkConfirm': 'EXCLUIR permanentemente toda esta rede ({count})? Cada mensagem, convite e nó de membro é removido para todos. Isto não pode ser desfeito.',
  'settings.deleteNetworkConfirm2': 'Você tem certeza absoluta? Isto é irreversível.', 'settings.deleteNetwork': 'Excluir toda a rede',
  'settings.member_one': '{count} membro', 'settings.member_other': '{count} membros',
  'settings.devNotice': 'O Arbor ainda está em desenvolvimento. Envie relatórios de erros para bugreports@arborsecure.app',
  'media.videoUnsupported': 'Este dispositivo não consegue decodificar este formato de vídeo', 'media.downloadInstead': 'Baixar', 'media.audioBlocked': 'Áudio bloqueado',
  'plan.upgradePrompt': 'Faça upgrade para o Arbor Premium para continuar crescendo.', 'plan.upgradeNow': 'Fazer upgrade', 'plan.dismiss': 'Dispensar',
  'plan.upgrade': 'Upgrade', 'plan.premium': 'Arbor Premium', 'plan.send': 'Enviar', 'plan.copyAddress': 'Copiar endereço',
  'plan.copyLink': 'Copiar link', 'plan.close': 'Fechar', 'plan.retry': 'Tentar novamente', 'plan.scanToJoin': 'Escaneie para instalar e entrar', 'plan.networkArchived': 'Rede arquivada',
  'status.isolatedNode': 'Nó isolado', 'status.panicWipe': 'Limpeza de emergência', 'status.protocolActive': 'Protocolo ativo',
  'status.noOneBelow': 'Ainda não há ninguém abaixo de você.', 'status.noNodes': 'Nenhum nó para exibir.', 'status.connecting': 'Conectando…',
  'status.noAckAnnouncements': 'Ainda não há anúncios que exijam confirmação.', 'status.awaitingAckEllipsis': 'Aguardando confirmação…',
  'call.video': 'Vídeo', 'call.voice': 'Voz',
  'onboard.welcome': 'Bem-vindo ao Arbor', 'onboard.readGuide': 'Ler o guia', 'onboard.skip': 'Pular',
  'howto.title': 'Como usar o Arbor',

  'auth.joinByInvite': 'Entrar por convite', 'auth.createRootNode': 'Criar rede',
  'auth.orgNickname': 'Apelido', 'auth.alias': 'Alias operacional',
  'auth.inviteCode': 'Código de convite', 'auth.networkName': 'Nome da rede',
  'auth.showNameToEveryone': 'Mostrar o nome a todos', 'auth.createTree': 'Criar árvore de rede',
  'auth.initializeNode': 'Entrar numa árvore existente',
  'auth.switchToCreate': 'Criar árvore de rede',
  'auth.switchToJoin': 'Entrar numa árvore existente', 'auth.back': 'Voltar', 'auth.language': 'Idioma',
  'auth.languageHint': 'Detectado automaticamente do seu dispositivo. Pode mudar nas configurações.',
  'nav.ancestors': 'Ascendentes', 'nav.descendants': 'Descendentes', 'nav.chats': 'Conversas',
  'nav.myInvitees': 'Meus convidados', 'nav.broadcast': 'Anúncios', 'nav.networkTree': 'Árvore da rede',
  'nav.monitor': 'Central de monitoramento', 'nav.howto': 'Como usar', 'nav.settings': 'Configurações',
  'nav.menu': 'Menu', 'nav.protocols': 'Protocolos',
  'composer.placeholder': 'Escreva uma mensagem…', 'composer.send': 'Enviar', 'composer.reply': 'Responder',
  'composer.replyingTo': 'Respondendo a {name}',
  'msg.acknowledge': 'Confirmar', 'msg.acknowledged': 'Confirmado',
  'msg.announcementFromLevel': 'Anúncio do nível {level}', 'msg.you': 'Você',
  'msg.today': 'Hoje', 'msg.yesterday': 'Ontem',
  'call.outgoing': 'Chamada realizada', 'call.incoming': 'Chamada recebida', 'call.missed': 'Chamada perdida',
  'call.declined': 'Chamada recusada', 'call.noAnswer': 'Sem resposta',
  'settings.showNameToEveryone': 'Mostrar o nome a todos',
  'common.cancel': 'Cancelar', 'common.confirm': 'Confirmar', 'common.copy': 'Copiar',
  'common.copied': 'Copiado', 'common.search': 'Buscar', 'common.back': 'Voltar',
  'common.noSignal': 'Nenhum sinal detectado', 'common.noMatchesShort': 'Sem resultados',
  'side.directLinks': 'Contatos diretos', 'side.isolatedNode': 'Nó isolado',
  'side.joinRequests': 'Pedidos de entrada', 'side.contactRequests': 'Pedidos de contato',
  'side.networkPlan': 'Plano da rede', 'side.device': 'Dispositivo',
  'side.personalChats': 'Conversas pessoais', 'side.encrypted': 'CRIPTOGRAFADO', 'side.gridNetwork': 'Rede',
  'hub.searchAll': 'Buscar em todas as conversas…',
  'hub.noChatsTitle': 'Nenhuma conversa ainda', 'hub.results': 'Resultados em todas as conversas',
  'hub.noMatches': 'Nenhuma correspondência.', 'hub.sayHi': 'Sem mensagens — diga oi',
  'hub.waiting': 'Pedido enviado — aguardando aceitação', 'hub.chats': 'Conversas', 'hub.chat': 'Conversa',
  'sel.selected': 'selecionadas', 'sel.deleteForMe': 'Apagar para mim', 'sel.deleteForAll': 'Apagar para todos', 'sel.edit': 'Editar',
  'msg.unread': 'Não lidas', 'msg.edited': 'editada', 'msg.disappears': 'Desaparece',
  'msg.translate': 'Traduzir', 'msg.translating': 'Traduzindo…', 'msg.showOriginal': 'Ver original',
  'msg.showTranslation': 'Ver tradução', 'msg.awaitingAck': 'Aguardando confirmação',
  'msg.ackedBy': 'Confirmado por {names}',
  'comp.message': 'Mensagem…', 'comp.recording': 'Gravando…', 'comp.reqAck': 'Pedir confirmação',
  'comp.editing': 'Editando mensagem', 'comp.scheduleTitle': 'Agendar mensagem',
  'comp.schedule': 'Agendar', 'comp.sealing': 'Criptografando…', 'comp.scheduled': 'Agendada',
  'bc.reach': 'Alcance do anúncio', 'bc.everyoneBelow': 'Todos abaixo de mim', 'bc.clear': 'Limpar',
  'bc.ackDashboard': 'Painel de confirmações', 'bc.acknowledgments': 'Confirmações', 'bc.sent': 'enviados',
  'bc.receiveOnly': 'Somente recepção — a raiz da rede pode conceder direitos de anúncio na Árvore da rede.',
  'mon.selectTarget': 'Escolher alvo de monitoramento', 'mon.activeTrace': 'Rastreamento ativo',
  'mon.noSubnodes': 'Nenhum subnó para monitorar',
  'settings.privacy': 'Privacidade', 'settings.autoTranslate': 'Traduzir mensagens automaticamente',
  'settings.autoTranslateDesc': 'Traduz automaticamente as mensagens recebidas para o seu idioma, neste dispositivo. Usa o tradutor integrado do navegador — nada é enviado a um servidor.',
  'settings.member': 'Membro', 'settings.networkRoot': 'Raiz da rede',
};

const DICTS: Partial<Record<LocaleCode, Dict>> = { en, es, fr, de, pt };

/** Translate a key for a locale, filling {placeholders}. Falls back to English,
 *  then to the key itself, so a missing string never renders blank. */
export function translate(locale: LocaleCode, key: string, vars?: Record<string, string | number>): string {
  const dict = DICTS[locale] || en;
  let str = dict[key] ?? en[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) str = str.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v));
  return str;
}

// ---------------------------------------------------------------------------
// On-device message translation using the browser's built-in Translator /
// LanguageDetector APIs (Chrome's on-device AI). Everything runs locally — no
// text is sent to any server. When the APIs are unavailable we report that so
// the UI can hide the control instead of failing.
// ---------------------------------------------------------------------------
export function translationSupported(): boolean {
  return typeof window !== 'undefined' && ('Translator' in window || 'translation' in (window as any));
}

/** Best-effort language detection of a text snippet; returns a base code or null. */
export async function detectTextLanguage(text: string): Promise<string | null> {
  try {
    const g: any = window as any;
    if ('LanguageDetector' in g) {
      const det = await g.LanguageDetector.create();
      const results = await det.detect(text);
      const top = results?.[0];
      return top && top.confidence > 0.5 ? top.detectedLanguage?.split('-')[0] : null;
    }
    if (g.translation?.canDetect) {
      const det = await g.translation.createDetector();
      const results = await det.detect(text);
      const top = results?.[0];
      return top ? top.detectedLanguage?.split('-')[0] : null;
    }
  } catch { /* ignore */ }
  return null;
}

/** Translate text into the target locale on-device. Returns null if impossible. */
export async function translateText(text: string, target: LocaleCode, sourceHint?: string): Promise<string | null> {
  try {
    const g: any = window as any;
    const source = sourceHint || (await detectTextLanguage(text)) || 'en';
    if (source === target) return text;
    const opts = { sourceLanguage: source, targetLanguage: target };
    if ('Translator' in g) {
      const avail = await g.Translator.availability(opts).catch(() => 'unavailable');
      if (avail === 'unavailable') return null;
      const tr = await g.Translator.create(opts);
      return await tr.translate(text);
    }
    if (g.translation?.createTranslator) {
      const tr = await g.translation.createTranslator(opts);
      return await tr.translate(text);
    }
  } catch { /* ignore */ }
  return null;
}
