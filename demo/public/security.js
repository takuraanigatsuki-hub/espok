/**
 * ЕПСОК · клиентский контур защиты (демо)
 * Сессия: PBKDF2 → AES-256-GCM + HMAC-SHA-256
 * Хранилище: AES-256-GCM (второй слой после входа)
 */
(function (global) {
  'use strict';

  const SESSION_PREFIX = 'epsok:v2:';
  const SESSION_VERSION = 2;
  const KDF_SALT = 'epsok-gost-contour-demo-v2';
  const HMAC_INFO = 'epsok-session-hmac-v2';
  const ENC_INFO = 'epsok-session-aes-v2';
  const STORAGE_INFO = 'epsok-storage-aes-v2';
  const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
  const REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
  const MAX_LOGIN_ATTEMPTS = 5;
  const LOCKOUT_MS = 15 * 60 * 1000;
  const LOGIN_ATTEMPTS_KEY = 'epsok-login-attempts';
  const TOKEN_CACHE_KEY = 'epsok-session-token-cache';
  const TOKEN_CACHE_PERSIST_KEY = 'epsok-session-token-persistent';
  const DEMO_HTTP_PREFIX = 'epsok:demo:http:';

  const ALLOWED_USERS = Object.freeze({
    'ivanov.sp': 1,
    'sidorov.av': 1,
    'kozlov.va': 1,
    'takura.anigatsuki': 1
  });

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  let storageKey = null;
  let sessionToken = null;
  let demoHashPromise = null;

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function b64ToBuf(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function hasWebCrypto() {
    if (typeof globalThis.isSecureContext === 'boolean') return globalThis.isSecureContext;
    return !!(globalThis.crypto && globalThis.crypto.subtle);
  }

  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', enc.encode(text));
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function deriveKey(baseMaterial, info, usages) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(baseMaterial),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    const isHmac = usages.includes('sign') || usages.includes('verify');
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode(`${KDF_SALT}:${info}`), iterations: 120000, hash: 'SHA-256' },
      baseKey,
      isHmac ? { name: 'HMAC', hash: 'SHA-256', length: 256 } : { name: 'AES-GCM', length: 256 },
      false,
      usages
    );
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/\//g, '&#x2F;');
  }

  function escapeAttr(s) {
    return escapeHtml(s).replace(/`/g, '&#96;');
  }

  function sanitizePlainObject(obj, maxDepth = 4) {
    if (!obj || typeof obj !== 'object' || maxDepth <= 0) return null;
    if (Array.isArray(obj)) {
      return obj.slice(0, 500).map(item =>
        typeof item === 'string' ? item.slice(0, 4000)
          : typeof item === 'number' || typeof item === 'boolean' ? item
            : typeof item === 'object' ? sanitizePlainObject(item, maxDepth - 1) : null
      );
    }
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      if (Object.keys(out).length >= 200) break;
      const key = String(k).slice(0, 64);
      if (typeof v === 'string') out[key] = v.slice(0, 4000);
      else if (typeof v === 'number' || typeof v === 'boolean') out[key] = v;
      else if (v && typeof v === 'object') out[key] = sanitizePlainObject(v, maxDepth - 1);
    }
    return out;
  }

  function getLoginAttempts() {
    try {
      const raw = sessionStorage.getItem(LOGIN_ATTEMPTS_KEY);
      if (!raw) return { count: 0, until: 0 };
      const p = JSON.parse(raw);
      if (p.until && Date.now() > p.until) return { count: 0, until: 0 };
      return { count: p.count || 0, until: p.until || 0 };
    } catch {
      return { count: 0, until: 0 };
    }
  }

  function recordLoginFailure() {
    const st = getLoginAttempts();
    const count = st.count + 1;
    const until = count >= MAX_LOGIN_ATTEMPTS ? Date.now() + LOCKOUT_MS : 0;
    sessionStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify({ count, until }));
    return { count, until, locked: until > Date.now() };
  }

  function clearLoginFailures() {
    sessionStorage.removeItem(LOGIN_ATTEMPTS_KEY);
  }

  function loginLockMessage(until) {
    const min = Math.max(1, Math.ceil((until - Date.now()) / 60000));
    return `Превышено число попыток входа. Повторите через ${min} мин.`;
  }

  async function verifyPassword(password) {
    const st = getLoginAttempts();
    if (st.until && Date.now() < st.until) {
      return { ok: false, locked: true, message: loginLockMessage(st.until) };
    }
    if (!hasWebCrypto()) {
      const ok = String(password || '') === 'epsok2028';
      if (!ok) {
        const fail = recordLoginFailure();
        if (fail.locked) {
          return { ok: false, locked: true, message: loginLockMessage(fail.until) };
        }
        return { ok: false, locked: false, message: null };
      }
      clearLoginFailures();
      return { ok: true, locked: false, message: null };
    }
    if (!demoHashPromise) demoHashPromise = sha256Hex('epsok2028');
    const expected = await demoHashPromise;
    const hash = await sha256Hex(String(password || ''));
    if (hash !== expected) {
      const fail = recordLoginFailure();
      if (fail.locked) {
        return { ok: false, locked: true, message: loginLockMessage(fail.until) };
      }
      return { ok: false, locked: false, message: null };
    }
    clearLoginFailures();
    return { ok: true, locked: false, message: null };
  }

  function randomToken() {
    if (hasWebCrypto()) {
      const buf = new Uint8Array(32);
      crypto.getRandomValues(buf);
      return bufToB64(buf);
    }
    return `demo-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
  }

  function cacheSessionToken(username, token, remember) {
    try {
      let map = {};
      const raw = sessionStorage.getItem(TOKEN_CACHE_KEY);
      if (raw) map = JSON.parse(raw) || {};
      map[username] = token;
      sessionStorage.setItem(TOKEN_CACHE_KEY, JSON.stringify(map));
      if (remember) {
        let persist = {};
        const pr = localStorage.getItem(TOKEN_CACHE_PERSIST_KEY);
        if (pr) persist = JSON.parse(pr) || {};
        persist[username] = token;
        localStorage.setItem(TOKEN_CACHE_PERSIST_KEY, JSON.stringify(persist));
      }
    } catch { /* ignore */ }
  }

  function loadCachedToken(username) {
    try {
      const raw = sessionStorage.getItem(TOKEN_CACHE_KEY);
      if (raw) {
        const map = JSON.parse(raw);
        if (map[username]) return map[username];
      }
      const pr = localStorage.getItem(TOKEN_CACHE_PERSIST_KEY);
      if (pr) {
        const persist = JSON.parse(pr);
        if (persist[username]) return persist[username];
      }
    } catch { /* ignore */ }
    return null;
  }

  async function tryDecryptEnvelope(env, username, token) {
    if (!token) return null;
    try {
      const hmacKey = await deriveKey(`${username}:${token}`, HMAC_INFO, ['sign', 'verify']);
      const sigData = enc.encode(`${username}|${env.exp}|${env.iv}|${env.ct}`);
      const valid = await crypto.subtle.verify('HMAC', hmacKey, b64ToBuf(env.sig), sigData);
      if (!valid) return null;
      const aesKey = await deriveKey(`${username}:${token}`, ENC_INFO, ['encrypt', 'decrypt']);
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBuf(env.iv) },
        aesKey,
        b64ToBuf(env.ct)
      );
      const inner = JSON.parse(dec.decode(plain));
      if (inner.token !== token) return null;
      return inner;
    } catch {
      return null;
    }
  }

  function parseDemoHttpSession(raw) {
    if (!raw || !raw.startsWith(DEMO_HTTP_PREFIX)) return null;
    try {
      const box = JSON.parse(dec.decode(b64ToBuf(raw.slice(DEMO_HTTP_PREFIX.length))));
      if (box.v !== SESSION_VERSION || !box.u || !ALLOWED_USERS[box.u]) return null;
      if (!box.exp || Date.now() > box.exp) return null;
      const token = loadCachedToken(box.u);
      if (!token || token !== box.token) return null;
      return box;
    } catch {
      return null;
    }
  }

  async function sealSession(username, innerJson, remember) {
    const ttl = remember ? REMEMBER_TTL_MS : SESSION_TTL_MS;
    const exp = Date.now() + ttl;
    const safeInner = { ...innerJson };
    if (safeInner.personaId != null) {
      safeInner.personaId = sanitizePersonaId(safeInner.personaId) || undefined;
    }

    if (!hasWebCrypto()) {
      sessionToken = randomToken();
      cacheSessionToken(username, sessionToken, remember);
      const payload = { ...safeInner, token: sessionToken, exp, v: SESSION_VERSION };
      const box = {
        v: SESSION_VERSION,
        u: username,
        exp,
        remember: !!remember,
        token: sessionToken,
        payload
      };
      global.__epsokStorageReady = true;
      return DEMO_HTTP_PREFIX + bufToB64(enc.encode(JSON.stringify(box)));
    }

    sessionToken = randomToken();
    cacheSessionToken(username, sessionToken, remember);
    const payload = { ...safeInner, token: sessionToken, exp, v: SESSION_VERSION };
    const plain = enc.encode(JSON.stringify(payload));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveKey(`${username}:${sessionToken}`, ENC_INFO, ['encrypt', 'decrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plain);
    const ivB64 = bufToB64(iv);
    const ctB64 = bufToB64(ct);
    const hmacKey = await deriveKey(`${username}:${sessionToken}`, HMAC_INFO, ['sign', 'verify']);
    const sigData = enc.encode(`${username}|${exp}|${ivB64}|${ctB64}`);
    const sig = await crypto.subtle.sign('HMAC', hmacKey, sigData);
    const envelope = {
      v: SESSION_VERSION,
      u: username,
      exp,
      remember: !!remember,
      iv: ivB64,
      ct: ctB64,
      sig: bufToB64(sig)
    };
    await activateStorageKey(username, sessionToken);
    return SESSION_PREFIX + bufToB64(enc.encode(JSON.stringify(envelope)));
  }

  async function openSealedSession(raw) {
    if (!raw || typeof raw !== 'string') return null;
    if (raw.startsWith('{')) {
      purgeLegacySessions();
      return null;
    }
    if (raw.startsWith(DEMO_HTTP_PREFIX)) {
      const box = parseDemoHttpSession(raw);
      if (!box) return null;
      sessionToken = box.token;
      global.__epsokStorageReady = true;
      return {
        username: box.u,
        personaId: sanitizePersonaId(box.payload.personaId),
        personaExplicit: !!box.payload.personaExplicit,
        at: box.payload.at || Date.now(),
        exp: box.exp,
        remember: !!box.remember
      };
    }
    if (!raw.startsWith(SESSION_PREFIX)) return null;
    let env;
    try {
      env = JSON.parse(dec.decode(b64ToBuf(raw.slice(SESSION_PREFIX.length))));
    } catch {
      return null;
    }
    if (env.v !== SESSION_VERSION || !env.u || !ALLOWED_USERS[env.u]) return null;
    if (!env.exp || Date.now() > env.exp) return null;

    const token = loadCachedToken(env.u);
    if (!token) return null;
    const inner = await tryDecryptEnvelope(env, env.u, token);
    if (!inner) return null;

    sessionToken = token;
    await activateStorageKey(env.u, sessionToken);
    return {
      username: env.u,
      personaId: sanitizePersonaId(inner.personaId),
      personaExplicit: !!inner.personaExplicit,
      at: inner.at || Date.now(),
      exp: env.exp,
      remember: !!env.remember
    };
  }

  function purgeLegacySessions() {
    try {
      sessionStorage.removeItem('epsok-session');
      localStorage.removeItem('epsok-session-persistent');
    } catch { /* ignore */ }
  }

  async function activateStorageKey(username, token) {
    if (!hasWebCrypto()) {
      storageKey = null;
      global.__epsokStorageReady = true;
      return;
    }
    storageKey = await deriveKey(`${username}:${token}`, STORAGE_INFO, ['encrypt', 'decrypt']);
    global.__epsokStorageReady = true;
  }

  async function encryptStorage(plainText) {
    if (!storageKey) return plainText;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, storageKey, enc.encode(plainText));
    return `epsok:enc:${bufToB64(iv)}.${bufToB64(ct)}`;
  }

  async function decryptStorage(cipherText) {
    if (!cipherText || typeof cipherText !== 'string') return null;
    if (!cipherText.startsWith('epsok:enc:')) return cipherText;
    if (!storageKey) return null;
    try {
      const body = cipherText.slice('epsok:enc:'.length);
      const dot = body.indexOf('.');
      if (dot < 0) return null;
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBuf(body.slice(0, dot)) },
        storageKey,
        b64ToBuf(body.slice(dot + 1))
      );
      return dec.decode(plain);
    } catch {
      return null;
    }
  }

  async function secureGetItem(storage, key) {
    const raw = storage.getItem(key);
    if (!raw) return null;
    let jsonText = raw;
    if (raw.startsWith('epsok:enc:')) {
      const decText = await decryptStorage(raw);
      if (decText == null) return null;
      jsonText = decText;
    }
    try {
      return sanitizePlainObject(JSON.parse(jsonText));
    } catch {
      return null;
    }
  }

  async function secureSetItem(storage, key, value) {
    const json = JSON.stringify(sanitizePlainObject(value));
    storage.setItem(key, storageKey ? await encryptStorage(json) : json);
  }

  function bootstrapAuthShell(sessionKey, rememberKey) {
    document.documentElement.dataset.auth = 'booting';
    try {
      const raw = sessionStorage.getItem(sessionKey) || localStorage.getItem(rememberKey);
      if (!raw) {
        document.documentElement.dataset.auth = 'login';
        return;
      }
      if (raw.startsWith(DEMO_HTTP_PREFIX)) {
        const box = parseDemoHttpSession(raw);
        document.documentElement.dataset.auth = box ? 'app' : 'login';
        return;
      }
      if (!raw.startsWith(SESSION_PREFIX)) {
        document.documentElement.dataset.auth = 'login';
        return;
      }
      const env = JSON.parse(dec.decode(b64ToBuf(raw.slice(SESSION_PREFIX.length))));
      const valid = env.v === SESSION_VERSION
        && env.u
        && ALLOWED_USERS[env.u]
        && env.exp
        && Date.now() < env.exp
        && !!loadCachedToken(env.u);
      document.documentElement.dataset.auth = valid ? 'app' : 'login';
    } catch {
      document.documentElement.dataset.auth = 'login';
    }
  }

  function clearSecurityState() {
    storageKey = null;
    sessionToken = null;
    global.__epsokStorageReady = false;
    try {
      sessionStorage.removeItem(TOKEN_CACHE_KEY);
      localStorage.removeItem(TOKEN_CACHE_PERSIST_KEY);
    } catch { /* ignore */ }
  }

  const DEEP_LINK_TOKEN_RE = /^[\w.\-А-Яа-яЁё]+$/u;
  const PERSONA_ID_RE = /^[A-Z][A-Z0-9_]{1,48}$/;

  function sanitizePersonaId(val) {
    if (val == null) return null;
    const s = String(val).trim().slice(0, 64);
    return PERSONA_ID_RE.test(s) ? s : null;
  }

  function sanitizeDeepLinkValue(val, maxLen = 80) {
    if (val == null) return null;
    const s = String(val).trim().slice(0, maxLen);
    if (!s || !DEEP_LINK_TOKEN_RE.test(s)) return null;
    return s;
  }

  function sanitizeUserText(text, maxLen = 4000) {
    return String(text ?? '').slice(0, maxLen);
  }

  function sanitizeExternalUrl(url) {
    if (!url || typeof url !== 'string') return null;
    try {
      const u = new URL(url, global.location?.origin || 'https://localhost');
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      return u.href;
    } catch {
      return null;
    }
  }

  let runtimeGuardsReady = false;
  let privacyVeilActive = false;
  let onConfidentialCopy = null;

  function setPrivacyVeil(active) {
    privacyVeilActive = !!active;
    const root = global.document?.documentElement;
    const veil = global.document?.getElementById('privacy-veil');
    if (root) root.classList.toggle('privacy-veil-active', privacyVeilActive);
    if (veil) veil.hidden = !privacyVeilActive;
  }

  function bindConfidentialCopyAudit(handler) {
    onConfidentialCopy = typeof handler === 'function' ? handler : null;
  }

  function initRuntimeGuards(opts = {}) {
    if (runtimeGuardsReady || typeof document === 'undefined') return;
    runtimeGuardsReady = true;

    const origOpen = global.open;
    if (typeof origOpen === 'function') {
      global.open = function guardedOpen(url, ...args) {
        if (url != null && url !== '') {
          const safe = sanitizeExternalUrl(url);
          if (!safe) return null;
          return origOpen.call(global, safe, ...args);
        }
        return origOpen.apply(global, [url, ...args]);
      };
    }

    document.addEventListener('visibilitychange', () => {
      if (opts.privacyVeil === false) return;
      setPrivacyVeil(document.visibilityState === 'hidden');
    }, { passive: true });

    document.addEventListener('copy', (e) => {
      const node = e.target?.closest?.('[data-confidential]');
      if (!node || !onConfidentialCopy) return;
      const label = node.getAttribute('data-confidential') || 'контур';
      onConfidentialCopy(label);
    }, { passive: true });
  }

  function getSecurityProfile() {
    return {
      sessionVersion: SESSION_VERSION,
      secureContext: hasWebCrypto(),
      runtimeGuards: runtimeGuardsReady,
      privacyVeil: privacyVeilActive,
      loginLockout: getLoginAttempts().count
    };
  }

  global.EpsokSecurity = {
    SESSION_PREFIX,
    escapeHtml,
    escapeAttr,
    sanitizePlainObject,
    verifyPassword,
    sealSession,
    openSealedSession,
    secureGetItem,
    secureSetItem,
    bootstrapAuthShell,
    clearSecurityState,
    getLoginAttempts,
    loginLockMessage,
    purgeLegacySessions,
    hasWebCrypto,
    sanitizeDeepLinkValue,
    sanitizeUserText,
    sanitizeExternalUrl,
    initRuntimeGuards,
    bindConfidentialCopyAudit,
    getSecurityProfile,
    setPrivacyVeil
  };

  global.escapeHtml = escapeHtml;
})(typeof window !== 'undefined' ? window : globalThis);
