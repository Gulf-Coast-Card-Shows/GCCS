/**
 * Gulf Coast Card Shows — "Interested" counter + TBD "Notify Me" (Web Push) API
 *
 * A Cloudflare Worker that stores a shared, per-show interest count in a
 * Cloudflare KV namespace, plus Web Push subscriptions for TBD shows.
 * Zero npm dependencies — pastes directly into the Cloudflare dashboard's
 * Quick Edit, same as before. All push encryption uses the Web Crypto API.
 *
 *   GET  /counts                -> { "evt-001": 3, "evt-002": 12, ... }
 *   POST /interest                body: { "id": "evt-001", "action": "add" | "remove" }
 *                                 returns: { "id": "evt-001", "count": 4 }
 *
 *   POST /push-subscribe          body: { "id": "evt-001", "subscription": <PushSubscription.toJSON()> }
 *                                 returns: { "ok": true }
 *   POST /push-unsubscribe        body: { "id": "evt-001", "endpoint": "..." }
 *                                 returns: { "ok": true }
 *   GET  /push-list?token=...   -> { "evt-001": 3, "evt-002": 1, ... }  (admin only — counts, not raw subscriptions)
 *   POST /push-send?token=...     body: { "id": "evt-001", "title": "...", "body": "...", "url": "https://gccardshows.com/#evt-001" }
 *                                 sends a push to every subscriber for that show, drops dead
 *                                 subscriptions, then clears the list for that show.
 *                                 returns: { "sent": 4, "failed": 0 }
 *
 * See WORKER-SETUP.md for how to deploy this, and WORKER-PUSH-SETUP.md for
 * the one-time VAPID key setup this feature needs.
 */

// Change this if your site is ever served from a different domain.
const ALLOWED_ORIGIN = 'https://gccardshows.com';

// The VAPID keypair identifies this server to push services (Chrome/FCM,
// Firefox/Mozilla, Safari/APNs). The private key is a secret — set it with
// `wrangler secret put VAPID_PRIVATE_KEY_JWK` or via the dashboard's
// Settings -> Variables and Secrets. See WORKER-PUSH-SETUP.md.
const VAPID_PUBLIC_KEY = 'BGDljPiRIL6F4JiG0c8RzYERHbtMkNoG7xV8swgn_hUXIcK6VymeXs79oY1flz6kpIn14i7AEKyTbuwDiq6KPLw';
const VAPID_SUBJECT = 'mailto:zacbrannen@gmail.com';

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

// ============================================================
//  Base64url helpers
// ============================================================
function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bytesToB64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// ============================================================
//  VAPID — signs a JWT proving this server is authorized to push
//  to a given endpoint. See RFC 8292.
// ============================================================
async function buildVapidAuthHeader(endpoint, privateKeyJwk) {
  const aud = new URL(endpoint).origin;
  const exp = Math.floor(Date.now() / 1000) + 12 * 60 * 60; // 12h, must be < 24h

  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud, exp, sub: VAPID_SUBJECT };
  const encHeader = bytesToB64url(new TextEncoder().encode(JSON.stringify(header)));
  const encPayload = bytesToB64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${encHeader}.${encPayload}`;

  const privateKey = await crypto.subtle.importKey(
    'jwk', privateKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  // Web Crypto's ECDSA signature is already raw (r||s), which is exactly
  // what a JWT's ES256 signature needs — no DER conversion required.
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } }, privateKey, new TextEncoder().encode(signingInput)
  );
  const jwt = `${signingInput}.${bytesToB64url(sigBuf)}`;
  return `vapid t=${jwt}, k=${VAPID_PUBLIC_KEY}`;
}

// ============================================================
//  Web Push payload encryption — RFC 8291 (message encryption) +
//  RFC 8188 (aes128gcm content encoding).
// ============================================================
async function hmacSha256(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}
async function hkdfExpand(prk, info, len) {
  // Only ever asked for <=32 bytes here, so a single HMAC block is enough.
  const t1 = await hmacSha256(prk, concatBytes(info, new Uint8Array([1])));
  return t1.slice(0, len);
}

async function encryptPushPayload(plaintextBytes, subscription) {
  const uaPublicRaw = b64urlToBytes(subscription.keys.p256dh);
  const authSecret = b64urlToBytes(subscription.keys.auth);

  const uaPublicKey = await crypto.subtle.importKey('raw', uaPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const asKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', asKeyPair.publicKey));

  const ecdhSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: uaPublicKey }, asKeyPair.privateKey, 256)
  );

  const prkKey = await hmacSha256(authSecret, ecdhSecret);
  const keyInfo = concatBytes(
    new TextEncoder().encode('WebPush: info'), new Uint8Array([0]), uaPublicRaw, asPublicRaw
  );
  const ikm = await hkdfExpand(prkKey, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmacSha256(salt, ikm);

  const cekInfo = concatBytes(new TextEncoder().encode('Content-Encoding: aes128gcm'), new Uint8Array([0]));
  const cek = await hkdfExpand(prk, cekInfo, 16);
  const nonceInfo = concatBytes(new TextEncoder().encode('Content-Encoding: nonce'), new Uint8Array([0]));
  const nonce = await hkdfExpand(prk, nonceInfo, 12);

  // 0x02 delimiter marks this as the (only) last record — see RFC 8188 §2.
  const paddedPlaintext = concatBytes(plaintextBytes, new Uint8Array([2]));
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, cekKey, paddedPlaintext)
  );

  const recordSizeBytes = new Uint8Array(4);
  new DataView(recordSizeBytes.buffer).setUint32(0, ciphertext.length, false);
  const header = concatBytes(salt, recordSizeBytes, new Uint8Array([asPublicRaw.length]), asPublicRaw);
  return concatBytes(header, ciphertext);
}

async function sendWebPush(subscription, payloadObj, privateKeyJwk, ttlSeconds = 60 * 60 * 24 * 3) {
  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));
  const body = await encryptPushPayload(plaintext, subscription);
  const authHeader = await buildVapidAuthHeader(subscription.endpoint, privateKeyJwk);

  const res = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': String(ttlSeconds),
      'Authorization': authHeader,
    },
    body,
  });
  return res;
}

// ============================================================
//  Lightweight rate limiting for the two public, unauthenticated endpoints
//  (/interest and /push-subscribe). Uses the same KV namespace as everything
//  else — a fixed-window counter keyed by client IP + endpoint + the current
//  window number, so each window is a fresh key that ages out on its own via
//  expirationTtl rather than needing separate cleanup. This is a simple
//  abuse-deterrent (stop a script from hammering the endpoint), not a
//  precision rate limiter — KV reads/writes aren't strictly atomic, so a
//  determined attacker could squeeze a few extra requests through right at
//  the edge of a window. That's an acceptable tradeoff for a community
//  calendar site; it's not guarding anything sensitive.
// ============================================================
async function checkRateLimit(env, bucket, ip, limit, windowSeconds) {
  const windowId = Math.floor(Date.now() / 1000 / windowSeconds);
  const key = `rl:${bucket}:${ip || 'unknown'}:${windowId}`;
  const current = parseInt((await env.INTEREST_KV.get(key)) || '0', 10);
  if (current >= limit) return false;
  // TTL is double the window so a key that's read right at window's edge
  // doesn't vanish before the window it belongs to has actually elapsed.
  await env.INTEREST_KV.put(key, String(current + 1), { expirationTtl: windowSeconds * 2 });
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    // ---------- GET /counts ----------
    if (request.method === 'GET' && url.pathname === '/counts') {
      const counts = {};
      let cursor;
      do {
        const list = await env.INTEREST_KV.list({ cursor });
        await Promise.all(list.keys.map(async (k) => {
          if (k.name.startsWith('push:')) return; // skip subscription lists, not counts
          const v = await env.INTEREST_KV.get(k.name);
          counts[k.name] = parseInt(v || '0', 10);
        }));
        cursor = list.cursor;
      } while (cursor);
      return json(counts);
    }

    // ---------- POST /interest ----------
    if (request.method === 'POST' && url.pathname === '/interest') {
      // 30 toggles/min/IP — generous enough for someone genuinely clicking
      // through several shows, tight enough to stop a script from inflating
      // or deflating a count.
      if (!(await checkRateLimit(env, 'interest', clientIp, 30, 60))) {
        return json({ error: 'Too many requests — please slow down and try again in a minute.' }, 429);
      }

      let body;
      try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON body' }, 400); }

      const id = String(body.id || '').slice(0, 64);
      const action = body.action === 'remove' ? 'remove' : 'add';
      if (!/^[a-zA-Z0-9_-]+$/.test(id)) return json({ error: 'Invalid id' }, 400);

      const current = parseInt((await env.INTEREST_KV.get(id)) || '0', 10);
      const next = Math.max(0, current + (action === 'add' ? 1 : -1));
      await env.INTEREST_KV.put(id, String(next));
      return json({ id, count: next });
    }

    // ---------- POST /push-subscribe ----------
    if (request.method === 'POST' && url.pathname === '/push-subscribe') {
      // Subscribing is a rare, one-time action per show per visitor — 10/hour/IP
      // comfortably covers someone subscribing to several TBD shows in one visit.
      if (!(await checkRateLimit(env, 'push-subscribe', clientIp, 10, 3600))) {
        return json({ error: 'Too many requests — please try again later.' }, 429);
      }

      let body;
      try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON body' }, 400); }

      const id = String(body.id || '').slice(0, 64);
      if (!/^[a-zA-Z0-9_-]+$/.test(id)) return json({ error: 'Invalid id' }, 400);

      const sub = body.subscription;
      if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
        return json({ error: 'Invalid subscription' }, 400);
      }

      const key = `push:${id}`;
      const existing = JSON.parse((await env.INTEREST_KV.get(key)) || '[]');
      if (!existing.some((s) => s.endpoint === sub.endpoint)) {
        existing.push({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
      }
      await env.INTEREST_KV.put(key, JSON.stringify(existing));
      return json({ ok: true, count: existing.length });
    }

    // ---------- POST /push-unsubscribe ----------
    if (request.method === 'POST' && url.pathname === '/push-unsubscribe') {
      let body;
      try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON body' }, 400); }

      const id = String(body.id || '').slice(0, 64);
      const endpoint = String(body.endpoint || '');
      if (!/^[a-zA-Z0-9_-]+$/.test(id) || !endpoint) return json({ error: 'Invalid request' }, 400);

      const key = `push:${id}`;
      const existing = JSON.parse((await env.INTEREST_KV.get(key)) || '[]');
      const filtered = existing.filter((s) => s.endpoint !== endpoint);
      await env.INTEREST_KV.put(key, JSON.stringify(filtered));
      return json({ ok: true });
    }

    // ---------- GET /push-list?token=... (admin) ----------
    if (request.method === 'GET' && url.pathname === '/push-list') {
      const token = url.searchParams.get('token');
      if (!token || token !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, 401);

      const result = {};
      let cursor;
      do {
        const list = await env.INTEREST_KV.list({ prefix: 'push:', cursor });
        await Promise.all(list.keys.map(async (k) => {
          const id = k.name.slice('push:'.length);
          const v = await env.INTEREST_KV.get(k.name);
          const subs = v ? JSON.parse(v) : [];
          if (subs.length) result[id] = subs.length;
        }));
        cursor = list.cursor;
      } while (cursor);
      return json(result);
    }

    // ---------- POST /push-send?token=... (admin) ----------
    if (request.method === 'POST' && url.pathname === '/push-send') {
      const token = url.searchParams.get('token');
      if (!token || token !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, 401);

      if (!env.VAPID_PRIVATE_KEY_JWK) {
        return json({ error: 'VAPID_PRIVATE_KEY_JWK secret is not set on this Worker.' }, 500);
      }
      let privateKeyJwk;
      try { privateKeyJwk = JSON.parse(env.VAPID_PRIVATE_KEY_JWK); }
      catch (e) { return json({ error: 'VAPID_PRIVATE_KEY_JWK secret is not valid JSON.' }, 500); }

      let body;
      try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON body' }, 400); }

      const id = String(body.id || '').slice(0, 64);
      if (!/^[a-zA-Z0-9_-]+$/.test(id)) return json({ error: 'Invalid id' }, 400);
      const title = String(body.title || 'Gulf Coast Card Shows').slice(0, 120);
      const messageBody = String(body.body || '').slice(0, 200);
      const targetUrl = String(body.url || 'https://gccardshows.com/').slice(0, 300);

      const key = `push:${id}`;
      const subs = JSON.parse((await env.INTEREST_KV.get(key)) || '[]');
      if (!subs.length) return json({ sent: 0, failed: 0, note: 'No subscribers for this show.' });

      const payload = { title, body: messageBody, url: targetUrl };
      let sent = 0, failed = 0;
      const stillValid = [];

      await Promise.all(subs.map(async (sub) => {
        try {
          const res = await sendWebPush(sub, payload, privateKeyJwk);
          if (res.ok) {
            sent++;
          } else if (res.status === 404 || res.status === 410) {
            // Subscription expired or was revoked by the user — drop it silently.
            failed++;
          } else {
            failed++;
            stillValid.push(sub); // transient error — keep it, could retry next time
          }
        } catch (e) {
          failed++;
          stillValid.push(sub);
        }
      }));

      // Clear out everyone who successfully got the push (or is confirmed dead);
      // only keep subs that hit a transient error, in case Zac sends again.
      await env.INTEREST_KV.put(key, JSON.stringify(stillValid));

      return json({ sent, failed });
    }

    return json({ error: 'Not found' }, 404);
  },
};