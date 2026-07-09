/**
 * Gulf Coast Card Shows — "Interested" counter + TBD "Notify Me" API
 *
 * A tiny Cloudflare Worker that stores a shared, per-show interest count in a
 * Cloudflare KV namespace, plus email signups for TBD shows. Endpoints:
 *
 *   GET  /counts            -> { "evt-001": 3, "evt-002": 12, ... }
 *   POST /interest          -> body: { "id": "evt-001", "action": "add" | "remove" }
 *                               returns: { "id": "evt-001", "count": 4 }
 *   POST /notify            -> body: { "id": "evt-001", "email": "someone@example.com" }
 *                               returns: { "ok": true, "count": 2 }
 *   GET  /notify-list?token=ADMIN_TOKEN
 *                            -> { "evt-001": ["a@example.com", "b@example.com"], ... }
 *
 * See WORKER-SETUP.md for how to deploy this.
 * /notify-list requires an ADMIN_TOKEN secret — see the note above that route.
 */

// Change this if your site is ever served from a different domain.
const ALLOWED_ORIGIN = 'https://gccardshows.com';

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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    // GET /counts — return every show's current count in one call, so the
    // site only needs a single request on page load instead of one per card.
    if (request.method === 'GET' && url.pathname === '/counts') {
      const counts = {};
      let cursor;
      do {
        const list = await env.INTEREST_KV.list({ cursor });
        await Promise.all(list.keys.map(async (k) => {
          // Skip notify: keys — they live in the same namespace but hold
          // email arrays, not counts.
          if (k.name.startsWith('notify:')) return;
          const v = await env.INTEREST_KV.get(k.name);
          counts[k.name] = parseInt(v || '0', 10);
        }));
        cursor = list.cursor;
      } while (cursor);
      return json(counts);
    }

    // POST /interest — increment or decrement a single show's count.
    if (request.method === 'POST' && url.pathname === '/interest') {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return json({ error: 'Invalid JSON body' }, 400);
      }

      const id = String(body.id || '').slice(0, 64);
      const action = body.action === 'remove' ? 'remove' : 'add';

      // Show IDs in this site always look like "evt-001" or "evt-<timestamp>" —
      // reject anything that doesn't match to keep KV keys predictable and safe.
      if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
        return json({ error: 'Invalid id' }, 400);
      }

      const current = parseInt((await env.INTEREST_KV.get(id)) || '0', 10);
      const next = Math.max(0, current + (action === 'add' ? 1 : -1));
      await env.INTEREST_KV.put(id, String(next));

      return json({ id, count: next });
    }

    // POST /notify — add an email to the notify list for a TBD show.
    // Dedupes automatically; stored under "notify:<id>" so it can't collide
    // with the plain count keys /counts and /interest use.
    if (request.method === 'POST' && url.pathname === '/notify') {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return json({ error: 'Invalid JSON body' }, 400);
      }

      const id = String(body.id || '').slice(0, 64);
      if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
        return json({ error: 'Invalid id' }, 400);
      }

      const email = String(body.email || '').trim().toLowerCase().slice(0, 254);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json({ error: 'Invalid email' }, 400);
      }

      const key = `notify:${id}`;
      const existing = JSON.parse((await env.INTEREST_KV.get(key)) || '[]');
      if (!existing.includes(email)) existing.push(email);
      await env.INTEREST_KV.put(key, JSON.stringify(existing));

      return json({ ok: true, count: existing.length });
    }

    // GET /notify-list?token=... — admin-only. Returns every TBD show's
    // notify signups so admin.html can display/export them.
    //
    // Set the token once with:  wrangler secret put ADMIN_TOKEN
    if (request.method === 'GET' && url.pathname === '/notify-list') {
      const token = url.searchParams.get('token');
      if (!token || token !== env.ADMIN_TOKEN) {
        return json({ error: 'Unauthorized' }, 401);
      }

      const result = {};
      let cursor;
      do {
        const list = await env.INTEREST_KV.list({ prefix: 'notify:', cursor });
        await Promise.all(list.keys.map(async (k) => {
          const id = k.name.slice('notify:'.length);
          const v = await env.INTEREST_KV.get(k.name);
          result[id] = v ? JSON.parse(v) : [];
        }));
        cursor = list.cursor;
      } while (cursor);

      return json(result);
    }

    return json({ error: 'Not found' }, 404);
  },
};

