import { Hono } from 'hono';
import { authMiddleware, requireAuth, requireAdmin, getAuth } from './middleware/auth';
import { loggingMiddleware } from './middleware/logging';

import { getSecurityHeaders, applySecurityHeaders } from '../shared/types/security';

const app = new Hono();

// Global security headers middleware
app.use('*', async (c, next) => {
  await next();
  const res = c.res as Response;
  return applySecurityHeaders(res);
});

/**
 * XAOSTECH API Hub
 * 
 * Centralized API server for all worker services.
 * Routes requests to specialized services via proxies.
 * 
 * Architecture:
 * - Auth layer: Validates via account.xaostech.io
 * - Logging layer: Records metrics locally
 * - Route layer: Processes or proxies requests
 * 
 * Separation:
 * - Admin API: /admin/* endpoints (require isAdmin flag)
 * - Public API: /public/* or root endpoints (require auth token)
 * - Internal: /health, /status (no auth)
 */

// === MIDDLEWARE STACK ===
// Apply to all routes
app.use('*', loggingMiddleware);
app.use('*', authMiddleware);

// === INTERNAL ROUTES (No Auth) ===
app.get('/', (c: any) => {
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>XAOSTECH API Hub</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .endpoint { background: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #007bff; border-radius: 4px; }
        .method { font-weight: bold; color: #007bff; }
        .path { font-family: monospace; color: #666; }
        .auth { color: #d9534f; font-size: 0.9em; }
        .public { color: #5cb85c; font-size: 0.9em; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>🚀 XAOSTECH API Hub</h1>
        <p>Centralised API server for all XAOSTECH worker services.</p>
        
        <h2>Health Checks</h2>
        <div class="endpoint">
          <div><span class="method">GET</span> <span class="path">/health</span></div>
          <div>Quick health check</div>
        </div>
        <div class="endpoint">
          <div><span class="method">GET</span> <span class="path">/status</span></div>
          <div>Detailed service status</div>
        </div>

        <h2>Chat Service</h2>
        <div class="endpoint">
          <div><span class="method">GET</span> <span class="path">/chat/messages</span> <span class="auth">Requires Auth</span></div>
          <div>Fetch user messages (paginated with limit/offset)</div>
        </div>
        <div class="endpoint">
          <div><span class="method">POST</span> <span class="path">/chat/messages</span> <span class="auth">Requires Auth</span></div>
          <div>Send a new message</div>
        </div>
        <div class="endpoint">
          <div><span class="method">POST</span> <span class="path">/chat/admin/moderation</span> <span class="auth">Requires Admin</span></div>
          <div>Moderate messages (delete, flag, etc.)</div>
        </div>

        <h2>Admin Routes</h2>
        <div class="endpoint">
          <div><span class="method">GET</span> <span class="path">/admin/users</span> <span class="auth">Requires Admin</span></div>
          <div>List all users</div>
        </div>
        <div class="endpoint">
          <div><span class="method">POST</span> <span class="path">/admin/users/:id/promote</span> <span class="auth">Requires Admin</span></div>
          <div>Promote user to admin</div>
        </div>
        <div class="endpoint">
          <div><span class="method">POST</span> <span class="path">/admin/users/:id/demote</span> <span class="auth">Requires Admin</span></div>
          <div>Remove admin privileges from user</div>
        </div>

        <h2>Authentication</h2>
        <p>Protected endpoints require either:</p>
        <ul>
          <li><strong>Bearer Token:</strong> <code>Authorization: Bearer &lt;token&gt;</code></li>
          <li><strong>Session Cookie:</strong> <code>Cookie: session_id=&lt;id&gt;</code></li>
        </ul>
        <p>All tokens are validated via <code>account.xaostech.io/verify</code></p>

        <h2>Logging</h2>
        <p>All requests are logged locally with metadata including:</p>
        <ul>
          <li>Method, path, status code, duration</li>
          <li>User ID (if authenticated)</li>
          <li>IP address and user agent</li>
          <li>Errors and stack traces</li>
        </ul>

        <h2>Service Architecture</h2>
        <p>This hub routes requests to specialized services:</p>
        <ul>
          <li><strong>account.xaostech.io</strong> - Authentication & user management</li>
          <li><strong>chat.xaostech.io</strong> - Chat messages & conversations</li>
          <li><strong>blog.xaostech.io</strong> - Blog posts & content</li>
          <li><strong>data.xaostech.io</strong> - Analytics & metrics</li>
          <li><strong>lingua.xaostech.io</strong> - Language & translation</li>
          <li><strong>payments.xaostech.io</strong> - Payment processing</li>
        </ul>
      </div>
    </body>
    </html>
  `;
  return c.html(html);
});

app.get('/health', (c: any) => c.json({ 
  service: 'api.xaostech.io',
  status: 'ok',
  timestamp: new Date().toISOString(),
}));

// === AUTH: GitHub OAuth endpoints ===
app.get('/auth/github/login', (c: any) => {
  const clientId = c.env.GITHUB_CLIENT_ID;
  if (!clientId) return c.json({ error: 'GITHUB_CLIENT_ID not configured' }, 501);

  const state = crypto.randomUUID();
  const redirectUri = new URL('/api/auth/github/callback', c.req.url).toString();

  // Set temporary state cookie for CSRF protection
  const stateCookie = `gh_oauth_state=${state}; Path=/; Max-Age=300; SameSite=Lax; Secure; HttpOnly`;

  const authUrl = new URL('https://github.com/login/oauth/authorize');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'read:user user:email');
  authUrl.searchParams.set('state', state);

  return new Response(null, { status: 302, headers: { Location: authUrl.toString(), 'Set-Cookie': stateCookie } });
});

app.get('/auth/github/callback', async (c: any) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const clientId = c.env.GITHUB_CLIENT_ID;
  const clientSecret = c.env.GITHUB_CLIENT_SECRET;

  if (!code || !state) return c.json({ error: 'code and state required' }, 400);
  if (!clientId || !clientSecret) return c.json({ error: 'GitHub OAuth secrets not configured' }, 501);

  // Verify state cookie
  const cookie = c.req.header('Cookie') || '';
  const cookieMatch = cookie.match(/gh_oauth_state=([^;]+)/);
  const cookieState = cookieMatch ? cookieMatch[1] : null;
  if (!cookieState || cookieState !== state) return c.json({ error: 'Invalid state (possible CSRF)' }, 400);

  try {
    // Exchange code for access token
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
    });
    const tokenJson = await tokenResp.json();
    const accessToken = tokenJson.access_token;
    if (!accessToken) return c.json({ error: 'Failed to obtain access token' }, 502);

    // Fetch GitHub profile
    const userResp = await fetch('https://api.github.com/user', { headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'xaostech' } });
    if (!userResp.ok) return c.json({ error: 'Failed to fetch GitHub user' }, 502);
    const ghUser = await userResp.json();

    // Fetch emails to get primary verified email
    const emailsResp = await fetch('https://api.github.com/user/emails', { headers: { Authorization: `token ${accessToken}`, 'User-Agent': 'xaostech' } });
    let primaryEmail = null;
    if (emailsResp.ok) {
      const emails = await emailsResp.json();
      const primary = (emails || []).find((e: any) => e.primary && e.verified);
      primaryEmail = primary ? primary.email : (emails && emails[0] && emails[0].email);
    }

    // Upsert user in DB (requires users table)
    const db = c.env.DB;
    if (!db) return c.json({ error: 'DB not configured on api.xaostech.io' }, 501);

    const existingRow = await db.prepare('SELECT id FROM users WHERE github_id = ?').bind(ghUser.id.toString()).first();
    const existing = existingRow as { id?: string } | undefined;
    let userId = existing?.id;
    if (userId) {
      await db.prepare('UPDATE users SET username = ?, email = ?, avatar_url = ?, last_login = datetime("now") WHERE id = ?')
        .bind(ghUser.login || '', primaryEmail || '', ghUser.avatar_url || '', userId).run();
    } else {
      userId = crypto.randomUUID();
      await db.prepare('INSERT INTO users (id, github_id, username, email, avatar_url, created_at, last_login) VALUES (?, ?, ?, ?, ?, datetime("now"), datetime("now"))')
        .bind(userId, ghUser.id.toString(), ghUser.login || '', primaryEmail || '', ghUser.avatar_url || '').run();
    }

    // Create session in SESSION KV
    const sessionKv = c.env.SESSION;
    if (!sessionKv) return c.json({ error: 'SESSION KV not configured' }, 501);

    const sessionId = crypto.randomUUID();
    await sessionKv.put(sessionId, JSON.stringify({ userId }), { expirationTtl: 60 * 60 * 24 * 7 });

    const sessionCookie = `session_id=${sessionId}; Path=/; Max-Age=${60 * 60 * 24 * 7}; HttpOnly; Secure; SameSite=Lax`;

    // Redirect to account page
    return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': sessionCookie } });
  } catch (err: any) {
    console.error('GitHub callback error', err);
    return c.json({ error: 'GitHub OAuth failed' }, 500);
  }
});

app.post('/auth/logout', requireAuth, async (c: any) => {
  try {
    const sessionKv = c.env.SESSION;
    const auth = getAuth(c);
    if (sessionKv && c.req.header('Cookie')) {
      const m = c.req.header('Cookie')!.match(/session_id=([^;]+)/);
      const sid = m ? m[1] : null;
      if (sid) await sessionKv.delete(sid);
    }
    // Expire cookie
    return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': 'session_id=deleted; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax' } });
  } catch (err: any) {
    console.error('Logout error', err);
    return c.json({ error: 'Logout failed' }, 500);
  }
});

app.get('/status', (c: any) => c.json({
  service: 'api.xaostech.io',
  version: '2.0.0',
  uptime: (globalThis as any).process?.uptime?.(),
  timestamp: new Date().toISOString(),
}));

// === ADMIN API (Protected - Admin Only) ===
app.get('/admin/users', requireAuth, requireAdmin, async (c: any) => {
  try {
    const db = c.env.DB;
    const { results } = await db.prepare('SELECT id, email, created_at, is_admin FROM users LIMIT 100').all();
    return c.json({ users: results });
  } catch (err) {
    return c.json({ error: 'Failed to fetch users' }, 500);
  }
});

app.post('/admin/users/:id/promote', requireAuth, requireAdmin, async (c: any) => {
  const userId = c.req.param('id');
  try {
    const db = c.env.DB;
    await db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').bind(userId).run();
    return c.json({ success: true, message: `User ${userId} promoted to admin` });
  } catch (err) {
    return c.json({ error: 'Failed to promote user' }, 500);
  }
});

app.post('/admin/users/:id/demote', requireAuth, requireAdmin, async (c: any) => {
  const userId = c.req.param('id');
  try {
    const db = c.env.DB;
    await db.prepare('UPDATE users SET is_admin = 0 WHERE id = ?').bind(userId).run();
    return c.json({ success: true, message: `User ${userId} removed from admin` });
  } catch (err) {
    return c.json({ error: 'Failed to demote user' }, 500);
  }
});

// === SERVICE ROUTES ===

// Chat service endpoints
app.get('/chat/health', (c: any) => c.json({ service: 'chat', status: 'ok' }));

app.get('/chat/messages', requireAuth, async (c: any) => {
  const auth = getAuth(c);
  const db = c.env.DB;

  try {
    const limit = parseInt(c.query('limit') || '50');
    const offset = parseInt(c.query('offset') || '0');

    const { results } = await db
      .prepare('SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?')
      .bind(auth.userId, limit, offset)
      .all();

    return c.json({
      messages: results,
      total: results.length,
      userId: auth.userId,
    });
  } catch (err) {
    return c.json({ error: 'Failed to fetch messages' }, 500);
  }
});

app.post('/chat/messages', requireAuth, async (c: any) => {
  const auth = getAuth(c);
  const db = c.env.DB;
  const { conversationId, content } = await c.req.json();

  if (!conversationId || !content) {
    return c.json({ error: 'conversationId and content required' }, 400);
  }

  try {
    const result = await db
      .prepare(
        'INSERT INTO messages (conversation_id, user_id, content, created_at) VALUES (?, ?, ?, datetime("now")) RETURNING id, created_at'
      )
      .bind(conversationId, auth.userId, content)
      .first();

    return c.json(result, 201);
  } catch (err) {
    return c.json({ error: 'Failed to send message' }, 500);
  }
});

app.post('/chat/admin/moderation', requireAuth, requireAdmin, async (c: any) => {
  const auth = getAuth(c);
  const { messageId, action, reason } = await c.req.json();

  if (!messageId || !action) {
    return c.json({ error: 'messageId and action required' }, 400);
  }

  console.log(`[MODERATION] Admin ${auth.userId} performed ${action} on message ${messageId}: ${reason}`);
});

// === New Chat AI + Rooms/DM endpoints ===
const CHAT_MODEL_ID = ((globalThis as any).process?.env?.CHAT_MODEL_ID) || '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
const CHAT_SYSTEM_PROMPT = 'You are the omnipotent void χάος. Be concise and neutral.';

// AI endpoint - mirrors previous chat worker behavior
app.post('/chat', async (c: any) => {
  try {
    const body = await c.req.json();
    const messages = (body && body.messages) || [];
    if (messages.length > 0 && messages[0].role !== 'system') {
      messages.unshift({ role: 'system', content: CHAT_SYSTEM_PROMPT });
    }

    if (!c.env.AI) {
      return c.json({ error: 'AI binding not configured on api.xaostech.io' }, 501);
    }

    const response = await c.env.AI.run(CHAT_MODEL_ID, { messages, max_tokens: 1024 }, { returnRawResponse: true });
    // Return the raw response from the AI binding
    return new Response(response.body, { status: response.status || 200, headers: response.headers });
  } catch (err) {
    console.error('AI /chat error', err);
    return c.json({ error: 'AI request failed' }, 500);
  }
});

// Rooms - use MESSAGES_KV if available
app.get('/chat/rooms', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const raw = await kv.get('rooms:index');
  const rooms = raw ? JSON.parse(raw) : [];
  return c.json(rooms);
});

app.get('/chat/rooms/random', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const raw = await kv.get('rooms:index');
  const rooms = raw ? JSON.parse(raw) : [];
  if (!Array.isArray(rooms) || rooms.length === 0) return c.json([]);
  const choice = rooms[Math.floor(Math.random() * rooms.length)];
  const messagesRaw = await kv.get(`room:${choice}:messages`);
  const messages = messagesRaw ? JSON.parse(messagesRaw) : [];
  return c.json(messages);
});

app.post('/chat/rooms/:id/post', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const roomId = c.req.param('id');
  const body = await c.req.json();
  const { userId, username, content } = body || {};
  if (!userId || !content) return c.json({ error: 'userId and content required' }, 400);

  const message = { messageId: crypto.randomUUID(), userId, username, content, timestamp: new Date().toISOString() };
  const key = `room:${roomId}:messages`;
  const existing = await kv.get(key);
  const messages = existing ? JSON.parse(existing) : [];
  messages.push(message);
  await kv.put(key, JSON.stringify(messages));
  return c.json({ success: true, messageId: message.messageId }, 201);
});

app.get('/chat/rooms/:id', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const roomId = c.req.param('id');
  const messagesRaw = await kv.get(`room:${roomId}:messages`);
  const messages = messagesRaw ? JSON.parse(messagesRaw) : [];
  return c.json(messages);
});

// Direct messages
app.post('/chat/dm/:recipientId/post', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const recipientId = c.req.param('recipientId');
  const body = await c.req.json();
  const { senderId, senderName, content } = body || {};
  if (!senderId || !content) return c.json({ error: 'senderId and content required' }, 400);

  const conversationId = [senderId, recipientId].sort().join(':');
  const key = `dm:${conversationId}`;
  const existing = await kv.get(key);
  const messages = existing ? JSON.parse(existing) : [];
  const message = { messageId: crypto.randomUUID(), senderId, senderName, content, timestamp: new Date().toISOString() };
  messages.push(message);
  await kv.put(key, JSON.stringify(messages));
  return c.json({ success: true, messageId: message.messageId }, 201);
});

app.get('/chat/dm/:recipientId', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const recipientId = c.req.param('recipientId');
  const senderId = c.req.query('senderId');
  if (!senderId) return c.json({ error: 'senderId query param required' }, 400);

  const conversationId = [senderId, recipientId].sort().join(':');
  const key = `dm:${conversationId}`;
  const messagesRaw = await kv.get(key);
  const messages = messagesRaw ? JSON.parse(messagesRaw) : [];
  return c.json(messages);
});

app.delete('/chat/admin/conversations/:id', requireAuth, requireAdmin, async (c: any) => {
  const auth = getAuth(c);
  const conversationId = c.req.param('id');

  try {
    await c.env.DB
      .prepare('DELETE FROM conversations WHERE id = ?')
      .bind(conversationId)
      .run();

    console.log(`[ADMIN] Admin ${auth.userId} deleted conversation ${conversationId}`);

    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: 'Failed to delete conversation' }, 500);
  }
});

// Blog proxy (example structure)
app.get('/blog/posts', requireAuth, async (c: any) => {
  try {
    const db = c.env.DB;
    const { results } = await db.prepare('SELECT * FROM blog_posts LIMIT 50').all();
    return c.json({ posts: results });
  } catch (err) {
    return c.json({ error: 'Failed to fetch blog posts' }, 500);
  }
});

app.post('/blog/posts', requireAuth, requireAdmin, async (c: any) => {
  const { title, content, tags } = await c.req.json();
  if (!title || !content) {
    return c.json({ error: 'title and content required' }, 400);
  }
  try {
    const db = c.env.DB;
    const result = await db
      .prepare('INSERT INTO blog_posts (title, content, tags, created_at) VALUES (?, ?, ?, datetime("now")) RETURNING id')
      .bind(title, content, JSON.stringify(tags || []))
      .first();
    return c.json(result, 201);
  } catch (err) {
    return c.json({ error: 'Failed to create post' }, 500);
  }
});

// Helper to get DATA access credentials (single source of truth)
function getDataAccessCredentials(c: any) {
  return {
    id: c.env?.DATA_ACCESS_CLIENT_ID,
    secret: c.env?.DATA_ACCESS_CLIENT_SECRET
  };
}

// Build headers for requests to data.xaostech.io and optionally ensure service token presence.
function getDataFetchHeaders(c: any, extra: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    'User-Agent': 'XAOSTECH API Worker',
    'X-Proxy-Source': 'api.xaostech.io',
    ...extra,
  };

  // Propagate trace id from upstream proxy if present so data worker logs can correlate
  const incomingTrace = c.req.header('X-Trace-Id');
  if (incomingTrace) headers['X-Trace-Id'] = incomingTrace;

  const { id, secret } = getDataAccessCredentials(c);
  if (id && secret) {
    headers['CF-Access-Client-Id'] = id;
    headers['CF-Access-Client-Secret'] = secret;
  }

  // Presence-only safe log
  const safeLog = {
    traceId: headers['X-Trace-Id'] || null,
    hasCfAccessId: !!headers['CF-Access-Client-Id'],
    hasCfAccessSecret: !!headers['CF-Access-Client-Secret'],
    extras: Object.keys(extra || {})
  };
  console.debug('[DATA] getDataFetchHeaders presence:', safeLog);

  return headers;
}

// Ensure DATA service token exists; return a Response (via c.json) if missing, else null.
function ensureDataAccessOrReject(c: any) {
  const { id, secret } = getDataAccessCredentials(c);
  if (!id || !secret) {
    console.error('[DATA] Missing DATA_ACCESS service credentials; rejecting request');
    return c.json({ error: 'Missing DATA service token' }, 502);
  }
  return null;
}
// Data service proxy
app.get('/data/analytics', requireAuth, requireAdmin, async (c: any) => {
  // Require DATA service token for any data proxy endpoints
  const maybeReject = ensureDataAccessOrReject(c);
  if (maybeReject) return maybeReject;

  return c.json({ 
    message: 'Analytics endpoint - proxies to data.xaostech.io',
    availableMetrics: ['users', 'requests', 'errors', 'latency']
  });
});

// === BLOG MEDIA SERVING (proxied to data worker) ===
app.post('/data/blog-media/upload', async (c: any) => {
  try {
    const formData = await c.req.formData();

    // Enforce DATA_ACCESS token and build headers including user metadata
    const maybeReject = ensureDataAccessOrReject(c);
    if (maybeReject) return maybeReject;

    const userHeaders = {
      'X-User-ID': c.req.header('X-User-ID') || '',
      'X-User-Role': c.req.header('X-User-Role') || '',
      'X-User-Email': c.req.header('X-User-Email') || '',
      'X-Account-ID': c.req.header('X-Account-ID') || ''
    };

    const fetchHeadersObj = getDataFetchHeaders(c, userHeaders);
    const safeLogUpload = {
      hasProxySource: !!fetchHeadersObj['X-Proxy-Source'],
      hasCfAccessId: !!fetchHeadersObj['CF-Access-Client-Id'],
      hasCfAccessSecret: !!fetchHeadersObj['CF-Access-Client-Secret']
    };
    console.debug('[DATA] Outgoing header presence for blog-media/upload:', safeLogUpload);
    const headers = new Headers(fetchHeadersObj);

    const response = await fetch('https://data.xaostech.io/blog-media/upload', {
      method: 'POST',
      headers,
      body: formData,
    });

    // If data returns HTML (Cloudflare Access login), surface a clear error
    const contentType = response.headers.get('content-type') || '';
    if (response.status === 200 && contentType.includes('text/html')) {
      const traceUpload = c.req.header('X-Trace-Id') || null;
      console.error('[DATA] Access login page received when uploading blog media; likely missing/invalid service token', { traceId: traceUpload });
      return new Response(JSON.stringify({ error: 'Upload blocked by Cloudflare Access' }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', 'X-Trace-Id': traceUpload || '' }
      });
    }

    if (!response.ok) {
      return c.json({ error: 'Upload failed' }, response.status);
    }

    return response.json();
  } catch (err: any) {
    console.error('Blog media upload proxy error:', err);
    return c.json({ error: 'Upload failed' }, 500);
  }
});

app.get('/data/blog-media/:key', async (c: any) => {
  const key = c.req.param('key');
  
  try {
    // Enforce DATA_ACCESS token and use helper headers
    const maybeReject = ensureDataAccessOrReject(c);
    if (maybeReject) return maybeReject;

    const fetchHeadersObj = getDataFetchHeaders(c);
    const safeLogFetch = {
      hasProxySource: !!fetchHeadersObj['X-Proxy-Source'],
      hasCfAccessId: !!fetchHeadersObj['CF-Access-Client-Id'],
      hasCfAccessSecret: !!fetchHeadersObj['CF-Access-Client-Secret']
    };
    console.debug('[DATA] Outgoing header presence for blog-media fetch:', safeLogFetch);

    const response = await fetch(`https://data.xaostech.io/blog-media/${key}`, {
      method: 'GET',
      headers: fetchHeadersObj
    });

    // Detect Access login HTML even on 200
    const contentType = response.headers.get('content-type') || '';
    if (response.status === 200 && contentType.includes('text/html')) {
      const bodyText = await response.text();
      if (bodyText.includes('Cloudflare') || bodyText.includes('Sign in') || bodyText.includes('Access')) {
        const traceBlogFetch = c.req.header('X-Trace-Id') || null;
        console.error('[DATA] Access login page received when fetching blog media', { traceId: traceBlogFetch });
        return new Response(JSON.stringify({ error: 'Media blocked by Cloudflare Access' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', 'X-Trace-Id': traceBlogFetch || '' }
        });
      }
    }

    if (!response.ok) {
      return c.json({ error: 'Media not found' }, response.status);
    }

    const blob = await response.blob();
    const headers = new Headers(response.headers);
    // Merge global security headers
    const secBlog = getSecurityHeaders();
    for (const k in secBlog) headers.set(k, secBlog[k]);
    
    return new Response(blob, {
      status: 200,
      headers
    });
  } catch (err: any) {
    console.error('Blog media fetch error:', err);
    return c.json({ error: 'Failed to fetch media' }, 500);
  }
});

// === ASSET SERVING ===
app.get('/data/assets/:filename', async (c: any) => {
  const filename = c.req.param('filename');
  
  if (!filename) {
    return c.json({ error: 'Filename required' }, 400);
  }

  try {
    // // NOTE: This worker is protected by Cloudflare Access — do NOT store or verify API access keys here.
    // // Cloudflare Access validates incoming requests; skip local verification and rely on Access.
    // const incomingApiId = c.req.header('CF-Access-Client-Id') || c.req.header('Cf-Access-Client-Id') || c.req.header('API-Access-Client-Id') || c.req.header('Api-Access-Client-Id');
    // console.debug('[ASSET] Skipping incoming API auth header verification (Cloudflare Access enforces authentication); incomingApiIdPresent=' + (!!incomingApiId));

    // Proxy to data worker which has R2 binding (may be protected by Cloudflare Access)
    // Enforce presence of DATA service token and build headers via helper
    const maybeReject = ensureDataAccessOrReject(c);
    if (maybeReject) return maybeReject;

    const fetchHeadersObj = getDataFetchHeaders(c);
    const safeLogAssets = {
      hasProxySource: !!fetchHeadersObj['X-Proxy-Source'],
      hasCfAccessId: !!fetchHeadersObj['CF-Access-Client-Id'],
      hasCfAccessSecret: !!fetchHeadersObj['CF-Access-Client-Secret']
    };
    console.debug('[DATA] Outgoing header presence for assets fetch:', safeLogAssets);

    const response = await fetch(`https://data.xaostech.io/assets/${filename}`, {
      method: 'GET',
      headers: fetchHeadersObj
    });

    // Detect HTML access login page even on 200 responses
    const contentType = response.headers.get('content-type') || '';
    if (response.status === 200 && contentType.includes('text/html')) {
      const bodyText = await response.text();
      if (bodyText.includes('Cloudflare') || bodyText.includes('Sign in') || bodyText.includes('Access')) {
        const traceAsset = c.req.header('X-Trace-Id') || null;
        console.error('[ASSET] Access login page received when fetching asset; likely missing/invalid service token', { traceId: traceAsset });
        return new Response(JSON.stringify({ error: 'Asset blocked by Cloudflare Access' }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', 'X-Trace-Id': traceAsset || '' }
        });
      }
    }

    if (!response.ok) {
      return c.json({ error: 'Asset not found' }, response.status);
    }

    // Return the asset with appropriate caching headers
    const blob = await response.blob();
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', 'public, max-age=604800'); // 1 week cache

    // Merge global security headers
    const sec = getSecurityHeaders();
    for (const k in sec) headers.set(k, sec[k]);
    
    console.log(`[ASSET] Returning ${filename} (${blob.size} bytes)`);
    
    return new Response(blob, {
      status: 200,
      headers
    });
  } catch (err: any) {
    console.error('[ASSET] Fetch error:', err.message, err.stack);
    return c.json({ error: 'Failed to fetch asset', details: err.message }, 500);
  }
});

// === FAVICON ROUTE ===
app.get('/favicon.ico', async (c: any) => {
  try {
    // Fetch the logo from the data worker's public assets endpoint
    // Enforce DATA_ACCESS service token and build headers via helper
    const maybeReject = ensureDataAccessOrReject(c);
    if (maybeReject) return maybeReject;

    const fetchHeaders = getDataFetchHeaders(c);
    const safeLogFavicon = {
      hasProxySource: !!fetchHeaders['X-Proxy-Source'],
      hasCfAccessId: !!fetchHeaders['CF-Access-Client-Id'],
      hasCfAccessSecret: !!fetchHeaders['CF-Access-Client-Secret']
    };
    console.debug('[DATA] Outgoing header presence for favicon fetch:', safeLogFavicon);

    const response = await fetch('https://data.xaostech.io/assets/XAOSTECH_LOGO.png', { headers: fetchHeaders });
    
    if (!response.ok) {
      return c.notFound();
    }
    
    const contentType = response.headers.get('content-type') || '';
    if (response.status === 200 && contentType.includes('text/html')) {
      const bodyText = await response.text();
      if (bodyText.includes('Cloudflare') || bodyText.includes('Sign in') || bodyText.includes('Access')) {
        const traceFav = c.req.header('X-Trace-Id') || null;
        console.error('[FAVICON] Received Access login page while attempting to fetch favicon', { traceId: traceFav });
        return c.notFound();
      }
    }

    const blob = await response.blob();
    const headers = new Headers({
      'Content-Type': 'image/png',
      'Cache-Control': 'public, max-age=604800', // 7 days
      
    });
    // Merge security headers
    const secFav = getSecurityHeaders();
    for (const k in secFav) headers.set(k, secFav[k]);
    console.debug && console.debug(`[FAVICON] Returning favicon, size=${blob.size}`);
    return new Response(blob, {
      status: 200,
      headers,
    });
  } catch (err: any) {
    console.error('Favicon fetch error:', err);
    return c.notFound();
  }
});

// // === DEBUG: CF-ACCESS HEADER PRESENCE ===
// app.get('/debug/headers', (c: any) => {
//   // Do NOT return secret values — only presence/status
//   const processEnv = (globalThis as any)?.process?.env;

//   const cfHeaderPresent = !!(c.req.header('CF-Access-Client-Id') || c.req.header('Cf-Access-Client-Id'));
//   const apiHeaderPresent = !!(c.req.header('API-Access-Client-Id') || c.req.header('Api-Access-Client-Id'));

//   // This worker does not store or verify API access keys locally (Cloudflare Access enforces auth)
//   const envHasApiClientId = false;
//   const envHasApiClientSecret = false;
//   const envHasDataClientId = !!getDataAccessCredentials(c).id;
//   const envHasDataClientSecret = !!getDataAccessCredentials(c).secret;

//   // Report presence of an incoming API header but do not verify it here
//   const incomingApiId = c.req.header('CF-Access-Client-Id') || c.req.header('Cf-Access-Client-Id') || c.req.header('API-Access-Client-Id') || c.req.header('Api-Access-Client-Id');
//   const apiAuthOk = 'not-checked';

//   return c.json({
//     cfHeaderPresent,
//     apiHeaderPresent,
//     envHasApiClientId,
//     envHasApiClientSecret,
//     envHasDataClientId,
//     envHasDataClientSecret,
//     apiAuthOk,
//   });
// });

// === ERROR HANDLING ===
app.notFound((c: any) => c.json({ 
  error: 'Not found',
  path: c.req.path,
  method: c.req.method,
}, 404));

// === ERROR HANDLING ===
app.notFound((c: any) => c.json({ 
  error: 'Not found',
  path: c.req.path,
  method: c.req.method,
}, 404));

app.onError((err: any, c: any) => {
  console.error('API Error:', err);
  return c.json({ 
    error: 'Internal server error',
    message: err.message,
  }, 500);
});

export default app;
