import { Hono } from 'hono';
import { authMiddleware, requireAuth, requireAdmin, getAuth } from './middleware/auth';
import { loggingMiddleware } from './middleware/logging';

// Routers
import { chatRouter } from './routes/chat';
import { authRouter } from './routes/auth';
import { accountRouter } from './routes/account';
import { blogRouter } from './routes/blog';
import { dataRouter } from './routes/data';

import { getSecurityHeaders, applySecurityHeaders } from '../shared/types/security';

const app = new Hono();

// Global security headers middleware - skip for OAuth flows
app.use('*', async (c: any, next: any) => {
  await next();
  const res = c.res as Response;
  
  // Skip strict CSP for auth endpoints to allow GitHub OAuth page to load
  // Auth endpoints handle their own security and don't need restrictive CSP
  if (c.req.path.startsWith('/auth/github/')) {
    return res;
  }
  
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

// Mount routers
app.route('/chat', chatRouter);
app.route('/auth', authRouter as any);
app.route('/account', accountRouter as any);
app.route('/blog', blogRouter as any);
app.route('/data', dataRouter as any);

// Note: /data/assets/:filename is handled by dataRouter via routes/data.ts

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

// Chat AI, rooms and related endpoints are handled by the chat router mounted at /chat
// See ./routes/chat.ts

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

// Data access helpers moved to lib so api-only logic stays in API worker
import { getDataAccessCredentials, getDataFetchHeaders, ensureDataAccessOrReject } from './lib/data-proxy';
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

    const response = await fetchData(c, '/blog-media/upload', { method: 'POST', body: formData }, Object.fromEntries(headers.entries()));

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

    const response = await fetchData(c, `/blog-media/${key}`, { method: 'GET' });

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

// Asset serving is handled by the data router mounted at /data via ./routes/data.ts


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
    const traceFav = c.req.header('X-Trace-Id') || null;
    console.debug('[DATA] Outgoing header presence for favicon fetch:', safeLogFavicon);

    console.debug('[FAVICON] fetch start', { traceId: traceFav, path: '/assets/XAOSTECH_LOGO.png' });
    let response = await fetchData(c, '/assets/XAOSTECH_LOGO.png', { method: 'GET' });
    console.debug('[FAVICON] initial fetch result', { status: response.status, traceId: traceFav });

    // If upstream failed, retry with explicit credentials and Accept header as a compatibility fallback
    if (!response.ok) {
      try {
        const id = c.env?.DATA_ACCESS_CLIENT_ID;
        const secret = c.env?.DATA_ACCESS_CLIENT_SECRET;
        const explicitExtra: Record<string,string> = {};
        if (id && secret) {
          explicitExtra['CF-Access-Client-Id'] = id;
          explicitExtra['CF-Access-Client-Secret'] = secret;
        }
        explicitExtra['Accept'] = 'image/*, */*';
        const retryUrl = `/assets/XAOSTECH_LOGO.png?_retry=${Date.now()}`;
        response = await fetchData(c, retryUrl, { method: 'GET' }, explicitExtra);
      } catch (e) {
        console.error('[FAVICON] Retry fetch failed', e);
      }
    }

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
