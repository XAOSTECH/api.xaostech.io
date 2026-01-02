import { Hono } from 'hono';
import { authMiddleware, requireAuth, requireAdmin, getAuth } from './middleware/auth';
import { loggingMiddleware } from './middleware/logging';

const app = new Hono();

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

app.get('/status', (c: any) => c.json({
  service: 'api.xaostech.io',
  version: '2.0.0',
  uptime: process.uptime?.(),
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

  try {
    if (action === 'delete') {
      await c.env.DB
        .prepare('UPDATE messages SET deleted_at = datetime("now"), deleted_by = ? WHERE id = ?')
        .bind(auth.userId, messageId)
        .run();
    } else if (action === 'flag') {
      await c.env.DB
        .prepare('UPDATE messages SET flagged = 1, flagged_by = ?, flag_reason = ? WHERE id = ?')
        .bind(auth.userId, reason, messageId)
        .run();
    }

    return c.json({ success: true, action, messageId });
  } catch (err) {
    return c.json({ error: 'Failed to moderate message' }, 500);
  }
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

// Data service proxy
app.get('/data/analytics', requireAuth, requireAdmin, async (c: any) => {
  return c.json({ 
    message: 'Analytics endpoint - proxies to data.xaostech.io',
    availableMetrics: ['users', 'requests', 'errors', 'latency']
  });
});

// === BLOG MEDIA SERVING (proxied to data worker) ===
app.post('/data/blog-media/upload', async (c: any) => {
  try {
    const formData = await c.req.formData();
    
    // Forward to data worker with user headers (no service token needed - data.xaostech.io is public)
    const headers = new Headers({
      'X-User-ID': c.req.header('X-User-ID') || '',
      'X-User-Role': c.req.header('X-User-Role') || '',
      'X-User-Email': c.req.header('X-User-Email') || '',
      'X-Account-ID': c.req.header('X-Account-ID') || '',
      'User-Agent': 'XAOSTECH API Worker'
    });
    
    const response = await fetch('https://data.xaostech.io/blog-media/upload', {
      method: 'POST',
      headers,
      body: formData,
    });

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
    // Forward to data worker (no service token needed - data.xaostech.io is public)
    const response = await fetch(`https://data.xaostech.io/blog-media/${key}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'XAOSTECH API Worker'
      }
    });
    
    if (!response.ok) {
      return c.json({ error: 'Media not found' }, response.status);
    }

    const blob = await response.blob();
    const headers = new Headers(response.headers);
    
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
    // Proxy to data worker which has R2 binding (may be protected by Cloudflare Access)
    const clientId = c.env?.CF_ACCESS_CLIENT_ID;
    const clientSecret = c.env?.CF_ACCESS_CLIENT_SECRET;

    const fetchHeaders: Record<string, string> = {
      'User-Agent': 'XAOSTECH API Worker'
    };

    if (clientId && clientSecret) {
      fetchHeaders['CF-Access-Client-Id'] = clientId;
      fetchHeaders['CF-Access-Client-Secret'] = clientSecret;
    } else {
      console.debug('[ASSET] CF_ACCESS credentials not present in env (may be intentional if data is public)');
    }

    const response = await fetch(`https://data.xaostech.io/assets/${filename}`, {
      method: 'GET',
      headers: fetchHeaders
    });
    
    if (!response.ok) {
      // If we received HTML (Cloudflare Access login), log and return a helpful error
      const contentType = response.headers.get('content-type') || '';
      if (response.status === 200 && contentType.includes('text/html')) {
        const bodyText = await response.text();
        if (bodyText.includes('Cloudflare') || bodyText.includes('Sign in') || bodyText.includes('Access')) {
          console.error('[ASSET] Access login page received when fetching asset; likely missing/invalid service token');
          return c.json({ error: 'Asset blocked by Cloudflare Access' }, 502);
        }
      }

      return c.json({ error: 'Asset not found' }, response.status);
    }

    // Return the asset with appropriate caching headers
    const blob = await response.blob();
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', 'public, max-age=604800'); // 1 week cache
    
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
    const clientId = c.env?.CF_ACCESS_CLIENT_ID;
    const clientSecret = c.env?.CF_ACCESS_CLIENT_SECRET;

    const fetchHeaders: Record<string, string> = {};
    if (clientId && clientSecret) {
      fetchHeaders['CF-Access-Client-Id'] = clientId;
      fetchHeaders['CF-Access-Client-Secret'] = clientSecret;
    } else {
      // Not all deployments require CF Access tokens for data; log at debug level only.
      console.debug('[FAVICON] CF_ACCESS credentials not present in env (may be intentional if data is public)');
    }

    const response = await fetch('https://data.xaostech.io/assets/XAOSTECH_LOGO.png', { headers: fetchHeaders });
    
    if (!response.ok) {
      return c.notFound();
    }
    
    const contentType = response.headers.get('content-type') || '';
    if (response.status === 200 && contentType.includes('text/html')) {
      const bodyText = await response.text();
      if (bodyText.includes('Cloudflare') || bodyText.includes('Sign in') || bodyText.includes('Access')) {
        console.error('[FAVICON] Received Access login page while attempting to fetch favicon');
        return c.notFound();
      }
    }

    const blob = await response.blob();
    return new Response(blob, {
      status: 200,
      headers: {
        'Content-Type': 'image/png',
        'Cache-Control': 'public, max-age=604800', // 7 days
      },
    });
  } catch (err: any) {
    console.error('Favicon fetch error:', err);
    return c.notFound();
  }
});

// === DEBUG: CF-ACCESS HEADER PRESENCE ===
app.get('/debug/headers', (c: any) => {
  // Do NOT return secret values — only presence/status
  const headerPresent = !!(c.req.header('CF-Access-Client-Id') || c.req.header('Cf-Access-Client-Id'));
  const xProxyFlag = !!c.req.header('X-Proxy-CF-Injected');
  const envHasClientId = !!(c.env && (c.env.CF_ACCESS_CLIENT_ID || process.env.CF_ACCESS_CLIENT_ID));
  const envHasClientSecret = !!(c.env && (c.env.CF_ACCESS_CLIENT_SECRET || process.env.CF_ACCESS_CLIENT_SECRET));

  return c.json({
    cfAccessHeaderPresent: headerPresent,
    xProxyFlag,
    envHasClientId,
    envHasClientSecret,
  });
});

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
