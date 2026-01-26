import { Hono } from 'hono';
import { requireAuth, requireAdmin, requireScope, getAuth } from '../middleware/auth';

/**
 * Chat Routes
 * 
 * Admin API (protected):
 *   POST /chat/admin/moderation - Moderate messages
 *   DELETE /chat/admin/messages/:id - Delete messages
 * 
 * Public API (requires auth):
 *   GET /chat/messages - List messages user has access to
 *   POST /chat/messages - Send message
 *   GET /chat/conversations - List user's conversations
 * 
 * Public (no auth):
 *   GET /chat/health - Health check
 */
export const chatRouter = new Hono();

// Health check (no auth required)
chatRouter.get('/health', (c) => c.json({ service: 'chat', status: 'ok' }));

// Public: List messages (requires user session) - proxy to DATA service
chatRouter.get('/messages', requireAuth, async (c) => {
  const auth = getAuth(c);
  const dataService = (c.env as any).DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  try {
    const limit = c.req.query('limit') || '50';
    const offset = c.req.query('offset') || '0';
    const resp = await dataService.fetch(`https://data.xaostech.io/chat/messages?user_id=${auth.userId}&limit=${limit}&offset=${offset}`);
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to fetch messages' }, 500);
  }
});

// Public: Send message - proxy to DATA service
chatRouter.post('/messages', requireAuth, async (c) => {
  const auth = getAuth(c);
  const dataService = (c.env as any).DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const body = await c.req.json();
  const { conversationId, content } = body;

  if (!conversationId || !content) {
    return c.json({ error: 'conversationId and content required' }, 400);
  }

  try {
    const resp = await dataService.fetch('https://data.xaostech.io/chat/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ room_id: conversationId, user_id: auth.userId, content }),
    });
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to send message' }, 500);
  }
});

// Admin: Moderate messages - proxy to DATA service
chatRouter.post('/admin/moderation', requireAuth, requireAdmin, async (c) => {
  const auth = getAuth(c);
  const dataService = (c.env as any).DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const { messageId, action, reason } = await c.req.json();

  if (!messageId || !action) {
    return c.json({ error: 'messageId and action required' }, 400);
  }

  console.log(`[MODERATION] Admin ${auth.userId} performed ${action} on message ${messageId}: ${reason}`);

  try {
    const resp = await dataService.fetch('https://data.xaostech.io/chat/moderation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messageId, action, reason, adminId: auth.userId }),
    });
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to moderate message' }, 500);
  }
});

// Admin: Delete conversation - proxy to DATA service
chatRouter.delete('/admin/conversations/:id', requireAuth, requireAdmin, async (c) => {
  const auth = getAuth(c);
  const dataService = (c.env as any).DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);

  const conversationId = c.req.param('id');

  try {
    const resp = await dataService.fetch(`https://data.xaostech.io/chat/rooms/${conversationId}`, {
      method: 'DELETE',
    });
    console.log(`[ADMIN] Admin ${auth.userId} deleted conversation ${conversationId}`);
    return resp;
  } catch (err) {
    return c.json({ error: 'Failed to delete conversation' }, 500);
  }
});

// AI endpoint - mirrors previous chat worker behavior
chatRouter.post('/', async (c: any) => {
  try {
    const body = await c.req.json();
    const messages = (body && body.messages) || [];
    if (messages.length > 0 && messages[0].role !== 'system') {
      messages.unshift({ role: 'system', content: 'You are the omnipotent void χάος. Be concise and neutral.' });
    }

    if (!c.env.AI) {
      return c.json({ error: 'AI binding not configured on api.xaostech.io' }, 501);
    }

    const CHAT_MODEL_ID = ((globalThis as any).process?.env?.CHAT_MODEL_ID) || '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
    const response = await c.env.AI.run(CHAT_MODEL_ID, { messages, max_tokens: 1024 }, { returnRawResponse: true });
    return new Response(response.body, { status: response.status || 200, headers: response.headers });
  } catch (err) {
    console.error('AI /chat error', err);
    return c.json({ error: 'AI request failed' }, 500);
  }
});

// Rooms - use MESSAGES_KV if available
chatRouter.get('/rooms', async (c: any) => {
  const kv = (c.env as any).MESSAGES_KV;
  if (!kv) return c.json({ error: 'MESSAGES_KV not configured' }, 501);

  const raw = await kv.get('rooms:index');
  const rooms = raw ? JSON.parse(raw) : [];
  return c.json(rooms);
});

chatRouter.get('/rooms/random', async (c: any) => {
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
