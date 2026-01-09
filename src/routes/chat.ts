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

// Public: List messages (requires user session)
chatRouter.get('/messages', requireAuth, async (c) => {
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

// Public: Send message
chatRouter.post('/messages', requireAuth, async (c) => {
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

// Admin: Moderate messages
chatRouter.post('/admin/moderation', requireAuth, requireAdmin, async (c) => {
  const auth = getAuth(c);
  const { messageId, action, reason } = await c.req.json();

  if (!messageId || !action) {
    return c.json({ error: 'messageId and action required' }, 400);
  }

  // Log moderation action
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

// Admin: Delete conversation
chatRouter.delete('/admin/conversations/:id', requireAuth, requireAdmin, async (c) => {
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
