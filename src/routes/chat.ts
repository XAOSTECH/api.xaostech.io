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
