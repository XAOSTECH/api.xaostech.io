import { Hono } from 'hono';
import { requireAuth, getAuth } from '../middleware/auth';

/**
 * Messages Router — STUB / SCAFFOLD
 *
 * Backed by env.MESSAGES_KV (binding declared in wrangler.toml).
 *
 * Storage shape (proposed, not yet enforced):
 *   conv:<userA>:<userB>     → JSON { participants: [a,b], lastMessageAt, lastPreview }
 *                              (sort participants alphabetically so the key is
 *                              identical from either side)
 *   msg:<convId>:<ulid>      → JSON { from, to, body, ts, read }
 *   inbox:<userId>           → JSON [{ convId, unread, lastPreview, peer }]
 *   unread:<userId>          → number (denormalised badge count)
 *
 * Endpoints implemented as stubs returning mock data so the bubble UI can be
 * built and demoed without committing to a schema. Replace TODOs with real KV
 * reads/writes once the shape is locked in.
 */
export const messagesRouter = new Hono();

messagesRouter.get('/health', (c) => c.json({ service: 'messages', status: 'ok' }));

// GET /messages/inbox — list of conversations + unread badge for current user
messagesRouter.get('/inbox', requireAuth, async (c) => {
  const auth = getAuth(c);
  // TODO: const raw = await c.env.MESSAGES_KV.get(`inbox:${auth.userId}`, 'json');
  return c.json({
    userId: auth.userId,
    unread: 0,
    conversations: [], // [{ convId, peer: { id, username, avatarUrl }, unread, lastPreview, lastMessageAt }]
    _stub: true,
  });
});

// GET /messages/thread/:peerId — full message history with one peer
messagesRouter.get('/thread/:peerId', requireAuth, async (c) => {
  const auth = getAuth(c);
  const peerId = c.req.param('peerId');
  // TODO: derive convId from sorted [auth.userId, peerId], list MESSAGES_KV with prefix `msg:${convId}:`
  return c.json({
    convId: [auth.userId, peerId].sort().join(':'),
    messages: [], // [{ id, from, to, body, ts, read }]
    _stub: true,
  });
});

// POST /messages/send — body: { to: string, body: string }
messagesRouter.post('/send', requireAuth, async (c) => {
  const auth = getAuth(c);
  const { to, body } = await c.req.json<{ to: string; body: string }>();
  if (!to || !body) return c.json({ error: 'to and body required' }, 400);
  // TODO: write msg:<convId>:<ulid>, bump conv:<convId> lastMessageAt, increment unread:<to>
  return c.json({
    id: 'stub-' + Date.now(),
    from: auth.userId,
    to,
    body,
    ts: Date.now(),
    read: false,
    _stub: true,
  });
});

// POST /messages/read — body: { convId: string }
messagesRouter.post('/read', requireAuth, async (c) => {
  // TODO: zero unread for this conv, recompute unread:<userId> denorm counter
  return c.json({ ok: true, _stub: true });
});
