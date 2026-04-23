import { Hono } from 'hono';
import { requireAuth } from '../middleware/auth';

/**
 * Music routes — proxies to data.xaostech.io for the Trove (music discoveries)
 *
 * data.xaostech.io is expected to host:
 *   GET    /music/trove?limit&offset&genre   -> { posts, total }
 *   GET    /music/trove/:idOrSlug            -> { post, comments }
 *   POST   /music/trove                      -> create (admin/owner)
 *   PATCH  /music/trove/:id                  -> update (admin/owner)
 *   DELETE /music/trove/:id                  -> delete (admin/owner)
 *   POST   /music/trove/:id/comments         -> add comment (auth)
 *
 * If the data worker hasn't shipped these yet they return 501 below so
 * the music site degrades gracefully (empty trove, no error toast).
 */

export const musicRouter = new Hono();

const callData = async (c: any, path: string, init?: RequestInit) => {
  const dataService = c.env.DATA;
  if (!dataService) return c.json({ error: 'DATA service not configured' }, 501);
  try {
    return await dataService.fetch(`https://data.xaostech.io${path}`, init);
  } catch (err) {
    console.error('music data proxy error', err);
    return c.json({ error: 'data proxy failed' }, 502);
  }
};

// List trove posts
musicRouter.get('/trove', async (c: any) => {
  const limit = c.req.query('limit') || '50';
  const offset = c.req.query('offset') || '0';
  const genre = c.req.query('genre') || '';
  let qs = `?limit=${limit}&offset=${offset}`;
  if (genre) qs += `&genre=${encodeURIComponent(genre)}`;
  return callData(c, `/music/trove${qs}`);
});

// Read single trove post by id or slug
musicRouter.get('/trove/:idOrSlug', async (c: any) => {
  const idOrSlug = c.req.param('idOrSlug');
  return callData(c, `/music/trove/${encodeURIComponent(idOrSlug)}`);
});

// Create trove post (admin/owner)
musicRouter.post('/trove', requireAuth, async (c: any) => {
  const auth = c.get('auth') as any;
  if (auth.role !== 'admin' && auth.role !== 'owner') {
    return c.json({ error: 'Forbidden' }, 403);
  }
  const body = await c.req.json().catch(() => ({}));
  const { title, content } = body || {};
  if (!title || !content) return c.json({ error: 'title and content required' }, 400);
  return callData(c, '/music/trove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...body, author_id: auth.userId }),
  });
});

// Update trove post (admin/owner)
musicRouter.patch('/trove/:id', requireAuth, async (c: any) => {
  const auth = c.get('auth') as any;
  if (auth.role !== 'admin' && auth.role !== 'owner') {
    return c.json({ error: 'Forbidden' }, 403);
  }
  const id = c.req.param('id');
  const body = await c.req.json().catch(() => ({}));
  return callData(c, `/music/trove/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'X-User-Id': auth.userId },
    body: JSON.stringify(body),
  });
});

// Delete trove post (admin/owner)
musicRouter.delete('/trove/:id', requireAuth, async (c: any) => {
  const auth = c.get('auth') as any;
  if (auth.role !== 'admin' && auth.role !== 'owner') {
    return c.json({ error: 'Forbidden' }, 403);
  }
  const id = c.req.param('id');
  return callData(c, `/music/trove/${id}`, {
    method: 'DELETE',
    headers: { 'X-User-Id': auth.userId },
  });
});

// Add comment to trove post (any authed user)
musicRouter.post('/trove/:id/comments', requireAuth, async (c: any) => {
  const auth = c.get('auth') as any;
  const id = c.req.param('id');
  const body = await c.req.json().catch(() => ({}));
  if (!body?.content) return c.json({ error: 'content required' }, 400);
  return callData(c, `/music/trove/${id}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...body, author_id: auth.userId, author_name: auth.username }),
  });
});
