import { Hono } from 'hono';
import { requireAuth } from '../middleware/auth';

export const blogRouter = new Hono();

// List posts
blogRouter.get('/posts', async (c: any) => {
  const db = c.env.DB;
  if (!db) return c.json({ error: 'DB not configured' }, 501);

  try {
    const { results } = await db.prepare('SELECT id, slug, title, excerpt, author_id, created_at, published FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT 100').all();
    return c.json({ posts: results });
  } catch (err) {
    return c.json({ error: 'Failed to fetch posts' }, 500);
  }
});

// Read post
blogRouter.get('/posts/:id', async (c: any) => {
  const id = c.req.param('id');
  const db = c.env.DB;
  if (!db) return c.json({ error: 'DB not configured' }, 501);

  try {
    const row = await db.prepare('SELECT id, slug, title, content, author_id, created_at, published FROM posts WHERE id = ?').bind(id).first();
    if (!row) return c.json({ error: 'Not found' }, 404);
    return c.json({ post: row });
  } catch (err) {
    return c.json({ error: 'Failed to fetch post' }, 500);
  }
});

// Create post (requires auth)
blogRouter.post('/posts', requireAuth, async (c: any) => {
  const auth = c.get('auth') as any;
  const db = c.env.DB;
  if (!db) return c.json({ error: 'DB not configured' }, 501);

  const { title, content, slug, published } = await c.req.json().catch(() => ({}));
  if (!title || !content) return c.json({ error: 'title and content required' }, 400);

  try {
    const id = crypto.randomUUID();
    await db.prepare('INSERT INTO posts (id, slug, title, excerpt, content, author_id, created_at, published) VALUES (?, ?, ?, ?, ?, ?, datetime("now"), ?)')
      .bind(id, slug || null, title, (content || '').slice(0, 320), content, auth.userId, published ? 1 : 0).run();

    return c.json({ success: true, id }, 201);
  } catch (err) {
    console.error('Create post error', err);
    return c.json({ error: 'Failed to create post' }, 500);
  }
});
