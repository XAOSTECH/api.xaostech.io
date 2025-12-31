import { Hono } from 'hono';

const app = new Hono();

app.get('/health', (c) => c.json({ status: 'ok' }));

app.get('/tasks', async (c) => {
  const db = c.env.DB;
  try {
    const { results } = await db.prepare('SELECT * FROM tasks LIMIT 100').all();
    return c.json(results);
  } catch (err) {
    return c.json({ error: 'Tasks table not initialized' }, 500);
  }
});

app.post('/tasks', async (c) => {
  const db = c.env.DB;
  const { title, description } = await c.req.json();
  
  if (!title) {
    return c.json({ error: 'title required' }, 400);
  }

  try {
    const stmt = db.prepare(
      'INSERT INTO tasks (title, description, created_at) VALUES (?, ?, datetime("now"))'
    );
    await stmt.bind(title, description || '').run();
    return c.json({ success: true }, 201);
  } catch (err) {
    return c.json({ error: 'Failed to create task' }, 500);
  }
});

app.get('/tasks/:id', async (c) => {
  const db = c.env.DB;
  const id = c.req.param('id');
  
  try {
    const stmt = db.prepare('SELECT * FROM tasks WHERE id = ?');
    const result = await stmt.bind(id).first();
    return result ? c.json(result) : c.json({ error: 'Not found' }, 404);
  } catch (err) {
    return c.json({ error: 'Failed to fetch task' }, 500);
  }
});

app.put('/tasks/:id', async (c) => {
  const db = c.env.DB;
  const id = c.req.param('id');
  const { title, description, completed } = await c.req.json();

  try {
    const stmt = db.prepare(
      'UPDATE tasks SET title = ?, description = ?, completed = ? WHERE id = ?'
    );
    await stmt.bind(title, description, completed ? 1 : 0, id).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: 'Failed to update task' }, 500);
  }
});

app.delete('/tasks/:id', async (c) => {
  const db = c.env.DB;
  const id = c.req.param('id');

  try {
    const stmt = db.prepare('DELETE FROM tasks WHERE id = ?');
    await stmt.bind(id).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: 'Failed to delete task' }, 500);
  }
});

export default app;
