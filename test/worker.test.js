import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';

test('Worker responds with 200 on health check GET /', async () => {
  const req = new Request('http://localhost/', { method: 'GET' });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.equal(text, '2FAuth Worker is running.');
});

test('Worker returns 404 on unknown routes', async () => {
  const req = new Request('http://localhost/unknown', { method: 'GET' });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 404);
});

test('Worker miniapp delete endpoint validates auth and parameters', async () => {
  const reqNoAuth = new Request('http://localhost/api/miniapp/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId: 1 }),
  });
  const resNoAuth = await worker.fetch(reqNoAuth, {
    BOT_TOKEN: 'fake_token',
    DB: { prepare: () => ({ first: async () => null }) },
  }, {});
  assert.equal(resNoAuth.status, 401);
});
