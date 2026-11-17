const test = require('node:test');
const assert = require('node:assert/strict');

// Test configuration - must be set before the app module is loaded.
process.env.NOTIFY_API_KEY = 'test-notify-key';
process.env.ALLOW_INSECURE_WEBHOOKS = 'true';
const AUTH = { Authorization: 'Bearer test-notify-key' };

const app = require('../src/index');
const config = require('../src/config');

const BASE_URL = `http://localhost:${config.PORT}`;
let server;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(config.PORT, resolve);
  });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

async function post(path, body, headers = AUTH) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function get(path, headers = AUTH) {
  const res = await fetch(`${BASE_URL}${path}`, { headers });
  return { status: res.status, body: await res.json() };
}

async function del(path) {
  const res = await fetch(`${BASE_URL}${path}`, { method: 'DELETE', headers: AUTH });
  return { status: res.status };
}


test('GET /health returns ok', async () => {
  const { status, body } = await get('/health');
  assert.equal(status, 200);
  assert.equal(body.status, 'ok');
});

test('POST /webhooks registers a webhook', async () => {
  const { status, body } = await post('/webhooks', {
    url: 'http://example.com/hook',
    events: ['scan.created'],
  });
  assert.equal(status, 201);
  assert.ok(body.id);
  assert.equal(body.url, 'http://example.com/hook');
});

test('POST /webhooks rejects missing url', async () => {
  const { status } = await post('/webhooks', { events: ['scan.created'] });
  assert.equal(status, 400);
});

test('POST /webhooks rejects empty events array', async () => {
  const { status } = await post('/webhooks', { url: 'http://example.com', events: [] });
  assert.equal(status, 400);
});

test('GET /webhooks lists registered webhooks', async () => {
  const { status, body } = await get('/webhooks');
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.webhooks));
});

test('DELETE /webhooks/:id removes a webhook', async () => {
  const { body } = await post('/webhooks', {
    url: 'http://example.com/deleteme',
    events: ['scan.updated'],
  });
  const { status } = await del(`/webhooks/${body.id}`);
  assert.equal(status, 204);
});

test('DELETE /webhooks/:id returns 404 for unknown id', async () => {
  const { status } = await del('/webhooks/non-existent-id');
  assert.equal(status, 404);
});

test('POST /notify requires event and payload', async () => {
  const { status } = await post('/notify', { event: 'scan.created' });
  assert.equal(status, 400);
});


// --- Security regression tests ---------------------------------------------

test('protected routes reject missing or wrong bearer key', async () => {
  assert.equal((await get('/webhooks', {})).status, 401);
  assert.equal((await get('/webhooks', { Authorization: 'Bearer wrong' })).status, 401);
  assert.equal((await post('/webhooks', { url: 'http://example.com/x', events: ['scan.created'] }, {})).status, 401);
  assert.equal((await post('/notify', { event: 'scan.created', payload: {} }, {})).status, 401);
});

test('POST /webhooks blocks SSRF targets', async () => {
  for (const url of [
    'http://169.254.169.254/latest/meta-data/',
    'http://localhost:8000/health',
    'http://127.0.0.1:3001/webhooks',
    'http://[::1]/',
    'http://10.0.0.5/',
    'file:///etc/passwd',
    'http://user:pass@example.com/',
  ]) {
    const { status } = await post('/webhooks', { url, events: ['scan.created'] });
    assert.equal(status, 400, url);
  }
});

test('POST /webhooks rejects unknown events and strips prototype keys', async () => {
  assert.equal((await post('/webhooks', { url: 'http://example.com/h', events: ['*'] })).status, 400);
  const { status, body } = await post('/webhooks', {
    url: 'http://example.com/h', events: ['scan.created'],
    metadata: JSON.parse('{"__proto__": {"polluted": true}, "team": "appsec"}'),
  });
  assert.equal(status, 201);
  assert.deepEqual(body.metadata, { team: 'appsec' });
  assert.equal({}.polluted, undefined);
});

test('errors do not leak stack traces', async () => {
  const res = await fetch(`${BASE_URL}/webhooks`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...AUTH }, body: '{bad json',
  });
  const body = await res.json();
  assert.equal(res.status, 400);
  assert.equal(body.stack, undefined);
});

test('outbound webhooks are HMAC-signed and never carry the service key', () => {
  const { sign } = require('../src/dispatcher');
  assert.match(sign('{"a":1}'), /^sha256=[0-9a-f]{64}$/);
  const src = require('fs').readFileSync(require.resolve('../src/dispatcher'), 'utf8');
  assert.ok(!src.includes('X-Service-Key'));
});
