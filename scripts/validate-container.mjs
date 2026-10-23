// Runs inside the built image, without provider credentials or external network.
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

assert.equal(process.platform, 'linux');
assert.equal(process.arch, 'x64');
assert.equal(process.getuid(), 1001);
assert.match(process.versions.node, /^26\./);
for (const [name, version] of Object.entries({
  '@modelcontextprotocol/sdk': '1.32.1',
  'proxy-addr': '2.0.8',
  'fast-uri': '3.1.9',
  hono: '4.13.13',
  'ip-address': '10.7.4',
  '@wyre-ai/node-datto-rmm': '1.1.0',
})) {
  assert.equal(JSON.parse(readFileSync(`/app/node_modules/${name}/package.json`, 'utf8')).version, version);
}
assert.equal(existsSync('/app/node_modules/typescript'), false);
assert.equal(existsSync('/app/node_modules/vitest'), false);
assert.equal(existsSync('/app/.npmrc'), false);
assert.equal(existsSync('/usr/local/lib/node_modules/npm'), false);
assert.equal(existsSync('/usr/local/bin/npm'), false);
assert.equal(existsSync('/usr/local/bin/npx'), false);
assert.equal(process.env.NODE_AUTH_TOKEN, undefined);
assert.equal(process.env.DATTO_API_KEY, undefined);
assert.equal(process.env.DATTO_API_SECRET, undefined);

const base = 'http://127.0.0.1:8080';
for (let attempt = 0; ; attempt++) {
  try {
    const response = await fetch(`${base}/health`, { signal: AbortSignal.timeout(2000) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, 'ok');
    break;
  } catch (error) {
    if (attempt === 19) throw error;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
}
assert.equal((await fetch(`${base}/ready`, { signal: AbortSignal.timeout(2000) })).status, 200);
const fixtureToken = 'synthetic-container-backend-token';
const init = version => ({ protocolVersion: version, capabilities: {}, clientInfo: { name: 'container-fixture', version: '0' } });
async function request(method, params, version, token = fixtureToken) {
  return fetch(`${base}/mcp`, {
    method: 'POST',
    signal: AbortSignal.timeout(5000),
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': version,
      ...(token ? { 'x-summit-datto-backend-token': token } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}
for (const token of ['', 'wrong-synthetic-token']) {
  assert.equal((await request('tools/list', {}, '2025-06-18', token)).status, 401);
}
for (const version of ['2025-06-18', '2025-11-25']) {
  const response = await request('initialize', init(version), version);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).result.protocolVersion, version);
  const list = await request('tools/list', {}, version);
  assert.equal(list.status, 200);
  assert.ok((await list.json()).result.tools.some(tool => tool.name === 'datto_get_device'));
}
// A provider read without credentials must fail locally, even after discovery.
const read = await request('tools/call', { name: 'datto_get_device', arguments: { deviceUid: 'fixture-device' } }, '2025-06-18');
assert.equal(read.status, 200);
assert.equal((await read.json()).result.isError, true);

// Exercise the published CLI entrypoint as well as the HTTP entrypoint.
const child = spawn('node', ['dist/index.js'], { env: { ...process.env, MCP_TRANSPORT: 'stdio' }, stdio: ['pipe', 'pipe', 'pipe'] });
const pending = new Map();
const lines = createInterface({ input: child.stdout });
const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
lines.on('line', line => {
  const message = JSON.parse(line);
  pending.get(message.id)?.(message);
});
child.stderr.resume();
try {
  const exchange = (id, method, params) => new Promise((resolve, reject) => {
    pending.set(id, resolve);
    child.once('exit', () => reject(new Error('stdio process exited before response')));
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  const initialized = await exchange(1, 'initialize', init('2025-06-18'));
  assert.equal(initialized.result.protocolVersion, '2025-06-18');
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  const list = await exchange(2, 'tools/list', {});
  assert.ok(list.result.tools.some(tool => tool.name === 'datto_get_device'));
} finally {
  clearTimeout(timer);
  lines.close();
  child.kill('SIGTERM');
}
console.log('Image checks passed: Node26/non-root, patched production packages, HTTP auth/init/discovery, missing-provider fail-safe, stdio init/discovery.');
