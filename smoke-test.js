'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const { startServer } = require('./server');

async function main() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nexa-social-smoke-'));
  const server = startServer({ host: '127.0.0.1', port: 0, dataDir });
  try {
    if (!server.listening) await once(server, 'listening');
    const address = server.address();
    assert(address && typeof address === 'object');
    const base = `http://127.0.0.1:${address.port}`;
    async function api(route, method = 'GET', body, token, expectedStatus = 200) {
      const headers = {};
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      if (token) headers.Authorization = `Bearer ${token}`;
      const response = await fetch(`${base}${route}`, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body)
      });
      const data = await response.json().catch(() => ({}));
      assert.equal(response.status, expectedStatus, `${method} ${route}: ${JSON.stringify(data)}`);
      return data;
    }

    const health = await api('/health');
    assert.equal(health.ok, true);
    const alice = await api('/api/register', 'POST', { username: 'alice_test', displayName: 'Alice', password: 'GoodPassword-A1' }, null, 201);
    const bob = await api('/api/register', 'POST', { username: 'bob_test', displayName: 'Bob', password: 'GoodPassword-B1' }, null, 201);
    const carol = await api('/api/register', 'POST', { username: 'carol_test', displayName: 'Carol', password: 'GoodPassword-C1' }, null, 201);

    const profile = await api('/api/profile', 'POST', { displayName: 'Alice Player' }, alice.token);
    assert.equal(profile.user.displayName, 'Alice Player');
    await api('/api/login', 'POST', { username: 'alice_test', password: 'not-correct' }, null, 401);
    await api('/api/me', 'GET', undefined, 'invalid-session', 401);

    await api('/api/friend-requests', 'POST', { username: 'bob_test' }, alice.token, 201);
    let snapshot = await api('/api/social', 'GET', undefined, bob.token);
    assert.equal(snapshot.incoming.length, 1);
    await api(`/api/friend-requests/${snapshot.incoming[0].id}/accept`, 'POST', undefined, bob.token);
    await api('/api/friend-requests', 'POST', { username: 'carol_test' }, alice.token, 201);
    snapshot = await api('/api/social', 'GET', undefined, carol.token);
    await api(`/api/friend-requests/${snapshot.incoming[0].id}/accept`, 'POST', undefined, carol.token);

    await api('/api/messages', 'POST', { to: 'bob_test', body: 'Direct chat OK' }, alice.token, 201);
    const direct = await api('/api/messages?with=alice_test&after=0', 'GET', undefined, bob.token);
    assert(direct.messages.some(message => message.body === 'Direct chat OK'));

    const created = await api('/api/groups', 'POST', { name: 'Smoke Test Party', members: ['bob_test'] }, alice.token, 201);
    const groupId = created.group.id;
    await api(`/api/groups/${groupId}/members`, 'POST', { username: 'carol_test' }, alice.token);
    let groups = await api('/api/groups', 'GET', undefined, carol.token);
    assert(groups.groups.some(group => group.id === groupId));
    await api(`/api/groups/${groupId}/members/carol_test`, 'DELETE', undefined, alice.token);
    groups = await api('/api/groups', 'GET', undefined, carol.token);
    assert(!groups.groups.some(group => group.id === groupId));
    await api(`/api/groups/${groupId}/messages`, 'POST', { body: 'Group chat OK' }, alice.token, 201);
    const groupMessages = await api(`/api/groups/${groupId}/messages?after=0`, 'GET', undefined, bob.token);
    assert(groupMessages.messages.some(message => message.body === 'Group chat OK'));

    await api('/api/blocks', 'POST', { username: 'bob_test' }, alice.token);
    const blocked = await api('/api/blocks', 'GET', undefined, alice.token);
    assert(blocked.blocked.some(user => user.username === 'bob_test'));
    await api('/api/messages', 'POST', { to: 'bob_test', body: 'blocked' }, alice.token, 403);
    await api('/api/blocks/bob_test', 'DELETE', undefined, alice.token);
    const unblocked = await api('/api/blocks', 'GET', undefined, alice.token);
    assert(!unblocked.blocked.some(user => user.username === 'bob_test'));

    await api(`/api/groups/${groupId}/leave`, 'DELETE', undefined, bob.token);
    await api(`/api/groups/${groupId}/messages?after=0`, 'GET', undefined, bob.token, 404);
    console.log('NEXA Social smoke test: PASS (contas, sessão, perfil, amizade, chat direto, grupos, permissões e bloqueios).');
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error('NEXA Social smoke test: FAIL');
  console.error(error.stack || error);
  process.exitCode = 1;
});
