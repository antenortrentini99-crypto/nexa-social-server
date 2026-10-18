'use strict';

// NEXA HUB Social Server 2.0.0
// Dependency-free Node.js server for accounts, friend requests, presence and chat.
// For public internet use, put this behind HTTPS (Caddy/Nginx/your hosting provider).

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');

let HOST = process.env.NEXA_HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');
let PORT = Number(process.env.PORT || process.env.NEXA_PORT || 47821);
let DATA_DIR = process.env.NEXA_DATA_DIR || path.join(__dirname, 'data');
let DATA_FILE = path.join(DATA_DIR, 'social-db.json');
const SESSION_DAYS = 30;
const MAX_BODY = 16 * 1024;
const rateBuckets = new Map();

function freshDb() {
  return { version: 1, users: [], friendships: [], friendRequests: [], messages: [], groups: [], groupMessages: [], sessions: [], nextMessageId: 1, nextGroupMessageId: 1 };
}
function loadDb() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return {
      ...freshDb(), ...parsed,
      users: Array.isArray(parsed.users) ? parsed.users : [],
      friendships: Array.isArray(parsed.friendships) ? parsed.friendships : [],
      friendRequests: Array.isArray(parsed.friendRequests) ? parsed.friendRequests : [],
      messages: Array.isArray(parsed.messages) ? parsed.messages : [],
      groups: Array.isArray(parsed.groups) ? parsed.groups : [],
      groupMessages: Array.isArray(parsed.groupMessages) ? parsed.groupMessages : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      nextMessageId: Number.isSafeInteger(parsed.nextMessageId) ? parsed.nextMessageId : 1,
      nextGroupMessageId: Number.isSafeInteger(parsed.nextGroupMessageId) ? parsed.nextGroupMessageId : 1
    };
  } catch (error) {
    if (error.code !== 'ENOENT') console.error('Banco inválido; usando banco novo:', error.message);
    return freshDb();
  }
}
let db = loadDb();
let server = null;
function saveDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const temp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(db, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(temp, DATA_FILE);
}
function nowIso() { return new Date().toISOString(); }
function json(res, status, value) {
  const data = JSON.stringify(value);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(data);
}
function cleanString(value, max = 100) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function publicUser(user) {
  return { username: user.username, displayName: user.displayName, createdAt: user.createdAt, lastSeen: user.lastSeen || null };
}
function isBlocked(blocker, other) {
  const user = findUser(blocker);
  return Array.isArray(user?.blocked) && user.blocked.includes(other);
}
function normalizeUsername(value) { return cleanString(value, 32).toLowerCase(); }
function usernameValid(value) { return /^[a-z0-9_]{3,20}$/.test(value); }
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function passwordMatches(password, user) {
  const test = crypto.scryptSync(password, user.passwordSalt, 64);
  const known = Buffer.from(user.passwordHash, 'hex');
  return test.length === known.length && crypto.timingSafeEqual(test, known);
}
function pairKey(a, b) { return [a, b].sort().join(':'); }
function areFriends(a, b) { return db.friendships.some(item => item.key === pairKey(a, b)); }
function findUser(username) { return db.users.find(user => user.username === username) || null; }
function getAuth(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!token) return null;
  const tokenHash = hashToken(token);
  const session = db.sessions.find(item => item.tokenHash === tokenHash && Date.parse(item.expiresAt) > Date.now());
  if (!session) return null;
  const user = findUser(session.username);
  return user ? { user, session } : null;
}
function authenticated(req, res) {
  const auth = getAuth(req);
  if (!auth) { json(res, 401, { error: 'Sua sessão expirou. Entre novamente.' }); return null; }
  return auth;
}
function requestLimit(req, res, pathname) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').toString().split(',')[0].trim();
  const key = `${ip}:${pathname}`;
  const current = rateBuckets.get(key) || { start: Date.now(), count: 0 };
  if (Date.now() - current.start > 60_000) { current.start = Date.now(); current.count = 0; }
  current.count++;
  rateBuckets.set(key, current);
  const limit = /login|register/.test(pathname) ? 10 : 180;
  if (current.count > limit) { json(res, 429, { error: 'Muitas solicitações. Aguarde um minuto e tente novamente.' }); return false; }
  return true;
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''; let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('Corpo da solicitação muito grande.'), { status: 413 })); req.destroy(); return; }
      body += chunk.toString('utf8');
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); }
      catch { reject(Object.assign(new Error('JSON inválido.'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const session = {
    tokenHash: hashToken(token), username: user.username,
    createdAt: nowIso(), lastSeen: nowIso(),
    expiresAt: new Date(Date.now() + SESSION_DAYS * 86400000).toISOString()
  };
  db.sessions = db.sessions.filter(item => Date.parse(item.expiresAt) > Date.now());
  db.sessions.push(session);
  const userSessions = db.sessions.filter(item => item.username === user.username).sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
  while (userSessions.length > 8) {
    const expiredOldest = userSessions.shift();
    db.sessions = db.sessions.filter(item => item !== expiredOldest);
  }
  user.lastSeen = nowIso();
  saveDb();
  return { token, user: publicUser(user) };
}
function updatePresence(auth) {
  const now = nowIso();
  auth.user.lastSeen = now;
  auth.session.lastSeen = now;
  saveDb();
}
function isOnline(user) { return !!user?.lastSeen && Date.now() - Date.parse(user.lastSeen) <= 45_000; }
function expandMessage(message) {
  const sender = findUser(message.from);
  const recipient = findUser(message.to);
  return {
    id: message.id, body: message.body, createdAt: message.createdAt,
    sender: sender ? publicUser(sender) : { username: message.from, displayName: message.from },
    recipient: recipient ? publicUser(recipient) : { username: message.to, displayName: message.to }
  };
}
function snapshot(auth) {
  updatePresence(auth);
  const own = auth.user.username;
  const friends = db.friendships.filter(item => item.key === pairKey(own, item.a) || item.a === own || item.b === own)
    .filter(item => item.a === own || item.b === own)
    .map(item => findUser(item.a === own ? item.b : item.a))
    .filter(Boolean)
    .map(user => ({ ...publicUser(user), online: isOnline(user) }))
    .sort((a, b) => Number(b.online) - Number(a.online) || a.displayName.localeCompare(b.displayName));
  const incoming = db.friendRequests.filter(item => item.to === own && item.status === 'pending').map(item => ({
    id: item.id, createdAt: item.createdAt, user: publicUser(findUser(item.from))
  }));
  const outgoing = db.friendRequests.filter(item => item.from === own && item.status === 'pending').map(item => ({
    id: item.id, createdAt: item.createdAt, user: publicUser(findUser(item.to))
  }));
  return { user: publicUser(auth.user), friends, incoming, outgoing };
}

function startServer(options = {}) {
  if (server) return server;
  HOST = options.host || HOST;
  PORT = Number(options.port ?? PORT);
  DATA_DIR = options.dataDir || DATA_DIR;
  DATA_FILE = path.join(DATA_DIR, 'social-db.json');
  db = loadDb();
  const instance = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const route = `${req.method} ${url.pathname}`;
  if (!requestLimit(req, res, url.pathname)) return;

  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { ok: true, service: 'NEXA HUB Social', version: '2.0.0', users: db.users.length, time: nowIso() });
    }

    if (req.method === 'POST' && url.pathname === '/api/register') {
      const body = await readBody(req);
      const username = normalizeUsername(body.username);
      const password = typeof body.password === 'string' ? body.password : '';
      const displayName = cleanString(body.displayName || username, 24).replace(/\s+/g, ' ');
      if (!usernameValid(username)) return json(res, 400, { error: 'O usuário deve ter 3 a 20 caracteres: letras, números e _.' });
      if (password.length < 8 || password.length > 128) return json(res, 400, { error: 'A senha deve ter entre 8 e 128 caracteres.' });
      if (db.users.some(user => user.username === username)) return json(res, 409, { error: 'Esse nome de usuário já está em uso.' });
      const credentials = passwordHash(password);
      const user = { username, displayName: displayName || username, passwordSalt: credentials.salt, passwordHash: credentials.hash, createdAt: nowIso(), lastSeen: nowIso() };
      user.blocked = [];
      db.users.push(user);
      const session = createSession(user);
      return json(res, 201, session);
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const body = await readBody(req);
      const username = normalizeUsername(body.username);
      const user = findUser(username);
      const password = typeof body.password === 'string' ? body.password : '';
      if (!user || !password || !passwordMatches(password, user)) return json(res, 401, { error: 'Usuário ou senha incorretos.' });
      return json(res, 200, createSession(user));
    }

    if (req.method === 'GET' && url.pathname === '/api/me') {
      const auth = authenticated(req, res); if (!auth) return;
      updatePresence(auth);
      return json(res, 200, { user: publicUser(auth.user) });
    }

    if (req.method === 'POST' && url.pathname === '/api/logout') {
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
      db.sessions = db.sessions.filter(item => item.tokenHash !== hashToken(token));
      saveDb();
      return json(res, 200, { ok: true });
    }

    const auth = authenticated(req, res); if (!auth) return;
    const own = auth.user.username;

    if (req.method === 'POST' && url.pathname === '/api/presence') {
      updatePresence(auth);
      return json(res, 200, { ok: true, lastSeen: auth.user.lastSeen });
    }
    if (req.method === 'GET' && url.pathname === '/api/social') {
      return json(res, 200, snapshot(auth));
    }

    if (req.method === 'POST' && url.pathname === '/api/profile') {
      const body = await readBody(req);
      const displayName = cleanString(body.displayName, 24).replace(/\s+/g, ' ');
      if (displayName.length < 2) return json(res, 400, { error: 'O nome de exibição deve ter pelo menos 2 caracteres.' });
      auth.user.displayName = displayName;
      saveDb();
      return json(res, 200, { user: publicUser(auth.user) });
    }

    if (req.method === 'GET' && url.pathname === '/api/groups') {
      updatePresence(auth);
      const groups = db.groups.filter(group => group.members.includes(own)).map(group => ({
        id: group.id, name: group.name, owner: group.owner, createdAt: group.createdAt,
        memberCount: group.members.length,
        members: group.members.map(username => publicUser(findUser(username))).filter(Boolean)
      })).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return json(res, 200, { groups });
    }

    if (req.method === 'POST' && url.pathname === '/api/groups') {
      const body = await readBody(req);
      const name = cleanString(body.name, 40).replace(/\s+/g, ' ');
      if (name.length < 2) return json(res, 400, { error: 'O nome do grupo deve ter entre 2 e 40 caracteres.' });
      const inputMembers = Array.isArray(body.members) ? body.members : [];
      const members = [...new Set([own, ...inputMembers.map(normalizeUsername)])];
      if (members.length < 2) return json(res, 400, { error: 'Escolha pelo menos um amigo para o grupo.' });
      if (members.length > 25) return json(res, 400, { error: 'Um grupo pode ter no máximo 25 membros.' });
      for (const username of members) {
        if (!usernameValid(username) || !findUser(username)) return json(res, 400, { error: `Usuário inválido ou inexistente: ${username}` });
        if (username !== own && !areFriends(own, username)) return json(res, 403, { error: `Você precisa ser amigo de @${username} para incluí-lo no grupo.` });
        if (isBlocked(own, username) || isBlocked(username, own)) return json(res, 403, { error: `Não é possível incluir @${username} por causa das configurações de bloqueio.` });
      }
      if (db.groups.filter(group => group.owner === own).length >= 50) return json(res, 429, { error: 'Você já criou 50 grupos. Exclua um antes de criar outro.' });
      const group = { id: crypto.randomUUID(), name, owner: own, members, createdAt: nowIso() };
      db.groups.push(group); saveDb();
      return json(res, 201, { group: { id: group.id, name: group.name, owner: own, createdAt: group.createdAt, memberCount: group.members.length, members: members.map(username => publicUser(findUser(username))).filter(Boolean) } });
    }

    const groupMessagesMatch = url.pathname.match(/^\/api\/groups\/([0-9a-f-]+)\/messages$/i);
    if (req.method === 'GET' && groupMessagesMatch) {
      const group = db.groups.find(item => item.id === groupMessagesMatch[1] && item.members.includes(own));
      if (!group) return json(res, 404, { error: 'Grupo não encontrado ou você não faz parte dele.' });
      const after = Math.max(0, Number.parseInt(url.searchParams.get('after') || '0', 10) || 0);
      let messages = db.groupMessages.filter(item => item.groupId === group.id && item.id > after).sort((a, b) => a.id - b.id);
      if (after === 0 && messages.length > 100) messages = messages.slice(-100); else messages = messages.slice(0, 100);
      const expanded = messages.map(message => ({ id: message.id, groupId: message.groupId, body: message.body, createdAt: message.createdAt, sender: publicUser(findUser(message.from)) }));
      return json(res, 200, { messages: expanded, cursor: messages.length ? messages[messages.length - 1].id : after });
    }

    if (req.method === 'POST' && groupMessagesMatch) {
      const group = db.groups.find(item => item.id === groupMessagesMatch[1] && item.members.includes(own));
      if (!group) return json(res, 404, { error: 'Grupo não encontrado ou você não faz parte dele.' });
      const body = await readBody(req);
      const messageBody = typeof body.body === 'string' ? body.body.trim() : '';
      if (!messageBody || messageBody.length > 1000) return json(res, 400, { error: 'A mensagem deve ter entre 1 e 1000 caracteres.' });
      const message = { id: db.nextGroupMessageId++, groupId: group.id, from: own, body: messageBody, createdAt: nowIso() };
      db.groupMessages.push(message);
      if (db.groupMessages.length > 100_000) db.groupMessages.splice(0, db.groupMessages.length - 100_000);
      saveDb();
      return json(res, 201, { message: { id: message.id, groupId: message.groupId, body: message.body, createdAt: message.createdAt, sender: publicUser(auth.user) } });
    }

    const groupMemberMatch = url.pathname.match(/^\/api\/groups\/([0-9a-f-]+)\/members$/i);
    if (req.method === 'POST' && groupMemberMatch) {
      const group = db.groups.find(item => item.id === groupMemberMatch[1]);
      if (!group || group.owner !== own || !group.members.includes(own)) return json(res, 403, { error: 'Somente o criador do grupo pode adicionar membros.' });
      const body = await readBody(req); const username = normalizeUsername(body.username);
      if (!usernameValid(username) || !findUser(username)) return json(res, 404, { error: 'Usuário não encontrado.' });
      if (group.members.includes(username)) return json(res, 409, { error: 'Esse usuário já faz parte do grupo.' });
      if (!areFriends(own, username) || isBlocked(own, username) || isBlocked(username, own)) return json(res, 403, { error: 'Você precisa ser amigo desse usuário e não pode haver bloqueio.' });
      if (group.members.length >= 25) return json(res, 429, { error: 'O grupo já atingiu o limite de 25 membros.' });
      group.members.push(username); saveDb();
      return json(res, 200, { ok: true });
    }

    const groupMemberDeleteMatch = url.pathname.match(/^\/api\/groups\/([0-9a-f-]+)\/members\/([a-z0-9_]{3,20})$/i);
    if (req.method === 'DELETE' && groupMemberDeleteMatch) {
      const group = db.groups.find(item => item.id === groupMemberDeleteMatch[1]);
      const username = normalizeUsername(groupMemberDeleteMatch[2]);
      if (!group || group.owner !== own || !group.members.includes(own)) return json(res, 403, { error: 'Somente o criador do grupo pode remover membros.' });
      if (username === group.owner) return json(res, 400, { error: 'O criador não pode remover a si mesmo; exclua o grupo se necessário.' });
      group.members = group.members.filter(member => member !== username); saveDb();
      return json(res, 200, { ok: true });
    }

    const groupLeaveMatch = url.pathname.match(/^\/api\/groups\/([0-9a-f-]+)\/leave$/i);
    if (req.method === 'DELETE' && groupLeaveMatch) {
      const group = db.groups.find(item => item.id === groupLeaveMatch[1] && item.members.includes(own));
      if (!group) return json(res, 404, { error: 'Grupo não encontrado.' });
      if (group.owner === own) return json(res, 400, { error: 'O criador precisa excluir o grupo ou transferir a propriedade antes de sair.' });
      group.members = group.members.filter(member => member !== own); saveDb();
      return json(res, 200, { ok: true });
    }

    const groupDeleteMatch = url.pathname.match(/^\/api\/groups\/([0-9a-f-]+)$/i);
    if (req.method === 'DELETE' && groupDeleteMatch) {
      const index = db.groups.findIndex(item => item.id === groupDeleteMatch[1] && item.owner === own);
      if (index < 0) return json(res, 403, { error: 'Somente o criador do grupo pode excluí-lo.' });
      const [group] = db.groups.splice(index, 1);
      db.groupMessages = db.groupMessages.filter(item => item.groupId !== group.id);
      saveDb();
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/api/blocks') {
      const blocked = Array.isArray(auth.user.blocked) ? auth.user.blocked : [];
      return json(res, 200, { blocked: blocked.map(findUser).filter(Boolean).map(publicUser) });
    }

    if (req.method === 'POST' && url.pathname === '/api/blocks') {
      const body = await readBody(req);
      const username = normalizeUsername(body.username);
      if (!usernameValid(username) || username === own) return json(res, 400, { error: 'Usuário para bloqueio inválido.' });
      if (!findUser(username)) return json(res, 404, { error: 'Usuário não encontrado.' });
      auth.user.blocked ||= [];
      if (!auth.user.blocked.includes(username)) auth.user.blocked.push(username);
      db.friendships = db.friendships.filter(item => item.key !== pairKey(own, username));
      db.friendRequests = db.friendRequests.filter(item => !((item.from === own && item.to === username) || (item.from === username && item.to === own)));
      saveDb();
      return json(res, 200, { ok: true });
    }
    const unblockMatch = url.pathname.match(/^\/api\/blocks\/([a-z0-9_]{3,20})$/i);
    if (req.method === 'DELETE' && unblockMatch) {
      const username = normalizeUsername(unblockMatch[1]);
      auth.user.blocked = (auth.user.blocked || []).filter(item => item !== username);
      saveDb();
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/friend-requests') {
      const body = await readBody(req);
      const username = normalizeUsername(body.username);
      if (!usernameValid(username)) return json(res, 400, { error: 'Digite um usuário NEXA válido.' });
      if (username === own) return json(res, 400, { error: 'Você não pode adicionar a si mesmo.' });
      const target = findUser(username);
      if (!target) return json(res, 404, { error: 'Não encontramos esse usuário NEXA.' });
      if (isBlocked(own, username) || isBlocked(username, own)) return json(res, 403, { error: 'Uma das contas bloqueou a outra.' });
      if (areFriends(own, username)) return json(res, 409, { error: 'Vocês já são amigos.' });
      const reverse = db.friendRequests.find(item => item.from === username && item.to === own && item.status === 'pending');
      if (reverse) {
        db.friendRequests = db.friendRequests.filter(item => item.id !== reverse.id);
        db.friendships.push({ key: pairKey(own, username), a: [own, username].sort()[0], b: [own, username].sort()[1], createdAt: nowIso() });
        saveDb();
        return json(res, 200, { acceptedAutomatically: true, message: 'Solicitação recíproca aceita. Vocês agora são amigos.' });
      }
      if (db.friendRequests.some(item => item.from === own && item.to === username && item.status === 'pending')) return json(res, 409, { error: 'Você já enviou uma solicitação para essa pessoa.' });
      db.friendRequests.push({ id: crypto.randomUUID(), from: own, to: username, status: 'pending', createdAt: nowIso() });
      saveDb();
      return json(res, 201, { ok: true, message: `Solicitação enviada para ${target.displayName}.` });
    }

    const acceptMatch = url.pathname.match(/^\/api\/friend-requests\/([0-9a-f-]+)\/accept$/i);
    if (req.method === 'POST' && acceptMatch) {
      const request = db.friendRequests.find(item => item.id === acceptMatch[1] && item.to === own && item.status === 'pending');
      if (!request) return json(res, 404, { error: 'Essa solicitação não existe mais.' });
      db.friendRequests = db.friendRequests.filter(item => item.id !== request.id);
      const a = [own, request.from].sort()[0], b = [own, request.from].sort()[1];
      if (!areFriends(own, request.from)) db.friendships.push({ key: pairKey(own, request.from), a, b, createdAt: nowIso() });
      saveDb();
      return json(res, 200, { ok: true });
    }
    const requestMatch = url.pathname.match(/^\/api\/friend-requests\/([0-9a-f-]+)$/i);
    if (req.method === 'DELETE' && requestMatch) {
      const request = db.friendRequests.find(item => item.id === requestMatch[1] && (item.to === own || item.from === own) && item.status === 'pending');
      if (!request) return json(res, 404, { error: 'Essa solicitação não existe mais.' });
      db.friendRequests = db.friendRequests.filter(item => item.id !== request.id);
      saveDb();
      return json(res, 200, { ok: true });
    }

    const friendMatch = url.pathname.match(/^\/api\/friends\/([a-z0-9_]{3,20})$/i);
    if (req.method === 'DELETE' && friendMatch) {
      const username = normalizeUsername(friendMatch[1]);
      db.friendships = db.friendships.filter(item => item.key !== pairKey(own, username));
      db.messages = db.messages.filter(item => !((item.from === own && item.to === username) || (item.from === username && item.to === own)));
      saveDb();
      return json(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/api/messages') {
      const username = normalizeUsername(url.searchParams.get('with'));
      const after = Math.max(0, Number.parseInt(url.searchParams.get('after') || '0', 10) || 0);
      if (!username || !areFriends(own, username)) return json(res, 403, { error: 'Vocês precisam ser amigos para trocar mensagens.' });
      let messages = db.messages.filter(item => ((item.from === own && item.to === username) || (item.from === username && item.to === own)) && item.id > after).sort((a, b) => a.id - b.id);
      if (after === 0 && messages.length > 100) messages = messages.slice(-100);
      else messages = messages.slice(0, 100);
      return json(res, 200, { messages: messages.map(expandMessage), cursor: messages.length ? messages[messages.length - 1].id : after });
    }

    if (req.method === 'POST' && url.pathname === '/api/messages') {
      const body = await readBody(req);
      const to = normalizeUsername(body.to);
      const messageBody = typeof body.body === 'string' ? body.body.trim() : '';
      if (!to || isBlocked(own, to) || isBlocked(to, own) || !areFriends(own, to)) return json(res, 403, { error: 'Adicione essa pessoa como amiga antes de enviar mensagens.' });
      if (!messageBody || messageBody.length > 1000) return json(res, 400, { error: 'A mensagem deve ter entre 1 e 1000 caracteres.' });
      const message = { id: db.nextMessageId++, from: own, to, body: messageBody, createdAt: nowIso() };
      db.messages.push(message);
      // Retain up to 100,000 recent messages in this lightweight server.
      if (db.messages.length > 100_000) db.messages.splice(0, db.messages.length - 100_000);
      saveDb();
      return json(res, 201, { message: expandMessage(message) });
    }

    return json(res, 404, { error: `Rota não encontrada: ${route}` });
  } catch (error) {
    console.error(`[${route}]`, error.stack || error.message);
    return json(res, error.status || 500, { error: error.status ? error.message : 'Erro interno no servidor.' });
  }
});
  server = instance;
  instance.on('error', error => {
    console.error('Não foi possível iniciar o servidor:', error.message);
    if (error.code === 'EADDRINUSE') console.error(`A porta ${PORT} já está em uso. Altere NEXA_PORT ou feche o processo que a utiliza.`);
    if (require.main === module) process.exitCode = 1;
  });
  instance.listen(PORT, HOST, () => {
    console.log('');
    console.log('  NEXA HUB Social Server 2.0.0');
    console.log(`  Health check: http://127.0.0.1:${instance.address()?.port || PORT}/health`);
    console.log(`  Host: ${HOST} | Porta: ${instance.address()?.port || PORT}`);
    console.log(`  Dados: ${DATA_FILE}`);
    console.log('  Para acesso público, publique atrás de HTTPS. Não exponha HTTP aberto na internet.');
    console.log('');
  });
  return instance;
}

function shutdown() {
  if (!server) process.exit(0);
  const instance = server;
  server = null;
  instance.close(() => { if (require.main === module) process.exit(0); });
  if (require.main === module) setTimeout(() => process.exit(1), 3000).unref();
}
if (require.main === module) {
  startServer();
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
module.exports = { startServer };
