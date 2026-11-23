// Tests for the Claude connector: sign-in by web page (OAuth), the MCP tools, the error log,
// change requests that need an admin's approval, and suggestions.
// Start the server on an EMPTY database with ADMIN_USERNAME=admin and ADMIN_PASSWORD=adminpass123, then:
//   BASE=http://localhost:3000 node server/test/connector.test.mjs
import crypto from 'node:crypto';

const B = process.env.BASE || 'http://localhost:3000';
let fails = 0;
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
async function call(method, path, body, token, form) {
  const headers = token ? { authorization: 'Bearer ' + token } : {};
  let payload;
  if (form) { headers['content-type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(form).toString(); }
  else if (body) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
  const r = await fetch(B + path, { method, headers, body: payload, redirect: 'manual' });
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; }
  return { s: r.status, j, h: r.headers };
}
let rpcId = 0;
const rpc = (token, method, params) => call('POST', '/mcp', { jsonrpc: '2.0', id: ++rpcId, method, params }, token);
async function tool(token, name, args = {}) {
  const r = await rpc(token, 'tools/call', { name, arguments: args });
  const text = r.j.result?.content?.[0]?.text ?? '';
  let data; try { data = JSON.parse(text); } catch { data = null; }
  return { isError: !!r.j.result?.isError, text, data };
}

const admin = (await call('POST', '/api/auth/login', { username: 'admin', password: 'adminpass123' })).j.token;
await call('POST', '/api/users', { username: 'dave', password: 'davepass1' }, admin);
const dave = (await call('POST', '/api/auth/login', { username: 'dave', password: 'davepass1' })).j.token;

// ── Discovery ──
let r = await call('POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
const challenge = r.h.get('www-authenticate') || '';
ok(r.s === 401 && challenge.includes(`resource_metadata="${B}/.well-known/oauth-protected-resource"`), 'the connector refuses to talk without signing in, and says where to start');
ok((await call('POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' }, admin)).s === 401, "the app's own sign-in token is not accepted by the connector");
r = await call('GET', '/.well-known/oauth-protected-resource');
ok(r.j.resource === `${B}/mcp` && r.j.authorization_servers[0] === B, 'protected resource metadata');
const meta = (await call('GET', '/.well-known/oauth-authorization-server')).j;
ok(meta.issuer === B && meta.authorization_endpoint === `${B}/oauth/authorize` && meta.token_endpoint === `${B}/oauth/token`
  && meta.registration_endpoint === `${B}/oauth/register` && meta.code_challenge_methods_supported.includes('S256'), 'authorization server metadata');

// ── Registration ──
const redirect = 'http://localhost:9999/callback';
ok((await call('POST', '/oauth/register', { client_name: 'Evil', redirect_uris: ['http://evil.example/cb'] })).s === 400, 'plain http redirect addresses are refused');
ok((await call('POST', '/oauth/register', { client_name: 'None' })).s === 400, 'a client must register where it returns to');
r = await call('POST', '/oauth/register', { client_name: 'Claude <b>', redirect_uris: [redirect] });
const clientId = r.j.client_id;
ok(r.s === 201 && clientId && r.j.token_endpoint_auth_method === 'none', 'client registered');

// ── The sign-in page ──
const verifier = crypto.randomBytes(32).toString('base64url');
const auth = {
  response_type: 'code', client_id: clientId, redirect_uri: redirect, state: 'xyz 123',
  code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
};
const qs = (o) => new URLSearchParams(o).toString();
r = await call('GET', '/oauth/authorize?' + qs(auth));
ok(r.s === 200 && r.j.includes('Claude &lt;b&gt;') && !r.j.includes('<b>') && r.j.includes('localhost:9999') && r.j.includes('name="password"'),
  'sign-in page names who is asking, safely');
ok((r.h.get('content-security-policy') || '').includes("form-action 'self' http://localhost:9999"), 'the page may only send its form here or back to the app that asked');
r = await call('GET', '/oauth/authorize?' + qs({ ...auth, client_id: 'nope' }));
ok(r.s === 400 && typeof r.j === 'string' && !r.h.get('location'), 'unknown client: an error page, never a redirect');
r = await call('GET', '/oauth/authorize?' + qs({ ...auth, redirect_uri: 'https://evil.example/cb' }));
ok(r.s === 400 && !r.h.get('location'), 'unregistered return address: an error page, never a redirect');
r = await call('GET', '/oauth/authorize?' + qs({ ...auth, redirect_uri: 'http://localhost:51234/callback' }));
ok(r.s === 200, 'a localhost return address may use any port');
r = await call('GET', '/oauth/authorize?' + qs({ ...auth, code_challenge: '' }));
ok(r.s === 303 && new URL(r.h.get('location')).searchParams.get('error') === 'invalid_request', 'PKCE is required');

const signIn = (username, password) => call('POST', '/oauth/authorize', null, null, { ...auth, username, password });
r = await signIn('admin', 'wrong-password');
ok(r.s === 401 && r.j.includes('Wrong username or password') && !r.h.get('location'), 'wrong password: back to the page with a message');
r = await signIn('dave', 'davepass1');
ok(r.s === 401 && r.j.includes('Only administrators can connect'), 'only admins can connect');
r = await signIn('Admin', 'adminpass123');
let back = new URL(r.h.get('location') || 'http://none');
ok(r.s === 303 && back.origin + back.pathname === redirect && back.searchParams.get('state') === 'xyz 123' && back.searchParams.get('code'), 'admin signs in and is sent back with a code');

// ── Tokens ──
const exchange = (code, v = verifier) => call('POST', '/oauth/token', null, null, { grant_type: 'authorization_code', code, code_verifier: v, client_id: clientId, redirect_uri: redirect });
ok((await exchange(back.searchParams.get('code'), 'wrong-verifier-wrong-verifier-wrong-verifier-wrong')).j.error === 'invalid_grant', 'the code is useless without the PKCE verifier');
ok((await exchange(back.searchParams.get('code'))).j.error === 'invalid_grant', 'a code works once, even after a failed try');
back = new URL((await signIn('admin', 'adminpass123')).h.get('location'));
r = await exchange(back.searchParams.get('code'));
ok(r.s === 200 && r.j.token_type === 'Bearer' && r.j.access_token && r.j.refresh_token && r.j.expires_in === 3600, 'code exchanged for tokens');
let { access_token: access, refresh_token: refresh } = r.j;

// ── MCP ──
r = await rpc(access, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
ok(r.s === 200 && r.j.result.protocolVersion === '2025-06-18' && r.j.result.serverInfo.name === 'mileage-tracker' && r.j.result.instructions.includes('approve'), 'initialize');
ok((await call('POST', '/mcp', { jsonrpc: '2.0', method: 'notifications/initialized' }, access)).s === 202, 'notifications are accepted without a reply');
r = await rpc(access, 'tools/list');
const names = r.j.result.tools.map((t) => t.name);
ok(['app_status', 'recent_errors', 'error_details', 'request_backup', 'suggest_improvement', 'list_suggestions'].every((n) => names.includes(n))
  && r.j.result.tools.every((t) => t.description && t.inputSchema.type === 'object'), 'tools are listed with descriptions and schemas');
ok((await rpc(access, 'nope/nope')).j.error.code === -32601, 'unknown method');
let t = await tool(access, 'app_status');
ok(!t.isError && t.data.users.total === 2 && t.data.unresolvedErrors === 0 && t.data.claudeMaySuggestAndRequestChanges === false && t.data.connectedAs.includes('admin'), 'app_status');
t = await tool(access, 'users');
ok(t.data.users.length === 2 && !t.text.includes('password') && !t.text.includes('totp'), 'users are listed without secrets');
ok((await tool(access, 'no_such_tool')).isError, 'unknown tool is an error result');

// ── Errors reported by the app on a device ──
ok((await call('POST', '/api/errors', { message: 'x' })).s === 401, 'only signed-in devices report errors');
const crash = { message: "Cannot read properties of undefined (reading 'miles')", stack: "TypeError: Cannot read properties of undefined (reading 'miles')\n    at TripRow (main.js:1:2)", version: '1.2.0', page: 'trips' };
await call('POST', '/api/errors', crash, dave);
await call('POST', '/api/errors', crash, dave);
await call('POST', '/api/errors', { message: 'Something else', stack: '' }, dave);
t = await tool(access, 'recent_errors');
const seen = t.data.errors.find((e) => e.message === crash.message);
ok(t.data.errors.length === 2 && seen.times === 2 && seen.source === 'app' && !seen.resolved, 'errors from the app are listed, with repeats counted');
t = await tool(access, 'error_details', { id: seen.id });
ok(t.data.stack.includes('TripRow') && t.data.context.user === 'dave' && t.data.context.page === 'trips', 'error details include the stack and what was happening');
ok((await tool(access, 'error_details', { id: 999999 })).isError, 'unknown error id');

// ── Changes need an admin's approval ──
t = await tool(access, 'request_backups_to_keep', { keep: 5, reason: 'Disk is filling up' });
ok(t.isError && t.text.includes('Let Claude suggest and request changes'), 'requests are refused until an admin allows them');
ok((await tool(access, 'suggest_improvement', { title: 'x', detail: 'y' })).isError, 'so are suggestions');
ok((await call('PUT', '/api/connector/settings', { allowChanges: true }, dave)).s === 403, 'only admins change connector settings');
await call('PUT', '/api/connector/settings', { allowChanges: true }, admin);
ok((await tool(access, 'request_backups_to_keep', { keep: 5 })).isError, 'a request needs a reason');
ok((await tool(access, 'request_backups_to_keep', { keep: 0, reason: 'x' })).isError, 'bad values are refused when asked, not when approved');
ok((await tool(access, 'request_user_sign_in', { username: 'nobody', allowed: false, reason: 'x' })).isError, 'unknown account refused');
t = await tool(access, 'request_backups_to_keep', { keep: 5, reason: 'Disk is filling up' });
const keepReq = t.data.request;
ok(!t.isError && keepReq.status === 'pending' && keepReq.summary.includes('newest 5') && keepReq.summary.includes('deleted straight away'), 'request filed, with a plain summary of what would happen');
ok((await call('GET', '/api/backups', null, admin)).j.config.keep === 30, 'nothing changes while the request waits');
const blockReq = (await tool(access, 'request_user_sign_in', { username: 'Dave', allowed: false, reason: 'Left the company' })).data.request;
const resolveReq = (await tool(access, 'request_error_resolved', { error_id: seen.id, reason: 'Fixed in 1.2.1' })).data.request;
r = await call('GET', '/api/connector', null, admin);
ok(r.j.allowChanges && r.j.requests.filter((x) => x.status === 'pending').length === 3 && r.j.connections.length === 1 && r.j.connections[0].connectedBy === 'admin',
  'the admin screen lists the connection and the waiting requests');
ok((await call('GET', '/api/connector', null, dave)).s === 403 && (await call('POST', `/api/connector/requests/${keepReq.id}/approve`, null, dave)).s === 403, 'only admins see and decide requests');

r = await call('POST', `/api/connector/requests/${keepReq.id}/approve`, null, admin);
ok(r.j.request.status === 'applied' && (await call('GET', '/api/backups', null, admin)).j.config.keep === 5, 'approving applies the change');
ok((await call('POST', `/api/connector/requests/${keepReq.id}/approve`, null, admin)).s === 404, 'a request can only be decided once');
r = await call('POST', `/api/connector/requests/${blockReq.id}/reject`, null, admin);
ok(r.j.request.status === 'rejected' && (await call('GET', '/api/auth/me', null, dave)).s === 200, 'rejecting changes nothing');
await call('POST', `/api/connector/requests/${resolveReq.id}/approve`, null, admin);
ok((await tool(access, 'recent_errors')).data.errors.length === 1, 'an approved resolve hides the error');
await call('POST', '/api/errors', crash, dave);
ok((await tool(access, 'recent_errors')).data.errors.some((e) => e.id === seen.id && e.times === 3), 'and it comes back if it happens again');
t = await tool(access, 'list_change_requests');
ok(t.data.requests.map((x) => x.status).sort().join() === 'applied,applied,rejected' && t.data.requests.every((x) => x.decidedBy === 'admin'), 'Claude can see what was decided');
// Approve a block for real, then check its safeguards.
const block2 = (await tool(access, 'request_user_sign_in', { username: 'dave', allowed: false, reason: 'Left' })).data.request;
r = await call('POST', `/api/connector/requests/${block2.id}/approve`, null, admin);
ok(r.j.request.status === 'applied' && (await call('GET', '/api/auth/me', null, dave)).s === 401, 'an approved block signs the person out');
const self = (await tool(access, 'request_user_sign_in', { username: 'admin', allowed: false, reason: 'test' })).data.request;
r = await call('POST', `/api/connector/requests/${self.id}/approve`, null, admin);
ok(r.j.request.status === 'failed' && /own account/.test(r.j.request.result) && (await call('GET', '/api/auth/me', null, admin)).s === 200, "an approval that can't be carried out is recorded as failed");
const log = (await tool(access, 'activity_log')).data.entries.map((e) => e.action);
ok(['connector.connect', 'connector.settings', 'change.request', 'change.approve', 'change.reject', 'backup.settings', 'user.update'].every((a) => log.includes(a)), 'all of it is in the activity log');

// ── Suggestions for the roadmap ──
t = await tool(access, 'suggest_improvement', { title: 'Warn before the backup folder fills up', detail: 'Backups failed silently when the disk was full.', kind: 'improvement' });
const sugId = t.data.id;
await tool(access, 'suggest_improvement', { title: 'Second idea', detail: 'More.' });
ok(!t.isError && sugId && (await tool(access, 'suggest_improvement', { title: ' ', detail: 'x' })).isError, 'suggestion saved; a title is required');
ok((await tool(access, 'list_suggestions')).data.suggestions.length === 2, 'new suggestions are listed');
ok((await tool(access, 'mark_suggestion_added', { id: sugId })).data.status === 'added' && (await tool(access, 'mark_suggestion_added', { id: sugId })).isError, 'marked as added to the roadmap, once');
t = await tool(access, 'list_suggestions');
ok(t.data.suggestions.length === 1 && t.data.suggestions[0].title === 'Second idea', 'added suggestions leave the to-do list');
r = await call('POST', `/api/connector/suggestions/${t.data.suggestions[0].id}/dismiss`, null, admin);
ok(r.j.suggestion.status === 'dismissed' && (await tool(access, 'list_suggestions')).data.suggestions.length === 0
  && (await call('GET', '/api/connector', null, admin)).j.suggestions.length === 1, 'an admin can dismiss a suggestion');

// ── Refreshing and disconnecting ──
r = await call('POST', '/oauth/token', null, null, { grant_type: 'refresh_token', refresh_token: refresh, client_id: clientId });
ok(r.s === 200 && r.j.access_token !== access, 'refresh gives new tokens');
ok((await rpc(access, 'ping')).s === 401 && (await rpc(r.j.access_token, 'ping')).s === 200, 'the old access token stops working');
ok((await call('POST', '/oauth/token', null, null, { grant_type: 'refresh_token', refresh_token: refresh, client_id: clientId })).j.error === 'invalid_grant', 'a refresh token works once');
access = r.j.access_token; refresh = r.j.refresh_token;
const conn = (await call('GET', '/api/connector', null, admin)).j.connections[0];
ok((await call('DELETE', `/api/connector/connections/${conn.id}`, null, admin)).s === 200 && (await rpc(access, 'ping')).s === 401, 'an admin can disconnect Claude');
ok((await call('POST', '/oauth/token', null, null, { grant_type: 'refresh_token', refresh_token: refresh, client_id: clientId })).j.error === 'invalid_grant', 'and it cannot reconnect without signing in again');

console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exitCode = fails ? 1 : 0;
