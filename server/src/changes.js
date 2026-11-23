// Changes Claude can ask for through the connector. Each kind checks the request against the current
// state and writes the summary an admin reads; nothing is applied until an admin approves it in the app.
import { query } from './db.js';
import { HttpError } from './http.js';
import { audit } from './audit.js';
import { runBackup, getKeep, setKeep, pruneBackups, MAX_KEEP, exclusive, defaultTargets } from './backup.js';

const MAX_PENDING = 20;
const bad = (message) => new HttpError(400, message);

async function findUser(username) {
  const { rows } = await query('SELECT * FROM users WHERE username=$1', [String(username ?? '').trim().toLowerCase()]);
  if (!rows[0]) throw bad(`There is no account called "${username}"`);
  return rows[0];
}

export const KINDS = {
  run_backup: {
    async prepare() {
      return { params: {}, summary: `Run a backup now (to ${defaultTargets().join(' and ')})` };
    },
    async apply(params, admin, ip) {
      return exclusive(async () => {
        const results = await runBackup({ createdBy: `${admin.username} (asked for by Claude)` });
        await audit(admin, 'backup.create', { target: results[0]?.filename || '', detail: { results: results.map((r) => `${r.target}: ${r.status}`) }, ip });
        const failed = results.filter((r) => r.status !== 'ok');
        if (failed.length) throw new Error(failed.map((f) => `${f.target}: ${f.error}`).join('; '));
        return `Backup made: ${results[0].filename}`;
      });
    },
  },

  set_backups_to_keep: {
    async prepare({ keep }) {
      if (!Number.isInteger(keep) || keep < 1 || keep > MAX_KEEP) throw bad(`keep must be a whole number from 1 to ${MAX_KEEP}`);
      const now = await getKeep();
      if (keep === now) throw bad(`Backups to keep is already ${now}`);
      return {
        params: { keep },
        summary: `Keep the newest ${keep} backups in each place instead of ${now}${keep < now ? '. Older backups are deleted straight away and cannot be brought back' : ''}`,
      };
    },
    async apply({ keep }, admin, ip) {
      return exclusive(async () => {
        const before = await getKeep();
        await setKeep(keep);
        const removed = await pruneBackups();
        await audit(admin, 'backup.settings', { detail: { keep, before, removed }, ip });
        return `Now keeping ${keep}${removed ? `; ${removed} older backup${removed === 1 ? '' : 's'} deleted` : ''}`;
      });
    },
  },

  set_user_sign_in: {
    async prepare({ username, allowed }) {
      if (typeof allowed !== 'boolean') throw bad('allowed must be true or false');
      const u = await findUser(username);
      if (u.is_active === allowed) throw bad(`${u.username} ${allowed ? 'can already sign in' : 'is already blocked from signing in'}`);
      return {
        params: { username: u.username, allowed },
        summary: allowed
          ? `Let ${u.username} sign in again`
          : `Block ${u.username} from signing in and sign them out everywhere. Their journeys and other records are kept`,
      };
    },
    async apply({ username, allowed }, admin, ip) {
      const u = await findUser(username);
      if (u.is_active === allowed) return 'Nothing to change: that was already the case';
      if (!allowed) {
        if (u.id === admin.id) throw new Error("You can't block your own account");
        const { rows } = await query('SELECT count(*)::int AS n FROM users WHERE is_admin AND is_active AND id <> $1', [u.id]);
        if (u.is_admin && rows[0].n === 0) throw new Error('There must always be at least one active admin');
      }
      await query('UPDATE users SET is_active=$1, token_version=token_version+$2, updated_at=now() WHERE id=$3', [allowed, allowed ? 0 : 1, u.id]);
      await audit(admin, 'user.update', { target: u.username, detail: { changes: [allowed ? 'sign-in allowed' : 'sign-in blocked'] }, ip });
      return allowed ? `${u.username} can sign in` : `${u.username} is blocked and signed out`;
    },
  },

  resolve_error: {
    async prepare({ error_id: id }) {
      const { rows } = await query('SELECT id, message, resolved_at FROM error_log WHERE id=$1', [Number(id) || 0]);
      if (!rows[0]) throw bad(`There is no error with id ${id}`);
      if (rows[0].resolved_at) throw bad('That error is already marked resolved');
      return { params: { error_id: Number(rows[0].id) }, summary: `Mark error ${rows[0].id} as resolved: "${rows[0].message.slice(0, 160)}". It comes back if it happens again` };
    },
    async apply({ error_id: id }) {
      await query('UPDATE error_log SET resolved_at=now() WHERE id=$1 AND resolved_at IS NULL', [id]);
      return 'Marked resolved';
    },
  },
};

/** Record a request from the connector. Returns the stored row. */
export async function requestChange(kind, input, reason, requestedBy) {
  const { rows: [{ n }] } = await query("SELECT count(*)::int AS n FROM change_requests WHERE status='pending'");
  if (n >= MAX_PENDING) throw bad(`There are already ${MAX_PENDING} requests waiting for an admin. Wait for those to be decided.`);
  const { params, summary } = await KINDS[kind].prepare(input || {});
  const { rows } = await query(
    `INSERT INTO change_requests (kind, params, summary, reason, requested_by) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [kind, JSON.stringify(params), summary, String(reason ?? '').slice(0, 1000), requestedBy]);
  await audit({ username: requestedBy }, 'change.request', { target: summary });
  return rows[0];
}

/** An admin's decision. Approving applies exactly the stored parameters; the outcome is kept on the request. */
export async function decideChange(id, approve, admin, ip) {
  // Claiming the row first means two admins (or two taps) can't apply the same request twice.
  const { rows } = await query(
    `UPDATE change_requests SET status=$2, decided_by=$3, decided_at=now() WHERE id=$1 AND status='pending' RETURNING *`,
    [Number(id) || 0, approve ? 'applying' : 'rejected', admin.username]);
  const request = rows[0];
  if (!request) throw new HttpError(404, 'That request has already been decided');
  if (!approve) {
    await audit(admin, 'change.reject', { target: request.summary, ip });
    return { ...request };
  }
  let status = 'applied';
  let result;
  try {
    result = await KINDS[request.kind].apply(request.params, admin, ip);
  } catch (e) {
    status = 'failed';
    result = e.message;
  }
  await query('UPDATE change_requests SET status=$2, result=$3 WHERE id=$1', [request.id, status, result]);
  await audit(admin, 'change.approve', { target: request.summary, detail: { outcome: status, result }, ip });
  return { ...request, status, result };
}

export const changeOut = (r) => ({
  id: Number(r.id), kind: r.kind, summary: r.summary, reason: r.reason, status: r.status, result: r.result,
  requestedBy: r.requested_by, requestedAt: r.requested_at, decidedBy: r.decided_by, decidedAt: r.decided_at,
});
