// The error log: problems on the server, in background jobs and in the app on people's devices.
import crypto from 'node:crypto';
import { query } from './db.js';

const clip = (v, max) => String(v ?? '').slice(0, max);

/**
 * Record a problem. Repeats of the same one (same source, message and place in the code) are counted
 * on one row, and bring it back if it had been marked resolved. Never throws.
 */
export async function logError(source, error, context = {}) {
  try {
    const message = clip(error?.message ?? error, 500) || 'Unknown error';
    const stack = clip(error?.stack, 4000);
    const where = stack.split('\n').find((l) => /^\s*at /.test(l)) || '';
    const fingerprint = crypto.createHash('sha256').update(`${source}\n${message}\n${where.trim()}`).digest('hex');
    await query(
      `INSERT INTO error_log (fingerprint, source, message, stack, context) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (fingerprint) DO UPDATE SET count = error_log.count + 1, last_at = now(), resolved_at = NULL,
         stack = EXCLUDED.stack, context = EXCLUDED.context`,
      [fingerprint, source, message, stack, JSON.stringify(context)]);
  } catch (e) {
    console.error('Could not write to the error log:', e.message);
  }
}
