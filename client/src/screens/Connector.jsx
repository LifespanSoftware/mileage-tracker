// Settings → Claude connector: how to connect, what is connected, and what Claude has asked for.
import { useCallback, useEffect, useState } from 'react';
import { api, OfflineError } from '../api.js';
import { useToast } from '../ui.jsx';

const errText = (e) => (e instanceof OfflineError ? 'This needs an internet connection' : e.message);
const when = (iso) => (iso ? new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'never');
const STATUS = { applied: 'Approved and done', failed: "Approved, but it couldn't be done", rejected: 'Rejected', applying: 'Being applied' };
const KIND = { improvement: 'Improvement', feedback: 'Feedback', bug: 'Bug' };

export function ConnectorScreen({ back }) {
  const toast = useToast();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setData(await api('GET', '/connector')); setError(null); } catch (e) { setError(errText(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  /** Run one admin action, say how it went, and refresh. */
  async function act(fn, done) {
    setBusy(true);
    try {
      const res = await fn();
      const message = typeof done === 'function' ? done(res) : done;
      if (message) toast(message.text ?? message, message.kind);
    } catch (e) { toast(errText(e), 'error'); } finally { setBusy(false); load(); }
  }

  const url = data && (data.url.startsWith('http') ? data.url : `${location.origin}${data.url}`);
  const pending = data?.requests.filter((r) => r.status === 'pending') || [];
  const decided = data?.requests.filter((r) => r.status !== 'pending') || [];
  const fresh = data?.suggestions.filter((s) => s.status === 'new') || [];
  const added = data?.suggestions.filter((s) => s.status === 'added') || [];

  return (
    <div className="screen">
      <header className="screen-head">
        <button type="button" className="back" onClick={back}>Settings</button>
        <h1>Claude connector</h1>
      </header>
      <p className="lede">Lets Claude look at this app's status and errors, suggest improvements, and ask for changes that you approve here.</p>
      {error && <p className="notice notice-warn">{error}</p>}
      {!data && !error && <p className="muted">Loading…</p>}
      {data && (
        <>
          <section className="panel">
            <h2 className="panel-title">Connect</h2>
            <p className="muted small">In Claude, add a custom connector with this address. Claude opens a Mileage Tracker sign-in page; sign in as an administrator to connect. There is no token to copy.</p>
            <p className="secret num" data-testid="connector-url">{url}</p>
            <button type="button" className="btn btn-quiet" onClick={() => navigator.clipboard.writeText(url).then(() => toast('Address copied'), () => toast("Couldn't copy. Select the address instead.", 'error'))}>Copy address</button>
          </section>

          <section className="panel">
            <h2 className="panel-title">What Claude may do</h2>
            <p className="muted small">Connected, Claude can always read the status, errors, activity log, backups and list of users. It never sees journeys, fuel or receipts.</p>
            <label className="check">
              <input type="checkbox" checked={data.allowChanges} disabled={busy}
                onChange={(e) => act(() => api('PUT', '/connector/settings', { allowChanges: e.target.checked }), null)} />
              <span>Let Claude suggest and request changes</span>
            </label>
            <p className="muted small">A requested change does nothing until an administrator approves it below.</p>
          </section>

          <section className="list-section">
            <div className="list-head"><h2>Waiting for you</h2></div>
            {pending.length === 0 && <p className="muted pad">Nothing is waiting for approval.</p>}
            <ul className="activity">
              {pending.map((r) => (
                <li key={r.id}>
                  <span><strong>{r.summary}</strong></span>
                  {r.reason && <span className="small">Why: {r.reason}</span>}
                  <span className="muted small">Asked {when(r.requestedAt)} through {r.requestedBy}</span>
                  <div className="btn-row wrap">
                    <button type="button" className="btn btn-primary btn-small" disabled={busy}
                      onClick={() => act(() => api('POST', `/connector/requests/${r.id}/approve`), ({ request }) => (request.status === 'applied'
                        ? `Done. ${request.result}` : { text: `Approved, but it couldn't be done: ${request.result}`, kind: 'error' }))}>Approve</button>
                    <button type="button" className="btn btn-quiet btn-small" disabled={busy}
                      onClick={() => act(() => api('POST', `/connector/requests/${r.id}/reject`), 'Rejected. Nothing was changed.')}>Reject</button>
                  </div>
                </li>
              ))}
            </ul>
          </section>

          <section className="list-section">
            <div className="list-head"><h2>Suggestions for the roadmap</h2></div>
            {fresh.length === 0 && <p className="muted pad">No new suggestions.</p>}
            {fresh.length > 0 && <p className="muted small">Ask Claude, working in the repository, to add these to ROADMAP.md. It marks each one as added when it has.</p>}
            <ul className="activity">
              {fresh.map((s) => (
                <li key={s.id}>
                  <span><strong>{s.title}</strong> <em className="tag">{KIND[s.kind] || s.kind}</em></span>
                  {s.detail && <span className="small">{s.detail}</span>}
                  <span className="muted small">{when(s.createdAt)}, {s.suggestedBy}</span>
                  <div className="btn-row wrap">
                    <button type="button" className="btn btn-quiet btn-small" disabled={busy}
                      onClick={() => act(() => api('POST', `/connector/suggestions/${s.id}/added`), 'Marked as added')}>It's in the roadmap</button>
                    <button type="button" className="btn btn-danger-quiet btn-small" disabled={busy}
                      onClick={() => act(() => api('POST', `/connector/suggestions/${s.id}/dismiss`), 'Dismissed')}>Dismiss</button>
                  </div>
                </li>
              ))}
            </ul>
            {added.length > 0 && <p className="muted small mt-s">{added.length} earlier {added.length === 1 ? 'suggestion is' : 'suggestions are'} already in the roadmap.</p>}
          </section>

          <section className="list-section">
            <div className="list-head"><h2>Connected</h2></div>
            {data.connections.length === 0 && <p className="muted pad">Claude isn't connected.</p>}
            <ul className="activity">
              {data.connections.map((c) => (
                <li key={c.id}>
                  <span><strong>{c.name}</strong></span>
                  <span className="muted small">Connected by {c.connectedBy} on {when(c.connectedAt)}. Last used {when(c.lastUsedAt)}.</span>
                  <div className="btn-row wrap">
                    <button type="button" className="btn btn-danger-quiet btn-small" disabled={busy}
                      onClick={() => { if (confirm(`Disconnect ${c.name}? It will have to sign in again to reconnect.`)) act(() => api('DELETE', `/connector/connections/${c.id}`), 'Disconnected'); }}>Disconnect</button>
                  </div>
                </li>
              ))}
            </ul>
          </section>

          {decided.length > 0 && (
            <section className="list-section">
              <div className="list-head"><h2>Earlier requests</h2></div>
              <ul className="activity">
                {decided.map((r) => (
                  <li key={r.id}>
                    <span>{r.summary}</span>
                    <span className={`small ${r.status === 'failed' ? 'warn-text' : 'muted'}`}>
                      {STATUS[r.status] || r.status}{r.result && r.status !== 'rejected' ? `: ${r.result}` : ''}. {r.decidedBy}, {when(r.decidedAt)}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
    </div>
  );
}
