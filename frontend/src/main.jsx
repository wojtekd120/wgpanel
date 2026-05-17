import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Circle, KeyRound, LogOut, Plus, RefreshCw, ShieldOff, Trash2, X } from 'lucide-react'
import './styles.css'

const friendlyError = (body, fallback = 'Something went wrong. Please try again.') => {
  const detail = body?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const first = detail[0]
    const field = first?.loc?.[first.loc.length - 1]
    if (field === 'name') return 'Peer name is required'
    if (field === 'expires_at') return 'Invalid expiration date'
    if (typeof first?.msg === 'string') return first.msg.replace('Value error, ', '')
  }
  return fallback
}

const api = async (path, options = {}) => {
  const response = await fetch(`/api${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(friendlyError(body))
  }
  return response.json()
}

const formatDate = (value) => value ? new Date(value).toLocaleString() : 'none'
const formatBytes = (value = 0) => `${value} B`

function Login({ onLogin }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api('/login', { method: 'POST', body: JSON.stringify({ password }) })
      onLogin()
    } catch (err) {
      setError(err.message || 'Unable to sign in')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="auth-shell">
      <form className="login-panel" onSubmit={submit}>
        <div className="brand-row">
          <KeyRound size={24} />
          <h1>WGPanel</h1>
        </div>
        <input
          type="password"
          autoFocus
          placeholder="Admin password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />
        {error && <p className="error">{error}</p>}
        <button disabled={busy}>{busy ? 'Signing in...' : 'Sign in'}</button>
      </form>
    </main>
  )
}

function App() {
  const [authed, setAuthed] = useState(true)
  const [dashboard, setDashboard] = useState(null)
  const [peers, setPeers] = useState([])
  const [banner, setBanner] = useState('')
  const [result, setResult] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [form, setForm] = useState({ name: '', expires_at: '', dry_run: false })
  const [edit, setEdit] = useState({ name: '', notes: '', expires_at: '' })

  const load = async () => {
    try {
      const [dash, peerRows] = await Promise.all([api('/dashboard'), api('/peers')])
      setDashboard(dash)
      setPeers(peerRows)
      setAuthed(true)
      if (!selectedId && peerRows.length) setSelectedId(peerRows[0].id)
    } catch (err) {
      if (err.message === 'Not authenticated') setAuthed(false)
      else setBanner(err.message || 'Unable to load WGPanel data')
    }
  }

  useEffect(() => {
    load()
  }, [])

  const statusByKey = useMemo(() => new Map((dashboard?.peers || []).map((peer) => [peer.public_key, peer])), [dashboard])
  const selectedPeer = peers.find((peer) => peer.id === selectedId)
  const selectedStatus = selectedPeer ? statusByKey.get(selectedPeer.public_key) : null

  useEffect(() => {
    if (selectedPeer) {
      setEdit({
        name: selectedPeer.name,
        notes: selectedPeer.notes || '',
        expires_at: selectedPeer.expires_at ? selectedPeer.expires_at.slice(0, 16) : '',
      })
    }
  }, [selectedPeer?.id])

  const createPeer = async (event) => {
    event.preventDefault()
    setBanner('')
    if (!form.name.trim()) {
      setBanner('Peer name is required')
      return
    }
    let expiresAt = null
    if (form.expires_at) {
      const parsed = new Date(form.expires_at)
      if (Number.isNaN(parsed.getTime())) {
        setBanner('Invalid expiration date')
        return
      }
      expiresAt = parsed.toISOString()
    }
    try {
      const created = await api('/peers', {
        method: 'POST',
        body: JSON.stringify({ name: form.name.trim(), dry_run: form.dry_run, expires_at: expiresAt }),
      })
      setResult(created)
      setSelectedId(created.peer.id || selectedId)
      setForm({ name: '', expires_at: '', dry_run: false })
      setBanner(created.dry_run ? 'Dry run generated successfully' : 'Peer created successfully')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to create peer')
    }
  }

  const togglePeer = async (peer) => {
    setBanner('')
    try {
      const updated = await api(`/peers/${peer.id}/toggle`, { method: 'POST' })
      setBanner(updated.disabled ? 'Peer disabled' : 'Peer enabled')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to update peer state')
    }
  }

  const saveMetadata = async () => {
    if (!selectedPeer) return
    setBanner('')
    if (!edit.name.trim()) {
      setBanner('Peer name is required')
      return
    }
    try {
      await api(`/peers/${selectedPeer.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: edit.name.trim(),
          notes: edit.notes,
          expires_at: edit.expires_at ? new Date(edit.expires_at).toISOString() : null,
        }),
      })
      setBanner('Peer details saved')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to save peer details')
    }
  }

  const deletePeer = async () => {
    if (!deleteTarget) return
    setBanner('')
    try {
      await api(`/peers/${deleteTarget.id}`, { method: 'DELETE' })
      setDeleteTarget(null)
      setSelectedId(null)
      setBanner('Peer deleted')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to delete peer')
    }
  }

  const logout = async () => {
    await api('/logout', { method: 'POST' })
    setAuthed(false)
  }

  if (!authed) return <Login onLogin={load} />

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <h1>WGPanel</h1>
          <p>Interface {dashboard?.interface || 'wg0'}</p>
        </div>
        <div className="actions">
          <button className="icon-button" onClick={load} title="Refresh"><RefreshCw size={18} /></button>
          <button className="icon-button" onClick={logout} title="Logout"><LogOut size={18} /></button>
        </div>
      </header>

      {banner && <div className="banner">{banner}</div>}

      <section className="stats">
        <div><span>Status</span><strong className={dashboard?.up ? 'ok' : 'down'}><Circle size={12} fill="currentColor" />{dashboard?.up ? 'Up' : 'Down'}</strong></div>
        <div><span>Peers</span><strong>{peers.length}</strong></div>
        <div><span>Active handshakes</span><strong>{(dashboard?.peers || []).filter((p) => p.latest_handshake > 0).length}</strong></div>
      </section>

      <section className="workspace">
        <form className="create-panel" onSubmit={createPeer}>
          <h2>New Client</h2>
          <label>
            <span>Peer name</span>
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </label>
          <label>
            <span>Expires at (optional)</span>
            <input type="datetime-local" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} />
          </label>
          <label className="check-row">
            <input type="checkbox" checked={form.dry_run} onChange={(event) => setForm({ ...form, dry_run: event.target.checked })} />
            Dry run
          </label>
          <label>
            <span>Bandwidth limit</span>
            <input disabled value="Not supported in this beta" readOnly />
          </label>
          <p className="muted">WireGuard does not provide native per-peer bandwidth limits; this requires tc/nftables integration.</p>
          <button><Plus size={18} /> Create</button>
        </form>

        <div className="peer-table">
          <div className="table-head">
            <span>Name</span><span>Status</span><span>IP</span><span>Handshake</span><span>RX / TX</span><span></span>
          </div>
          {peers.map((peer) => {
            const live = statusByKey.get(peer.public_key)
            return (
              <div className={selectedId === peer.id ? 'peer-row selected' : 'peer-row'} key={peer.id} role="button" tabIndex="0" onClick={() => setSelectedId(peer.id)} onKeyDown={(event) => { if (event.key === 'Enter') setSelectedId(peer.id) }}>
                <span>{peer.name}</span>
                <span className={peer.disabled ? 'badge off' : 'badge on'}>{peer.disabled ? 'Disabled' : 'Enabled'}</span>
                <span>{peer.assigned_ip}</span>
                <span>{live?.latest_handshake ? new Date(live.latest_handshake * 1000).toLocaleString() : 'never'}</span>
                <span>{live ? `${formatBytes(live.transfer_rx)} / ${formatBytes(live.transfer_tx)}` : '0 B / 0 B'}</span>
                <span className="row-actions">
                  <button type="button" className="small-button" onClick={(event) => { event.stopPropagation(); togglePeer(peer) }}>
                    <ShieldOff size={16} /> {peer.disabled ? 'Enable' : 'Disable'}
                  </button>
                  <button type="button" className="icon-button danger" onClick={(event) => { event.stopPropagation(); setDeleteTarget(peer) }} title="Delete"><Trash2 size={16} /></button>
                </span>
              </div>
            )
          })}
        </div>
      </section>

      {selectedPeer && (
        <section className="details">
          <div className="detail-grid">
            <div><span>Name</span><strong>{selectedPeer.name}</strong></div>
            <div><span>Status</span><strong>{selectedPeer.disabled ? 'Disabled' : 'Enabled'}</strong></div>
            <div><span>Assigned IP</span><strong>{selectedPeer.assigned_ip}</strong></div>
            <div><span>Created</span><strong>{formatDate(selectedPeer.created_at)}</strong></div>
            <div><span>Expires</span><strong>{formatDate(selectedPeer.expires_at)}</strong></div>
            <div><span>Latest handshake</span><strong>{selectedStatus?.latest_handshake ? new Date(selectedStatus.latest_handshake * 1000).toLocaleString() : 'never'}</strong></div>
            <div><span>RX / TX</span><strong>{selectedStatus ? `${formatBytes(selectedStatus.transfer_rx)} / ${formatBytes(selectedStatus.transfer_tx)}` : '0 B / 0 B'}</strong></div>
            <div className="wide"><span>Public key</span><code>{selectedPeer.public_key}</code></div>
          </div>
          <div className="edit-panel">
            <h2>Edit Metadata</h2>
            <label><span>Name</span><input value={edit.name} onChange={(event) => setEdit({ ...edit, name: event.target.value })} /></label>
            <label><span>Notes</span><textarea value={edit.notes} onChange={(event) => setEdit({ ...edit, notes: event.target.value })} /></label>
            <label><span>Expires at (optional)</span><input type="datetime-local" value={edit.expires_at} onChange={(event) => setEdit({ ...edit, expires_at: event.target.value })} /></label>
            <button onClick={saveMetadata}>Save details</button>
          </div>
        </section>
      )}

      {result && (
        <section className="result">
          <div>
            <div className="result-head">
              <h2>{result.dry_run ? 'Dry-run client config' : 'Client config'}</h2>
              <button className="icon-button" onClick={() => setResult(null)} title="Hide config"><X size={18} /></button>
            </div>
            <p className="warning">Save this configuration now. The private key is shown only once and cannot be recovered later.</p>
            <pre>{result.client_config}</pre>
          </div>
          <img src={result.qr_png_data_uri} alt="WireGuard client QR code" />
        </section>
      )}

      {deleteTarget && (
        <div className="modal-backdrop">
          <div className="modal">
            <h2>Delete peer?</h2>
            <p>This removes {deleteTarget.name} from WGPanel and reapplies the WireGuard config.</p>
            <div className="modal-actions">
              <button className="secondary" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className="danger-button" onClick={deletePeer}>Delete</button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}

createRoot(document.getElementById('root')).render(<App />)
