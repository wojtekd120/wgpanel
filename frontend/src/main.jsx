import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Circle, KeyRound, LogOut, Plus, RefreshCw, ShieldOff, Trash2 } from 'lucide-react'
import './styles.css'

const api = async (path, options = {}) => {
  const response = await fetch(`/api${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || 'Request failed')
  }
  return response.json()
}

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
      setError(err.message)
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
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [form, setForm] = useState({ name: '', expires_at: '', dry_run: false })

  const load = async () => {
    setError('')
    try {
      const [dash, peerRows] = await Promise.all([api('/dashboard'), api('/peers')])
      setDashboard(dash)
      setPeers(peerRows)
      setAuthed(true)
    } catch (err) {
      if (err.message === 'Not authenticated') setAuthed(false)
      else setError(err.message)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const statusByKey = useMemo(() => new Map((dashboard?.peers || []).map((peer) => [peer.public_key, peer])), [dashboard])

  const createPeer = async (event) => {
    event.preventDefault()
    const body = {
      name: form.name,
      dry_run: form.dry_run,
      expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
    }
    try {
      const created = await api('/peers', { method: 'POST', body: JSON.stringify(body) })
      setResult(created)
      setForm({ name: '', expires_at: '', dry_run: false })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  const disablePeer = async (id) => {
    await api(`/peers/${id}/disable`, { method: 'POST' })
    await load()
  }

  const deletePeer = async (id) => {
    await api(`/peers/${id}`, { method: 'DELETE' })
    await load()
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

      {error && <div className="banner">{error}</div>}

      <section className="stats">
        <div><span>Status</span><strong className={dashboard?.up ? 'ok' : 'down'}><Circle size={12} fill="currentColor" />{dashboard?.up ? 'Up' : 'Down'}</strong></div>
        <div><span>Peers</span><strong>{peers.length}</strong></div>
        <div><span>Active handshakes</span><strong>{(dashboard?.peers || []).filter((p) => p.latest_handshake > 0).length}</strong></div>
      </section>

      <section className="workspace">
        <form className="create-panel" onSubmit={createPeer}>
          <h2>New Client</h2>
          <input placeholder="Peer name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          <input type="datetime-local" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} />
          <label className="check-row">
            <input type="checkbox" checked={form.dry_run} onChange={(event) => setForm({ ...form, dry_run: event.target.checked })} />
            Dry run
          </label>
          <button><Plus size={18} /> Create</button>
        </form>

        <div className="peer-table">
          <div className="table-head">
            <span>Name</span><span>IP</span><span>Handshake</span><span>RX / TX</span><span></span>
          </div>
          {peers.map((peer) => {
            const live = statusByKey.get(peer.public_key)
            return (
              <div className={peer.disabled ? 'peer-row disabled' : 'peer-row'} key={peer.id}>
                <span>{peer.name}</span>
                <span>{peer.assigned_ip}</span>
                <span>{live?.latest_handshake ? new Date(live.latest_handshake * 1000).toLocaleString() : 'never'}</span>
                <span>{live ? `${live.transfer_rx} / ${live.transfer_tx}` : '0 / 0'}</span>
                <span className="row-actions">
                  <button className="icon-button" onClick={() => disablePeer(peer.id)} title="Disable"><ShieldOff size={16} /></button>
                  <button className="icon-button danger" onClick={() => deletePeer(peer.id)} title="Delete"><Trash2 size={16} /></button>
                </span>
              </div>
            )
          })}
        </div>
      </section>

      {result && (
        <section className="result">
          <div>
            <h2>{result.dry_run ? 'Dry-run client config' : 'Client config'}</h2>
            <pre>{result.client_config}</pre>
          </div>
          <img src={result.qr_png_data_uri} alt="WireGuard client QR code" />
        </section>
      )}
    </main>
  )
}

createRoot(document.getElementById('root')).render(<App />)
