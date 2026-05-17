import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Circle, Download, KeyRound, LogOut, Moon, Plus, RefreshCw, ShieldOff, Sun, Trash2, X } from 'lucide-react'
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
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api('/login', { method: 'POST', body: JSON.stringify({ username, password }) })
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
        <input value={username} onChange={(event) => setUsername(event.target.value)} />
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

function Setup() {
  const params = new URLSearchParams(window.location.search)
  const [token, setToken] = useState(params.get('token') || '')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [message, setMessage] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    setMessage('')
    if (password.length < 12) {
      setMessage('Password must be at least 12 characters')
      return
    }
    if (password !== confirm) {
      setMessage('Passwords do not match')
      return
    }
    try {
      await api('/setup', { method: 'POST', body: JSON.stringify({ token, username, password, confirm_password: confirm }) })
      setMessage('Setup complete. You can sign in now.')
    } catch (err) {
      setMessage(err.message || 'Setup failed')
    }
  }

  return (
    <main className="auth-shell">
      <form className="login-panel" onSubmit={submit}>
        <h1>Set up WGPanel</h1>
        <p className="muted">If your token expired, run docker-compose logs wgpanel or docker-compose exec wgpanel cat /var/lib/wgpanel/setup-token.</p>
        <label><span>Setup token</span><input value={token} onChange={(event) => setToken(event.target.value)} /></label>
        <label><span>Admin username</span><input value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        <label><span>Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <label><span>Confirm password</span><input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>
        {message && <p className="banner">{message}</p>}
        <button>Create admin</button>
      </form>
    </main>
  )
}

function App() {
  const [authed, setAuthed] = useState(true)
  const [dashboard, setDashboard] = useState(null)
  const [peers, setPeers] = useState([])
  const [interfaces, setInterfaces] = useState([])
  const [currentInterface, setCurrentInterface] = useState('wg0')
  const [setupRequired, setSetupRequired] = useState(false)
  const [banner, setBanner] = useState('')
  const [result, setResult] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [theme, setTheme] = useState(() => localStorage.getItem('wgpanel-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
  const [form, setForm] = useState({ name: '', expires_at: '', no_expiration: true, dry_run: false, tunnel_mode: 'split', custom_allowed_ips: '', client_dns: '' })
  const [edit, setEdit] = useState({ name: '', notes: '', expires_at: '' })

  const load = async () => {
    try {
      const setup = await fetch('/api/setup/status').then((r) => r.json()).catch(() => ({ setup_required: false }))
      setSetupRequired(setup.setup_required)
      if (setup.setup_required) return
      const [dash, peerRows, ifaceRows, selected] = await Promise.all([api('/dashboard'), api('/peers'), api('/interfaces'), api('/settings/interface')])
      setDashboard(dash)
      setPeers(peerRows)
      setInterfaces(ifaceRows.interfaces || [])
      setCurrentInterface(selected.interface)
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

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('wgpanel-theme', theme)
  }, [theme])

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
    if (!form.no_expiration && form.expires_at) {
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
        body: JSON.stringify({
          name: form.name.trim(),
          dry_run: form.dry_run,
          expires_at: expiresAt,
          tunnel_mode: form.tunnel_mode,
          custom_allowed_ips: form.tunnel_mode === 'custom' ? form.custom_allowed_ips : null,
          client_dns: form.client_dns || null,
        }),
      })
      setResult(created)
      setSelectedId(created.peer.id || selectedId)
      setForm({ name: '', expires_at: '', no_expiration: true, dry_run: false, tunnel_mode: 'split', custom_allowed_ips: '', client_dns: '' })
      setBanner(created.dry_run ? 'Dry run generated successfully' : 'Peer created successfully')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to create peer')
    }
  }

  const togglePeer = async (peer) => {
    if (!peer.managed) return
    setBanner('')
    try {
      const updated = await api(`/peers/${peer.id}/toggle`, { method: 'POST' })
      setBanner(updated.detail || (updated.active ? 'Peer enabled' : 'Peer disabled'))
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to update peer state')
    }
  }

  const copyConfig = async () => {
    if (!result?.client_config) return
    await navigator.clipboard.writeText(result.client_config)
    setBanner('Client config copied')
  }

  const downloadConfig = () => {
    if (!result?.client_config) return
    const blob = new Blob([result.client_config], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${result.peer.name}.conf`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const takeOwnership = async (peer) => {
    const name = window.prompt('Name for this imported peer', peer.name === 'Unmanaged peer' ? '' : peer.name)
    if (!name) return
    try {
      await api(`/peers/take-ownership?public_key=${encodeURIComponent(peer.public_key)}`, {
        method: 'POST',
        body: JSON.stringify({ name, notes: 'Imported existing WireGuard peer', expires_at: null }),
      })
      setBanner('Peer ownership imported')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to take ownership')
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

  if (setupRequired || window.location.pathname === '/setup') return <Setup />
  if (!authed) return <Login onLogin={load} />

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <h1>WGPanel</h1>
          <p>Interface {dashboard?.interface || currentInterface}</p>
        </div>
        <div className="actions">
          <select value={currentInterface} onChange={(event) => switchInterface(event.target.value)}>
            {interfaces.map((item) => <option key={item.name} value={item.name}>{item.name}{item.config_exists ? '' : ' (no config)'}</option>)}
          </select>
          <button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title="Toggle theme">
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button className="icon-button" onClick={load} title="Refresh"><RefreshCw size={18} /></button>
          <button className="icon-button" onClick={logout} title="Logout"><LogOut size={18} /></button>
        </div>
      </header>

      {banner && <div className="banner">{banner}</div>}
      <div className="notice">Existing unmanaged peers are preserved. WGPanel only modifies peers it manages.</div>

      <section className="stats">
        <div><span>Status</span><strong className={dashboard?.up ? 'ok' : 'down'}><Circle size={12} fill="currentColor" />{dashboard?.up ? 'Up' : 'Down'}</strong></div>
        <div><span>Peers</span><strong>{peers.length}</strong></div>
        <div><span>Pool</span><strong>{dashboard?.client_address_pool || '10.8.0.0/24'}</strong></div>
      </section>

      <section className="workspace">
        <form className="create-panel" onSubmit={createPeer}>
          <h2>New Client</h2>
          <label>
            <span>Peer name</span>
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </label>
          <label>
            <span>Tunnel mode</span>
            <select value={form.tunnel_mode} onChange={(event) => setForm({ ...form, tunnel_mode: event.target.value })}>
              <option value="split">Split tunnel</option>
              <option value="full">Full tunnel</option>
              <option value="custom">Custom AllowedIPs</option>
            </select>
          </label>
          {form.tunnel_mode === 'custom' && (
            <label>
              <span>Custom AllowedIPs</span>
              <input placeholder="10.8.0.0/24, 192.168.1.0/24" value={form.custom_allowed_ips} onChange={(event) => setForm({ ...form, custom_allowed_ips: event.target.value })} />
            </label>
          )}
          <label>
            <span>DNS (optional)</span>
            <input placeholder="Default from server" value={form.client_dns} onChange={(event) => setForm({ ...form, client_dns: event.target.value })} />
          </label>
          <label>
            <span>Expiration date</span>
            <input type="datetime-local" disabled={form.no_expiration} value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} />
            <small>Optional. Leave empty for no expiration.</small>
          </label>
          <label className="check-row">
            <input type="checkbox" checked={form.no_expiration} onChange={(event) => setForm({ ...form, no_expiration: event.target.checked, expires_at: event.target.checked ? '' : form.expires_at })} />
            No expiration
          </label>
          <label className="check-row">
            <input type="checkbox" checked={form.dry_run} onChange={(event) => setForm({ ...form, dry_run: event.target.checked })} />
            Dry run
          </label>
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
                <span className={peer.status === 'Unmanaged' ? 'badge unmanaged' : peer.status === 'Expired' ? 'badge expired' : peer.disabled ? 'badge off' : 'badge on'}>{peer.status}</span>
                <span>{peer.assigned_ip}</span>
                <span>{live?.latest_handshake ? new Date(live.latest_handshake * 1000).toLocaleString() : 'never'}</span>
                <span>{live ? `${formatBytes(live.transfer_rx)} / ${formatBytes(live.transfer_tx)}` : '0 B / 0 B'}</span>
                <span className="row-actions">
                  {peer.managed ? (
                    <>
                      <button type="button" className="small-button" onClick={(event) => { event.stopPropagation(); togglePeer(peer) }}>
                        <ShieldOff size={16} /> {peer.disabled ? 'Enable' : 'Disable'}
                      </button>
                      <button type="button" className="icon-button danger" onClick={(event) => { event.stopPropagation(); setDeleteTarget(peer) }} title="Delete"><Trash2 size={16} /></button>
                    </>
                  ) : (
                    <button type="button" className="small-button" onClick={(event) => { event.stopPropagation(); takeOwnership(peer) }}>Take ownership</button>
                  )}
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
            <div><span>Expires</span><strong>{selectedPeer.expires_at ? formatDate(selectedPeer.expires_at) : 'No expiration'}</strong></div>
            <div><span>Latest handshake</span><strong>{selectedStatus?.latest_handshake ? new Date(selectedStatus.latest_handshake * 1000).toLocaleString() : 'never'}</strong></div>
            <div><span>RX / TX</span><strong>{selectedStatus ? `${formatBytes(selectedStatus.transfer_rx)} / ${formatBytes(selectedStatus.transfer_tx)}` : '0 B / 0 B'}</strong></div>
            <div className="wide"><span>Public key</span><code>{selectedPeer.public_key}</code></div>
            <div className="wide"><span>Client config</span><strong>{selectedPeer.managed ? 'Client private key is not stored, so this config cannot be regenerated.' : 'Unmanaged peer. Client private key is not stored, so this config cannot be regenerated.'}</strong></div>
          </div>
          {selectedPeer.managed && <div className="edit-panel">
            <h2>Edit Metadata</h2>
            <label><span>Name</span><input value={edit.name} onChange={(event) => setEdit({ ...edit, name: event.target.value })} /></label>
            <label><span>Notes</span><textarea value={edit.notes} onChange={(event) => setEdit({ ...edit, notes: event.target.value })} /></label>
            <label><span>Expires at (optional)</span><input type="datetime-local" value={edit.expires_at} onChange={(event) => setEdit({ ...edit, expires_at: event.target.value })} /></label>
            <button onClick={saveMetadata}>Save details</button>
          </div>}
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
            <div className="config-actions">
              <button onClick={downloadConfig}><Download size={18} /> Download config</button>
              <button className="secondary" onClick={copyConfig}>Copy config</button>
              <button className="secondary" onClick={() => setResult(null)}>Hide config</button>
            </div>
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
  const switchInterface = async (value) => {
    try {
      await api('/settings/interface', { method: 'POST', body: JSON.stringify({ interface: value }) })
      setCurrentInterface(value)
      setSelectedId(null)
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to switch interface')
    }
  }
