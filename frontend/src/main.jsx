import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Circle, Download, HelpCircle, KeyRound, LogOut, Moon, Plus, RefreshCw, RotateCcw, ShieldOff, Sun, Trash2, X } from 'lucide-react'
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
const formatBytes = (value = 0) => {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let amount = Math.max(0, Number(value) || 0)
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024
    unit += 1
  }
  const digits = unit === 0 ? 0 : amount >= 100 ? 0 : amount >= 10 ? 1 : 2
  return `${amount.toFixed(digits)} ${units[unit]}`
}
const formatMbps = (value = 0) => {
  const speed = Math.max(0, Number(value) || 0)
  const digits = speed >= 100 ? 0 : speed >= 10 ? 1 : speed >= 1 ? 2 : 3
  return `${speed.toFixed(digits)} Mbps`
}
const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds))

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

function Setup({ disabled = false }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [message, setMessage] = useState('')
  const [done, setDone] = useState(false)

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
      await api('/setup', { method: 'POST', body: JSON.stringify({ username, password, confirm_password: confirm }) })
      setDone(true)
      setMessage('Setup complete. You can sign in now.')
    } catch (err) {
      setMessage(err.message || 'Setup failed')
    }
  }

  return (
    <main className="auth-shell">
      <form className="login-panel" onSubmit={submit}>
        <h1>Set up WGPanel</h1>
        {disabled ? (
          <>
            <p className="banner">Setup is already completed.</p>
            <button type="button" onClick={() => window.location.assign('/')}>Go to login</button>
          </>
        ) : (
          <>
        <p className="muted">Create the first admin account. WGPanel stores only a password hash, never the plain password.</p>
        <label><span>Admin username</span><input value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        <label><span>Password</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <label><span>Confirm password</span><input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>
        {message && <p className="banner">{message}</p>}
        {done ? <button type="button" onClick={() => window.location.assign('/')}>Go to login</button> : <button>Create admin</button>}
          </>
        )}
      </form>
    </main>
  )
}

function HelpPage({ currentInterface, profiles, onCopy, onOpenDiagnostics, onOpenBackups }) {
  const guestInterface = profiles?.guest?.interface || 'wg1'
  const topics = [
    {
      title: 'WGPanel container',
      description: 'Start here when the page does not load, health is degraded, or an update failed.',
      commands: [
        'docker compose ps',
        'docker compose logs --tail=100 wgpanel',
        'docker compose restart wgpanel',
      ],
    },
    {
      title: `WireGuard ${currentInterface}`,
      description: 'These commands show public peer state and routing. They do not print private keys.',
      commands: [
        `sudo wg show ${currentInterface}`,
        `sudo wg show ${currentInterface} allowed-ips`,
        'ip -4 route show',
      ],
    },
    {
      title: 'Safe config inspection',
      description: 'Use the redacted command when sharing a config for support. Never paste the raw file.',
      commands: [
        `sudo sed -E 's/^([[:space:]]*(PrivateKey|PresharedKey)[[:space:]]*=).*/\\1 <redacted>/' /etc/wireguard/${currentInterface}.conf`,
      ],
    },
    {
      title: 'Routing and AllowedIPs',
      description: 'Server-side AllowedIPs select the peer on the VPS. Client-side AllowedIPs only control routes exported to the client.',
      commands: [
        `sudo wg show ${currentInterface} allowed-ips`,
        'ip -4 route get 1.1.1.1',
        'sudo iptables-nft -t nat -S',
      ],
    },
    {
      title: `Guest VPN (${guestInterface})`,
      description: profiles?.guest?.enabled
        ? 'Guest mode is enabled. Check the interface, fail-closed firewall, UFW, and service ordering.'
        : 'Guest mode is disabled. Install and verify the host firewall before enabling it in .env.',
      commands: [
        `sudo wg show ${guestInterface}`,
        'sudo nft -a list table inet wgpanel_guest',
        `sudo systemctl status wgpanel-guest-firewall wg-quick@${guestInterface} --no-pager`,
        'sudo ufw status verbose',
      ],
    },
    {
      title: 'Update verification',
      description: 'Confirm the checked-out release, rebuild only WGPanel, and inspect startup before making peer changes.',
      commands: [
        'git log -1 --oneline',
        'cat VERSION',
        'docker compose build wgpanel && docker compose up -d --no-deps wgpanel',
      ],
    },
  ]

  return (
    <section className="help-page">
      <div className="help-hero">
        <div>
          <h2><HelpCircle size={20} /> Help &amp; recovery</h2>
          <p>Read-only checks and safe first actions for the currently selected interface <strong>{currentInterface}</strong>.</p>
        </div>
        <div className="help-actions">
          <button className="small-button" onClick={onOpenDiagnostics}>Open Diagnostics</button>
          <button className="small-button" onClick={onOpenBackups}>Open Backups</button>
        </div>
      </div>

      <div className="warning help-warning">
        Stop before destructive recovery: never run <code>docker compose down -v</code>, never delete the database, and do not restart or recreate WireGuard when your administrative access depends on it.
      </div>

      <div className="help-grid">
        {topics.map((topic) => (
          <article className="help-card" key={topic.title}>
            <h3>{topic.title}</h3>
            <p>{topic.description}</p>
            <div className="help-commands">
              {topic.commands.map((command) => (
                <div className="help-command" key={command}>
                  <code>{command}</code>
                  <button className="small-button" onClick={() => onCopy(command)}>Copy</button>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>

      <div className="help-card help-wide">
        <h3>Safe recovery order</h3>
        <ol>
          <li>Keep a second SSH session or provider console open.</li>
          <li>Create database and WireGuard config backups before changing anything.</li>
          <li>Stop only the WGPanel container if the UI is misbehaving; the active tunnel keeps running.</li>
          <li>Use Diagnostics and redacted output. Never share PrivateKey or PresharedKey values.</li>
          <li>Restore a backup with the restricted helper instead of taking the interface down.</li>
        </ol>
      </div>
    </section>
  )
}

function App() {
  const [authed, setAuthed] = useState(true)
  const [dashboard, setDashboard] = useState(null)
  const [peers, setPeers] = useState([])
  const [interfaces, setInterfaces] = useState([])
  const [profiles, setProfiles] = useState({ private: { interface: 'wg0', enabled: true }, guest: { interface: 'wg1', enabled: false } })
  const [currentInterface, setCurrentInterface] = useState('wg0')
  const [setupRequired, setSetupRequired] = useState(false)
  const [banner, setBanner] = useState('')
  const [backups, setBackups] = useState([])
  const [onboarding, setOnboarding] = useState([])
  const [page, setPage] = useState('dashboard')
  const [dismissedDiagnostics, setDismissedDiagnostics] = useState(() => new Set())
  const [backupDiff, setBackupDiff] = useState('')
  const [restoreTarget, setRestoreTarget] = useState(null)
  const [restoreText, setRestoreText] = useState('')
  const [result, setResult] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [trafficSnapshot, setTrafficSnapshot] = useState(null)
  const [trafficBusy, setTrafficBusy] = useState(false)
  const trafficMeasurementId = useRef(0)
  const [theme, setTheme] = useState(() => localStorage.getItem('wgpanel-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
  const [form, setForm] = useState({ name: '', peer_type: 'private', expires_at: '', no_expiration: true, dry_run: false, tunnel_mode: 'split', custom_allowed_ips: '', server_allowed_ips: '', client_dns: '' })
  const [edit, setEdit] = useState({ name: '', notes: '', expires_at: '', server_allowed_ips: '', tunnel_mode: 'split', client_allowed_ips: '', client_dns: '' })

  const sampleTraffic = async (interfaceName = currentInterface) => {
    if (trafficBusy) return
    const measurementId = trafficMeasurementId.current + 1
    trafficMeasurementId.current = measurementId
    setTrafficBusy(true)
    try {
      const query = `?interface=${encodeURIComponent(interfaceName)}`
      const first = await api(`/dashboard${query}`)
      const startedAt = performance.now()
      await wait(2000)
      const second = await api(`/dashboard${query}`)
      const elapsedSeconds = Math.max((performance.now() - startedAt) / 1000, 0.001)
      const previousByKey = new Map((first.peers || []).map((peer) => [peer.public_key, peer]))
      const peerRates = (second.peers || []).map((peer) => {
        const previous = previousByKey.get(peer.public_key)
        const rxBytes = previous ? Math.max(0, peer.transfer_rx - previous.transfer_rx) : 0
        const txBytes = previous ? Math.max(0, peer.transfer_tx - previous.transfer_tx) : 0
        return {
          public_key: peer.public_key,
          from_peer_mbps: (rxBytes * 8) / elapsedSeconds / 1_000_000,
          to_peer_mbps: (txBytes * 8) / elapsedSeconds / 1_000_000,
        }
      })
      if (trafficMeasurementId.current !== measurementId) return
      setDashboard((current) => current?.interface === interfaceName ? second : current)
      setTrafficSnapshot({
        interface: interfaceName,
        measured_at: new Date().toISOString(),
        sample_seconds: elapsedSeconds,
        peers: peerRates,
        from_peers_mbps: peerRates.reduce((total, peer) => total + peer.from_peer_mbps, 0),
        to_peers_mbps: peerRates.reduce((total, peer) => total + peer.to_peer_mbps, 0),
      })
    } catch (err) {
      if (trafficMeasurementId.current === measurementId) {
        setBanner(err.message || 'Unable to measure traffic')
      }
    } finally {
      if (trafficMeasurementId.current === measurementId) setTrafficBusy(false)
    }
  }

  const load = async ({ sampleAfterLoad = false } = {}) => {
    try {
      const setup = await fetch('/api/setup/status').then((r) => r.json()).catch(() => ({ setup_required: false }))
      setSetupRequired(setup.setup_required)
      if (setup.setup_required) return
      const [dash, peerRows, ifaceRows, selected, backupRows, onboardingRows, profileRows] = await Promise.all([api('/dashboard'), api('/peers'), api('/interfaces'), api('/settings/interface'), api('/backups'), api('/diagnostics'), api('/peer-profiles')])
      setDashboard(dash)
      setPeers(peerRows)
      setBackups(backupRows.backups || [])
      setOnboarding(onboardingRows || [])
      setInterfaces(ifaceRows.interfaces || [])
      setProfiles(profileRows)
      setCurrentInterface(selected.interface)
      setAuthed(true)
      if (!selectedId && peerRows.length) setSelectedId(peerRows[0].id)
      if (sampleAfterLoad) sampleTraffic(selected.interface)
    } catch (err) {
      if (err.message === 'Not authenticated') setAuthed(false)
      else setBanner(err.message || 'Unable to load WGPanel data')
    }
  }

  useEffect(() => {
    load({ sampleAfterLoad: true })
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('wgpanel-theme', theme)
  }, [theme])

  const statusByKey = useMemo(() => new Map((dashboard?.peers || []).map((peer) => [peer.public_key, peer])), [dashboard])
  const trafficByKey = useMemo(() => new Map((trafficSnapshot?.peers || []).map((peer) => [peer.public_key, peer])), [trafficSnapshot])
  const selectedPeer = peers.find((peer) => peer.id === selectedId)
  const selectedStatus = selectedPeer ? statusByKey.get(selectedPeer.public_key) : null

  useEffect(() => {
    if (selectedPeer) {
      setEdit({
        name: selectedPeer.name,
        notes: selectedPeer.notes || '',
        expires_at: selectedPeer.expires_at ? selectedPeer.expires_at.slice(0, 16) : '',
        server_allowed_ips: selectedPeer.server_allowed_ips || '',
        tunnel_mode: selectedPeer.tunnel_mode || 'split',
        client_allowed_ips: selectedPeer.client_allowed_ips || '',
        client_dns: selectedPeer.client_dns || '',
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
      const targetInterface = form.peer_type === 'guest' ? profiles.guest.interface : profiles.private.interface
      const created = await api(`/peers?interface=${encodeURIComponent(targetInterface)}`, {
        method: 'POST',
        body: JSON.stringify({
          name: form.name.trim(),
          peer_type: form.peer_type,
          dry_run: form.dry_run,
          expires_at: expiresAt,
          tunnel_mode: form.tunnel_mode,
          custom_allowed_ips: form.tunnel_mode === 'custom' ? form.custom_allowed_ips : null,
          server_allowed_ips: form.server_allowed_ips || null,
          client_dns: form.client_dns || null,
        }),
      })
      setResult(created)
      setSelectedId(created.peer.id || selectedId)
      if (!form.dry_run && currentInterface !== targetInterface) {
        await api('/settings/interface', { method: 'POST', body: JSON.stringify({ interface: targetInterface }) })
        setCurrentInterface(targetInterface)
      }
      setForm({ name: '', peer_type: 'private', expires_at: '', no_expiration: true, dry_run: false, tunnel_mode: 'split', custom_allowed_ips: '', server_allowed_ips: '', client_dns: '' })
      setBanner(created.dry_run ? 'Preview generated successfully' : 'Peer created successfully')
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

  const copyPublicKey = async (publicKey) => {
    await navigator.clipboard.writeText(publicKey)
    setBanner('Public key copied')
  }

  const copyText = async (value) => {
    await navigator.clipboard.writeText(value)
    setBanner('Copied')
  }

  const createBackupNow = async () => {
    try {
      await api('/backups', { method: 'POST' })
      setBanner('Backup created')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to create backup')
    }
  }

  const diagnosticsSummary = useMemo(() => {
    const counts = { pass: 0, warn: 0, fail: 0 }
    onboarding.forEach((item) => { counts[item.state] = (counts[item.state] || 0) + 1 })
    return counts
  }, [onboarding])

  const diagnosticsByGroup = useMemo(() => {
    return onboarding.filter((item) => !dismissedDiagnostics.has(item.key)).reduce((groups, item) => {
      groups[item.group] = groups[item.group] || []
      groups[item.group].push(item)
      return groups
    }, {})
  }, [onboarding, dismissedDiagnostics])

  const dismissDiagnostic = (key) => {
    setDismissedDiagnostics((current) => new Set([...current, key]))
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

  const switchInterface = async (value) => {
    try {
      trafficMeasurementId.current += 1
      setTrafficBusy(false)
      setTrafficSnapshot(null)
      await api('/settings/interface', { method: 'POST', body: JSON.stringify({ interface: value }) })
      setCurrentInterface(value)
      setSelectedId(null)
      setBackupDiff('')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to switch interface')
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
          server_allowed_ips: edit.server_allowed_ips,
          tunnel_mode: edit.tunnel_mode,
          client_allowed_ips: edit.client_allowed_ips,
          client_dns: edit.client_dns,
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

  const viewBackupDiff = async (backup) => {
    try {
      const data = await api(`/backups/${encodeURIComponent(backup.name)}/diff`)
      setBackupDiff(data.diff || 'No differences')
    } catch (err) {
      setBanner(err.message || 'Unable to load backup diff')
    }
  }

  const restoreBackup = async () => {
    if (!restoreTarget) return
    try {
      await api(`/backups/${encodeURIComponent(restoreTarget.name)}/restore`, {
        method: 'POST',
        body: JSON.stringify({ confirmation: restoreText }),
      })
      setBanner('Backup restored')
      setRestoreTarget(null)
      setRestoreText('')
      setBackupDiff('')
      await load()
    } catch (err) {
      setBanner(err.message || 'Unable to restore backup')
    }
  }

  if (setupRequired) return <Setup />
  if (window.location.pathname === '/setup') return <Setup disabled />
  if (!authed) return <Login onLogin={() => load({ sampleAfterLoad: true })} />

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
          <button className="icon-button" onClick={() => load()} title="Refresh"><RefreshCw size={18} /></button>
          <button className="icon-button" onClick={logout} title="Logout"><LogOut size={18} /></button>
        </div>
      </header>

      <nav className="tabs">
        <button className={page === 'dashboard' ? 'active' : ''} onClick={() => setPage('dashboard')}>Dashboard</button>
        <button className={page === 'diagnostics' ? 'active' : ''} onClick={() => setPage('diagnostics')}>Diagnostics</button>
        <button className={page === 'backups' ? 'active' : ''} onClick={() => setPage('backups')}>Backups</button>
        <button className={page === 'help' ? 'active' : ''} onClick={() => setPage('help')}><HelpCircle size={16} /> Help</button>
      </nav>

      {banner && <div className="banner">{banner}</div>}
      <div className="notice">Existing unmanaged peers are preserved. WGPanel only modifies peers it manages.</div>

      {page === 'dashboard' && (
        <>
          <section className="summary-card">
            <strong>System checks: {diagnosticsSummary.pass} passed, {diagnosticsSummary.warn} warnings, {diagnosticsSummary.fail} failed</strong>
            <button className="small-button" onClick={() => setPage('diagnostics')}>Open Diagnostics</button>
          </section>

      <section className="stats">
        <div><span>Status</span><strong className={dashboard?.up ? 'ok' : 'down'}><Circle size={12} fill="currentColor" />{dashboard?.up ? 'Up' : 'Down'}</strong></div>
        <div><span>Peers</span><strong>{peers.length}</strong></div>
        <div><span>Pool</span><strong>{dashboard?.client_address_pool || '10.8.0.0/24'}</strong></div>
      </section>

      <section className="traffic-card">
        <div className="traffic-heading">
          <div>
            <h2>Traffic snapshot · {currentInterface}</h2>
            <p>Two-second measurement on login or on demand. No background polling.</p>
          </div>
          <button className="small-button" disabled={trafficBusy} onClick={() => sampleTraffic(currentInterface)}>
            <RefreshCw className={trafficBusy ? 'spin' : ''} size={16} />
            {trafficBusy ? 'Measuring...' : 'Measure now'}
          </button>
        </div>
        <div className="traffic-totals">
          <div><span>From peers</span><strong>{trafficSnapshot?.interface === currentInterface ? formatMbps(trafficSnapshot.from_peers_mbps) : 'Not measured'}</strong></div>
          <div><span>To peers</span><strong>{trafficSnapshot?.interface === currentInterface ? formatMbps(trafficSnapshot.to_peers_mbps) : 'Not measured'}</strong></div>
          <div><span>Measured</span><strong>{trafficSnapshot?.interface === currentInterface ? new Date(trafficSnapshot.measured_at).toLocaleTimeString() : '—'}</strong></div>
        </div>
      </section>

      <section className="workspace">
        <form className="create-panel" onSubmit={createPeer}>
          <h2>New Client</h2>
          <label>
            <span>Peer name</span>
            <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          </label>
          <label>
            <span>Client type</span>
            <select value={form.peer_type} onChange={(event) => setForm({ ...form, peer_type: event.target.value })}>
              <option value="private">Private</option>
              <option value="guest" disabled={!profiles.guest.enabled}>Guest (isolated){profiles.guest.enabled ? '' : ' - not configured'}</option>
            </select>
            <small>{form.peer_type === 'guest' ? `Separate ${profiles.guest.interface}, IPv4 internet only; private networks and other guests are blocked.` : `Managed on ${profiles.private.interface}.`}</small>
          </label>
          {form.peer_type === 'private' && <label>
            <span>Tunnel mode</span>
            <select value={form.tunnel_mode} onChange={(event) => setForm({ ...form, tunnel_mode: event.target.value })}>
              <option value="split">Split tunnel</option>
              <option value="full">Full tunnel</option>
              <option value="custom">Custom AllowedIPs</option>
            </select>
          </label>}
          {form.peer_type === 'private' && form.tunnel_mode === 'custom' && (
            <label>
              <span>Client-side AllowedIPs (export)</span>
              <input placeholder="10.8.0.0/24, 198.51.100.0/24" value={form.custom_allowed_ips} onChange={(event) => setForm({ ...form, custom_allowed_ips: event.target.value })} />
              <small>Routes installed on the client. This does not control server cryptokey routing.</small>
            </label>
          )}
          {form.peer_type === 'private' && <label>
            <span>Additional server-side AllowedIPs</span>
            <input placeholder="198.51.100.0/24" value={form.server_allowed_ips} onChange={(event) => setForm({ ...form, server_allowed_ips: event.target.value })} />
            <small>Optional networks behind this peer. Its assigned /32 is added automatically.</small>
          </label>}
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
            Preview changes
            <small>Advanced: show the generated config without modifying WireGuard.</small>
          </label>
          <button><Plus size={18} /> Create</button>
        </form>

        <div className="peer-table">
          <div className="table-head">
            <span>Name</span><span>Status</span><span>IP</span><span>Handshake</span><span>RX / TX</span><span></span>
          </div>
          {peers.map((peer) => {
            const live = statusByKey.get(peer.public_key)
            const speed = trafficByKey.get(peer.public_key)
            return (
              <div className={selectedId === peer.id ? 'peer-row selected' : 'peer-row'} key={peer.id} role="button" tabIndex="0" onClick={() => setSelectedId(peer.id)} onKeyDown={(event) => { if (event.key === 'Enter') setSelectedId(peer.id) }}>
                <span>{peer.name}<small>{peer.peer_type === 'guest' ? 'Guest (isolated)' : 'Private'}</small></span>
                <span className={peer.status === 'Unmanaged' ? 'badge unmanaged' : peer.status === 'Expired' ? 'badge expired' : peer.disabled ? 'badge off' : 'badge on'}>{peer.status}</span>
                <span>{peer.assigned_ip}</span>
                <span>
                  <span className={`badge activity ${live?.activity_status === 'Active' ? 'on' : live?.activity_status === 'Recent' ? 'recent' : live?.activity_status === 'Stale' ? 'expired' : 'off'}`}>
                    {live?.activity_status || 'Never connected'}
                  </span>
                  <small>{live?.latest_handshake ? new Date(live.latest_handshake * 1000).toLocaleString() : 'never'}</small>
                </span>
                <span>
                  {live ? `${formatBytes(live.transfer_rx)} / ${formatBytes(live.transfer_tx)}` : '0 B / 0 B'}
                  <small>{speed ? `From: ${formatMbps(speed.from_peer_mbps)} · To: ${formatMbps(speed.to_peer_mbps)}` : 'Speed not measured'}</small>
                </span>
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
            <div><span>Client type</span><strong>{selectedPeer.peer_type === 'guest' ? 'Guest (isolated)' : 'Private'}</strong></div>
            <div><span>Assigned IP</span><strong>{selectedPeer.assigned_ip}</strong></div>
            <div className="wide"><span>Server-side AllowedIPs</span><code>{selectedPeer.server_allowed_ips || 'none'}</code></div>
            <div className="wide"><span>Client-side AllowedIPs (export)</span><code>{selectedPeer.client_allowed_ips || 'none'}</code></div>
            <div><span>Created</span><strong>{formatDate(selectedPeer.created_at)}</strong></div>
            <div><span>Expires</span><strong>{selectedPeer.expires_at ? formatDate(selectedPeer.expires_at) : 'No expiration'}</strong></div>
            <div><span>Latest handshake</span><strong>{selectedStatus?.latest_handshake ? new Date(selectedStatus.latest_handshake * 1000).toLocaleString() : 'never'}</strong></div>
            <div><span>Activity</span><strong><span className={`badge activity ${selectedStatus?.activity_status === 'Active' ? 'on' : selectedStatus?.activity_status === 'Recent' ? 'recent' : selectedStatus?.activity_status === 'Stale' ? 'expired' : 'off'}`}>{selectedStatus?.activity_status || 'Never connected'}</span></strong></div>
            <div><span>RX / TX</span><strong>{selectedStatus ? `${formatBytes(selectedStatus.transfer_rx)} / ${formatBytes(selectedStatus.transfer_tx)}` : '0 B / 0 B'}</strong></div>
            <div><span>From this peer</span><strong>{trafficByKey.has(selectedPeer.public_key) ? formatMbps(trafficByKey.get(selectedPeer.public_key).from_peer_mbps) : 'Not measured'}</strong></div>
            <div><span>To this peer</span><strong>{trafficByKey.has(selectedPeer.public_key) ? formatMbps(trafficByKey.get(selectedPeer.public_key).to_peer_mbps) : 'Not measured'}</strong></div>
            <div className="wide key-line"><span>Public key</span><code>{selectedPeer.public_key}</code><button className="small-button" onClick={() => copyPublicKey(selectedPeer.public_key)}>Copy</button></div>
            <div className="wide"><span>Client config</span><strong>{selectedPeer.managed ? 'Client private key is not stored, so this config cannot be regenerated.' : 'Unmanaged peer. Client private key is not stored, so this config cannot be regenerated.'}</strong></div>
          </div>
          {selectedPeer.managed && <div className="edit-panel">
            <h2>Edit Peer</h2>
            <label><span>Name</span><input value={edit.name} onChange={(event) => setEdit({ ...edit, name: event.target.value })} /></label>
            <label><span>Notes</span><textarea value={edit.notes} onChange={(event) => setEdit({ ...edit, notes: event.target.value })} /></label>
            <label><span>Expires at (optional)</span><input type="datetime-local" value={edit.expires_at} onChange={(event) => setEdit({ ...edit, expires_at: event.target.value })} /></label>
            <label>
              <span>Server-side AllowedIPs</span>
              <input disabled={selectedPeer.peer_type === 'guest'} value={edit.server_allowed_ips} onChange={(event) => setEdit({ ...edit, server_allowed_ips: event.target.value })} />
              <small>{selectedPeer.peer_type === 'guest' ? 'Guest peers are fixed to their assigned /32.' : `Cryptokey routes accepted from and sent to this peer. Must include ${selectedPeer.assigned_ip}/32.`}</small>
            </label>
            <label>
              <span>Client tunnel mode</span>
              <select disabled={selectedPeer.peer_type === 'guest'} value={edit.tunnel_mode} onChange={(event) => {
                const mode = event.target.value
                setEdit({
                  ...edit,
                  tunnel_mode: mode,
                  client_allowed_ips: mode === 'full' ? '0.0.0.0/0, ::/0' : mode === 'split' ? (dashboard?.client_address_pool || edit.client_allowed_ips) : edit.client_allowed_ips,
                })
              }}>
                <option value="split">Split tunnel</option>
                <option value="full">Full tunnel</option>
                <option value="custom">Custom</option>
              </select>
            </label>
            <label>
              <span>Client-side AllowedIPs (export metadata)</span>
              <input disabled={selectedPeer.peer_type === 'guest'} value={edit.client_allowed_ips} onChange={(event) => setEdit({ ...edit, client_allowed_ips: event.target.value })} />
              <small>{selectedPeer.peer_type === 'guest' ? 'IPv4-only full tunnel (0.0.0.0/0); no IPv6 route is exported.' : 'Stored for client export semantics; it is never written into the server peer block.'}</small>
            </label>
            <label><span>Client DNS</span><input value={edit.client_dns} onChange={(event) => setEdit({ ...edit, client_dns: event.target.value })} /></label>
            <button onClick={saveMetadata}>Save peer</button>
          </div>}
        </section>
      )}
        </>
      )}

      {page === 'diagnostics' && (
        <section className="diagnostics-page">
          {Object.entries(diagnosticsByGroup).map(([group, checks]) => (
            <div className="onboarding" key={group}>
              <div className="section-head">
                <h2>{group}</h2>
                <span>{checks.length} checks</span>
              </div>
              <div className="checklist">
                {checks.map((check) => (
                  <div className={`check-card ${check.state}`} key={check.key}>
                    <div>
                      <span className={`badge ${check.state}`}>{check.state}</span>
                      <strong>{check.label}</strong>
                    </div>
                    <p>{check.detail}</p>
                    {(check.fixes || []).map((fix) => (
                      <div className="fix-row" key={`${check.key}-${fix.label}`}>
                        <code>{fix.command}</code>
                        <button className="small-button" onClick={() => copyText(fix.command)}>Copy</button>
                      </div>
                    ))}
                    <div className="diagnostic-actions">
                      <button className="small-button" onClick={load}>Recheck</button>
                      <button className="small-button" onClick={() => dismissDiagnostic(check.key)}>Dismiss for this session</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </section>
      )}

      {page === 'backups' && (
      <section className="details backups-page">
        <div className="detail-grid">
          <div className="wide">
            <h2>Backups</h2>
            <p className="muted">Diffs are redacted before display. PrivateKey values are never shown.</p>
            <button className="small-button" onClick={createBackupNow}>Create backup now</button>
          </div>
          {backups.length === 0 && <div className="wide"><strong>No backups found for {currentInterface}</strong></div>}
          {backups.map((backup) => (
            <div className="wide backup-row" key={backup.name}>
              <div>
                <strong>{backup.name}</strong>
                <strong>{backup.timestamp}</strong>
                <span>{backup.interface} - {backup.size} B</span>
              </div>
              <div className="row-actions">
                <button className="small-button" onClick={() => viewBackupDiff(backup)}>View diff</button>
                <a className="small-button" href={`/api/backups/${encodeURIComponent(backup.name)}/download`}>Download redacted</a>
                <button className="small-button" onClick={() => { setRestoreTarget(backup); setRestoreText('') }}><RotateCcw size={16} /> Restore</button>
              </div>
            </div>
          ))}
        </div>
        <div className="edit-panel">
          <h2>Redacted Diff</h2>
          <pre>{backupDiff || 'Select a backup to view its diff against the current config.'}</pre>
        </div>
      </section>
      )}

      {page === 'help' && (
        <HelpPage
          currentInterface={currentInterface}
          profiles={profiles}
          onCopy={copyText}
          onOpenDiagnostics={() => setPage('diagnostics')}
          onOpenBackups={() => setPage('backups')}
        />
      )}

      {result && (
        <section className="result">
          <div>
            <div className="result-head">
              <h2>{result.dry_run ? 'Preview client config' : 'Client config'}</h2>
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

      {restoreTarget && (
        <div className="modal-backdrop">
          <div className="modal">
            <h2>Restore backup?</h2>
            <p>This creates a fresh backup first, then restores {restoreTarget.name}. Type RESTORE {currentInterface} to continue.</p>
            <input value={restoreText} onChange={(event) => setRestoreText(event.target.value)} />
            <div className="modal-actions">
              <button className="secondary" onClick={() => setRestoreTarget(null)}>Cancel</button>
              <button className="danger-button" onClick={restoreBackup}>Restore</button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}

createRoot(document.getElementById('root')).render(<App />)
