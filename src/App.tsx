import { useEffect, useMemo, useRef, useState } from "react"
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  AreaChart,
  Area,
  BarChart,
  Bar,
  CartesianGrid,
  Legend,
} from "recharts"

// ---------- Types ----------
type Severity = "low" | "medium" | "high"
type AlertStatus = "open" | "investigating" | "blocked" | "isolated" | "ignored" | "escalated" | "resolved"

interface Alert {
  id: string
  ts: number
  type: "BruteForce" | "Malware" | "Exfiltration" | "Phishing" | "PortScan" | "Lateral" | "Ransomware"
  severity: Severity
  confidence: number // 0..1
  srcIp: string
  host: string
  status: AlertStatus
  actionTaken?: string
}

interface Host {
  id: string
  compromised: boolean
  risk: number // 0..1
  cpu: number // 0..1
  lastSeen: number
}

interface LogEntry {
  id: string
  ts: number
  msg: string
  kind: "info" | "success" | "warn" | "error"
  reward?: number
}

interface StepResult {
  state: StateSnapshot
  reward: number
  done: boolean
  info: string
}

interface StateSnapshot {
  step: number
  score: number // 0..1
  alerts: Alert[]
  hosts: Host[]
  metrics: {
    compromisedHosts: number
    anomalyScore: number // 0..1
    cpu: number // 0..1
    threatLevel: number // 0..1
  }
  history: { step: number; anomaly: number; cpu: number; threats: number; compromised: number }[]
  logs: LogEntry[]
}

interface User {
  username: string
  role: "analyst" | "senior_analyst" | "soc_lead" | "admin"
  name: string
  avatar: string
}

// ---------- Sentinel-Core Simulation ----------
class SentinelCore {
  private rng: () => number
  private state: StateSnapshot

  constructor(seed = Date.now()) {
    let x = seed | 1
    this.rng = () => {
      x ^= x << 13; x ^= x >> 17; x ^= x << 5
      return ((x >>> 0) % 1_000_000) / 1_000_000
    }
    this.state = this._initialState()
  }

  private _initialState(): StateSnapshot {
    const hosts: Host[] = Array.from({ length: 12 }).map((_, i) => ({
      id: `h-${(i + 1).toString().padStart(2, "0")}`,
      compromised: false,
      risk: 0.1 + this.rng() * 0.2,
      cpu: 0.2 + this.rng() * 0.3,
      lastSeen: Date.now(),
    }))

    const alerts: Alert[] = this._genInitialAlerts(6)

    return {
      step: 0,
      score: 0.72,
      alerts,
      hosts,
      metrics: this._computeMetrics(hosts, alerts),
      history: [{ step: 0, anomaly: 0.35, cpu: 0.32, threats: 3, compromised: 0 }],
      logs: [
        { id: uid(), ts: Date.now(), kind: "info", msg: "Sentinel-Core online. Cloud-native SOC initialized." },
        { id: uid(), ts: Date.now(), kind: "success", msg: "Telemetry ingestion: vpc-flow, EDR, WAF, CloudTrail" },
      ],
    }
  }

  private _genInitialAlerts(n: number): Alert[] {
    const types: Alert["type"][] = ["PortScan", "BruteForce", "Phishing", "Malware", "Lateral", "Exfiltration", "Ransomware"]
    const alerts: Alert[] = []
    for (let i = 0; i < n; i++) {
      const sevRoll = this.rng()
      const severity: Severity = sevRoll > 0.7 ? "high" : sevRoll > 0.35 ? "medium" : "low"
      alerts.push({
        id: `A-${1000 + i}`,
        ts: Date.now() - Math.floor(this.rng() * 1000 * 60 * 8),
        type: types[Math.floor(this.rng() * types.length)],
        severity,
        confidence: +(0.55 + this.rng() * 0.4).toFixed(2),
        srcIp: `203.${Math.floor(this.rng() * 255)}.${Math.floor(this.rng() * 255)}.${Math.floor(this.rng() * 255)}`,
        host: `h-${(1 + Math.floor(this.rng() * 12)).toString().padStart(2, "0")}`,
        status: "open",
      })
    }
    return alerts
  }

  private _computeMetrics(hosts: Host[], alerts: Alert[]) {
    const compromisedHosts = hosts.filter(h => h.compromised).length
    const activeHigh = alerts.filter(a => a.status === "open" || a.status === "investigating").filter(a => a.severity === "high").length
    const anomalyScore = clamp01(0.2 + activeHigh * 0.12 + compromisedHosts * 0.08 + this.rng() * 0.1)
    const cpu = clamp01(0.25 + this.rng() * 0.2 + compromisedHosts * 0.05 + activeHigh * 0.03)
    const threatLevel = clamp01(0.3 + activeHigh * 0.1 + compromisedHosts * 0.12 + this.rng() * 0.08)
    return { compromisedHosts, anomalyScore, cpu, threatLevel }
  }

  private _mutateEnvironment(): void {
    const { hosts, alerts } = this.state
    if (this.rng() > 0.35) {
      const newA = this._genInitialAlerts(1)[0]
      newA.id = `A-${1000 + Math.floor(this.rng() * 9000)}`
      newA.ts = Date.now()
      alerts.unshift(newA)
      this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "warn", msg: `New alert ${newA.id} (${newA.type}) from ${newA.srcIp} → ${newA.host}` })
    }
    hosts.forEach(h => {
      h.cpu = clamp01(h.cpu + (this.rng() - 0.5) * 0.06)
      h.risk = clamp01(h.risk + (this.rng() - 0.5) * 0.05 + (h.compromised ? 0.02 : 0))
      h.lastSeen = Date.now() - Math.floor(this.rng() * 60_000)
      if (!h.compromised && h.risk > 0.85 && this.rng() > 0.6) {
        h.compromised = true
        this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "error", msg: `Host ${h.id} compromised (risk ${Math.round(h.risk * 100)}%)` })
      }
    })
    alerts.forEach(a => {
      if (a.status === "open" && this.rng() > 0.85) a.confidence = clamp01(a.confidence + 0.05)
    })
    this.state.metrics = this._computeMetrics(hosts, alerts)
    const { anomalyScore, cpu } = this.state.metrics
    this.state.history.push({
      step: this.state.step,
      anomaly: +anomalyScore.toFixed(3),
      cpu: +cpu.toFixed(3),
      threats: alerts.filter(a => ["open", "investigating"].includes(a.status)).length,
      compromised: hosts.filter(h => h.compromised).length,
    })
    if (this.state.history.length > 120) this.state.history.shift()
  }

  reset(): StateSnapshot {
    this.state = this._initialState()
    this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "info", msg: "Environment reset." })
    return this._clone()
  }

  getState(): StateSnapshot {
    return this._clone()
  }

  step(action: ActionRequest): StepResult {
    const prevScore = this.state.score
    this.state.step += 1
    const a = this.state.alerts.find(x => x.id === action.alertId)
    let reward = 0
    let info = ""

    if (!a && action.kind !== "noop") {
      reward = -0.05
      info = "No such alert."
      this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "warn", msg: `Action failed: alert ${action.alertId} not found`, reward })
    } else if (a) {
      switch (action.kind) {
        case "investigate": {
          if (a.status === "open") {
            a.status = "investigating"
            a.confidence = clamp01(a.confidence + 0.08)
            reward = 0.05
            info = "Investigation started."
            this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "info", msg: `Investigating ${a.id} (${a.type}) on ${a.host}`, reward })
          } else {
            reward = -0.01
            info = "Already in progress."
          }
          break
        }
        case "block_ip": {
          a.status = "blocked"
          a.actionTaken = `Blocked ${a.srcIp}`
          const host = this.state.hosts.find(h => h.id === a.host)
          if (host) host.risk = clamp01(host.risk - 0.15)
          reward = a.severity === "high" ? 0.12 : a.severity === "medium" ? 0.08 : 0.04
          info = `IP ${a.srcIp} blocked.`
          this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "success", msg: `${a.id}: ${info}`, reward })
          break
        }
        case "isolate_host": {
          a.status = "isolated"
          const host = this.state.hosts.find(h => h.id === a.host)
          if (host) {
            host.compromised = false
            host.risk = clamp01(host.risk - 0.35)
            host.cpu = clamp01(host.cpu - 0.1)
          }
          a.actionTaken = `Isolated ${a.host}`
          reward = 0.15
          info = `Host ${a.host} isolated.`
          this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "success", msg: `${a.id}: ${info}`, reward })
          break
        }
        case "ignore": {
          a.status = "ignored"
          reward = a.severity === "high" ? -0.15 : a.severity === "medium" ? -0.07 : -0.02
          info = "Alert ignored."
          this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: a.severity === "high" ? "error" : "warn", msg: `${a.id} ignored (${a.severity})`, reward })
          break
        }
        case "escalate": {
          a.status = "escalated"
          a.confidence = clamp01(a.confidence + 0.05)
          reward = 0.03
          info = "Escalated to Tier-2."
          this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "info", msg: `${a.id}: ${info}`, reward })
          break
        }
        case "resolve": {
          a.status = "resolved"
          reward = 0.06
          info = "Resolved."
          this.state.logs.unshift({ id: uid(), ts: Date.now(), kind: "success", msg: `${a.id}: resolved`, reward })
          break
        }
        default:
          break
      }
    }

    this._mutateEnvironment()
    const unhealthy = this.state.metrics.compromisedHosts * 0.05 + this.state.metrics.anomalyScore * 0.08
    this.state.score = clamp01(prevScore * 0.9 + 0.1 * (0.5 + reward) - unhealthy * 0.1 + 0.05)
    const done = this.state.step >= 200 || this.state.score < 0.15
    return { state: this._clone(), reward, done, info }
  }

  private _clone(): StateSnapshot {
    return JSON.parse(JSON.stringify(this.state))
  }
}

// ---------- Helpers ----------
const clamp01 = (x: number) => Math.max(0, Math.min(1, x))
const uid = () => Math.random().toString(36).slice(2, 9)
const fmtTime = (ts: number) => new Date(ts).toLocaleTimeString()
type ActionKind = "investigate" | "block_ip" | "isolate_host" | "ignore" | "escalate" | "resolve" | "noop"
interface ActionRequest { kind: ActionKind; alertId?: string }
type AppTheme = "cyber" | "slate" | "violet"

// ---------- Demo Users ----------
const DEMO_USERS: Record<string, { password: string; user: User }> = {
  "analyst": {
    password: "soc2024",
    user: { username: "analyst", role: "analyst", name: "Alex Rivera", avatar: "AR" }
  },
  "senior": {
    password: "soc2024",
    user: { username: "senior", role: "senior_analyst", name: "Jordan Kim", avatar: "JK" }
  },
  "lead": {
    password: "soc2024",
    user: { username: "lead", role: "soc_lead", name: "Morgan Chen", avatar: "MC" }
  },
  "admin": {
    password: "sentinel",
    user: { username: "admin", role: "admin", name: "Dr. Samir Patel", avatar: "SP" }
  },
}

// ---------- API Configuration ----------
const API_BASE = (import.meta as any).env?.VITE_API_URL || "http://localhost:8000"

// ---------- Main App with Auth ----------
export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentUser, setCurrentUser] = useState<User | null>(null)
  const [authError, setAuthError] = useState("")

  // Check for existing session
  useEffect(() => {
    const saved = localStorage.getItem("sentinel-session")
    const token = localStorage.getItem("sentinel-token")
    if (saved && token) {
      try {
        const session = JSON.parse(saved)
        if (session.expires > Date.now()) {
          setCurrentUser(session.user)
          setIsAuthenticated(true)
          // Verify token with backend
          fetch(`${API_BASE}/me`, {
            headers: { Authorization: `Bearer ${token}` }
          }).catch(() => {
            // Backend not available, fall back to demo mode
          })
        } else {
          localStorage.removeItem("sentinel-session")
          localStorage.removeItem("sentinel-token")
        }
      } catch {}
    }
  }, [])

  const handleLogin = async (username: string, password: string, mfa: string) => {
    setAuthError("")
    
    // Try backend first
    try {
      const resp = await fetch(`${API_BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, mfa_code: mfa || undefined })
      })
      
      if (resp.ok) {
        const data = await resp.json()
        const session = {
          user: data.user,
          expires: Date.now() + 8 * 60 * 60 * 1000,
        }
        localStorage.setItem("sentinel-session", JSON.stringify(session))
        localStorage.setItem("sentinel-token", data.access_token)
        setCurrentUser(data.user)
        setIsAuthenticated(true)
        return true
      }
    } catch (e) {
      console.log("Backend unavailable, using demo mode")
    }
    
    // Fallback to demo mode
    const demo = DEMO_USERS[username.toLowerCase()]
    
    if (!demo || demo.password !== password) {
      setAuthError("Invalid credentials. Try analyst / soc2024")
      return false
    }
    
    if (mfa && mfa !== "123456") {
      setAuthError("Invalid MFA code. Use 123456 for demo")
      return false
    }

    const session = {
      user: demo.user,
      expires: Date.now() + 8 * 60 * 60 * 1000,
    }
    localStorage.setItem("sentinel-session", JSON.stringify(session))
    setCurrentUser(demo.user)
    setIsAuthenticated(true)
    return true
  }

  const handleLogout = () => {
    localStorage.removeItem("sentinel-session")
    localStorage.removeItem("sentinel-token")
    setIsAuthenticated(false)
    setCurrentUser(null)
  }

  if (!isAuthenticated || !currentUser) {
    return <LoginPortal onLogin={handleLogin} error={authError} />
  }

  return <SOCDashboard user={currentUser} onLogout={handleLogout} />
}

// ---------- Login Portal ----------
function LoginPortal({ onLogin, error }: { onLogin: (u: string, p: string, m: string) => Promise<boolean>; error: string }) {
  const [username, setUsername] = useState("analyst")
  const [password, setPassword] = useState("soc2024")
  const [mfa, setMfa] = useState("")
  const [showMfa, setShowMfa] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [capsLock, setCapsLock] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!showMfa) {
      setShowMfa(true)
      return
    }
    setIsLoading(true)
    const success = await onLogin(username, password, mfa)
    if (!success) setIsLoading(false)
  }

  return (
    <div className="min-h-screen bg-[#030508] text-zinc-100 flex items-center justify-center relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(6,182,212,0.15),_transparent_60%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,_rgba(168,85,247,0.1),_transparent_50%)]" />
        <div className="absolute inset-0 opacity-[0.03]" style={{
          backgroundImage: `linear-gradient(rgba(148,163,184,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.5) 1px, transparent 1px)`,
          backgroundSize: '50px 50px'
        }} />
      </div>

      {/* Floating orbs */}
      <div className="absolute top-20 left-[10%] w-72 h-72 bg-cyan-500/10 rounded-full blur-[120px] animate-pulse" />
      <div className="absolute bottom-20 right-[10%] w-96 h-96 bg-violet-500/10 rounded-full blur-[140px] animate-pulse [animation-delay:1s]" />

      <div className="relative z-10 w-full max-w-6xl mx-auto px-6 py-12 grid lg:grid-cols-2 gap-12 items-center">
        {/* Left - Branding */}
        <div className="hidden lg:block">
          <div className="mb-8 flex items-center gap-3">
            <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-cyan-400 to-cyan-600 grid place-items-center shadow-lg shadow-cyan-500/20 ring-1 ring-white/10">
              <ShieldIconBig />
            </div>
            <div>
              <div className="text-2xl font-semibold tracking-tight">Sentinel-Core</div>
              <div className="text-sm text-zinc-500 -mt-1">Autonomous Cloud-Native SOC</div>
            </div>
          </div>

          <h1 className="text-[42px] font-bold leading-[1.1] tracking-tight mb-4">
            Threat detection
            <br />
            <span className="bg-gradient-to-r from-cyan-400 to-violet-400 bg-clip-text text-transparent">reimagined.</span>
          </h1>
          <p className="text-zinc-400 text-lg mb-8 max-w-md">
            AI-powered security operations center. Monitor, investigate, and neutralize threats in real-time across your cloud-native infrastructure.
          </p>

          <div className="space-y-3">
            {[
              { icon: <RadarIcon />, text: "Real-time alert correlation across 12+ data sources" },
              { icon: <BrainIcon />, text: "Autonomous investigation with 94.7% accuracy" },
              { icon: <BoltBigIcon />, text: "Sub-second response to critical threats" },
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-3 text-sm text-zinc-300">
                <div className="grid h-8 w-8 place-items-center rounded-lg bg-white/[0.03] ring-1 ring-white/10">
                  {item.icon}
                </div>
                {item.text}
              </div>
            ))}
          </div>

          <div className="mt-12 flex items-center gap-6 text-xs text-zinc-600">
            <div className="flex items-center gap-1.5">
              <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              All systems operational
            </div>
            <div>99.99% uptime</div>
            <div>SOC2 Type II</div>
          </div>
        </div>

        {/* Right - Login Form */}
        <div className="w-full max-w-[420px] mx-auto lg:ml-auto">
          <div className="lg:hidden mb-8 flex items-center justify-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-400 to-cyan-600 grid place-items-center">
              <ShieldIconBig />
            </div>
            <div className="text-xl font-semibold">Sentinel-Core</div>
          </div>

          <div className="rounded-[28px] border border-white/10 bg-zinc-950/70 backdrop-blur-2xl p-8 shadow-2xl shadow-black/50">
            <div className="mb-6">
              <h2 className="text-2xl font-semibold tracking-tight">Secure Access</h2>
              <p className="text-sm text-zinc-500 mt-1">Sign in to your SOC workstation</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="text-[12px] font-medium text-zinc-400 uppercase tracking-wider mb-1.5 block">Operator ID</label>
                <div className="relative group">
                  <div className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600 group-focus-within:text-cyan-400 transition-colors">
                    <UserIcon />
                  </div>
                  <input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    onKeyUp={e => setCapsLock(e.getModifierState('CapsLock'))}
                    className="w-full h-11 pl-10 pr-3 rounded-xl bg-zinc-900/70 border border-white/10 text-[14px] outline-none transition-all focus:bg-zinc-900 focus:border-cyan-500/50 focus:ring-4 focus:ring-cyan-500/10"
                    placeholder="analyst"
                    autoComplete="username"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-[12px] font-medium text-zinc-400 uppercase tracking-wider mb-1.5 block">Passphrase</label>
                <div className="relative group">
                  <div className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600 group-focus-within:text-cyan-400 transition-colors">
                    <LockIcon />
                  </div>
                  <input
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    onKeyUp={e => setCapsLock(e.getModifierState('CapsLock'))}
                    className="w-full h-11 pl-10 pr-3 rounded-xl bg-zinc-900/70 border border-white/10 text-[14px] outline-none transition-all focus:bg-zinc-900 focus:border-cyan-500/50 focus:ring-4 focus:ring-cyan-500/10"
                    placeholder="••••••••"
                    autoComplete="current-password"
                    required
                  />
                </div>
                {capsLock && <div className="mt-1.5 text-[11px] text-amber-400 flex items-center gap-1"><CautionIcon /> Caps Lock is on</div>}
              </div>

              {showMfa && (
                <div className="animate-in fade-in slide-in-from-top-1 duration-300">
                  <label className="text-[12px] font-medium text-zinc-400 uppercase tracking-wider mb-1.5 block">MFA Code</label>
                  <div className="relative group">
                    <div className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600 group-focus-within:text-cyan-400 transition-colors">
                      <KeyIcon />
                    </div>
                    <input
                      type="text"
                      value={mfa}
                      onChange={e => setMfa(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="w-full h-11 pl-10 pr-3 rounded-xl bg-zinc-900/70 border border-white/10 text-[14px] outline-none transition-all focus:bg-zinc-900 focus:border-cyan-500/50 focus:ring-4 focus:ring-cyan-500/10 font-mono tracking-widest"
                      placeholder="123456"
                      inputMode="numeric"
                      autoFocus
                    />
                  </div>
                  <div className="mt-1.5 text-[11px] text-zinc-500">Enter code from authenticator app</div>
                </div>
              )}

              {error && (
                <div className="rounded-xl bg-red-500/10 border border-red-500/20 px-3 py-2.5 flex items-start gap-2 animate-in fade-in">
                  <div className="text-red-400 mt-0.5"><ErrorIcon /></div>
                  <div className="text-[13px] text-red-300 leading-snug">{error}</div>
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="relative w-full h-11 rounded-xl bg-white text-black font-medium text-[14px] overflow-hidden group disabled:opacity-60"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 to-violet-400 opacity-0 group-hover:opacity-10 transition-opacity" />
                <div className="relative flex items-center justify-center gap-2">
                  {isLoading ? (
                    <>
                      <div className="h-4 w-4 border-2 border-black/20 border-t-black rounded-full animate-spin" />
                      Authenticating...
                    </>
                  ) : showMfa ? (
                    <>Verify & Enter SOC</>
                  ) : (
                    <>Continue</>
                  )}
                </div>
              </button>
            </form>

            <div className="mt-6 pt-6 border-t border-white/5">
              <div className="text-[12px] text-zinc-500 mb-2.5 font-medium">Demo Credentials</div>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(DEMO_USERS).map(([key, { user }]) => (
                  <button
                    key={key}
                    onClick={() => { setUsername(key); setPassword(DEMO_USERS[key].password); setShowMfa(false) }}
                    className="text-left px-2.5 py-2 rounded-lg bg-white/[0.02] hover:bg-white/[0.05] border border-white/5 transition-colors group"
                  >
                    <div className="text-[11px] font-mono text-zinc-500 group-hover:text-zinc-400">{key}</div>
                    <div className="text-[12px] text-zinc-300">{user.role.replace('_', ' ')}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-6 text-center text-[11px] text-zinc-600">
            Protected by Sentinel-Core v3.2.1 • FIPS 140-2 Level 3
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------- SOC Dashboard ----------
function SOCDashboard({ user, onLogout }: { user: User; onLogout: () => void }) {
  const coreRef = useRef<SentinelCore | null>(null)
  if (!coreRef.current) coreRef.current = new SentinelCore()

  const [state, setState] = useState<StateSnapshot>(() => coreRef.current!.getState())
  const [selectedAlert, setSelectedAlert] = useState<string>(state.alerts[0]?.id ?? "")
  const [filterSev, setFilterSev] = useState<"all" | Severity>("all")
  const [filterType, setFilterType] = useState<"all" | Alert["type"]>("all")
  const [autoPlay, setAutoPlay] = useState(false)
  const [speed, setSpeed] = useState(900)
  const [currentPage, setCurrentPage] = useState<1 | 2>(1)
  const [showInfoPanel, setShowInfoPanel] = useState(false)
  const [infoSection, setInfoSection] = useState<"how" | "theme" | "about" | null>("how")
  const [theme, setTheme] = useState<AppTheme>("cyber")

  const themeTone =
    theme === "slate"
      ? { accent: "text-sky-300", ring: "ring-sky-400/30", button: "bg-sky-500/20 text-sky-200 ring-sky-400/30" }
      : theme === "violet"
        ? { accent: "text-violet-300", ring: "ring-violet-400/30", button: "bg-violet-500/20 text-violet-200 ring-violet-400/30" }
        : { accent: "text-cyan-300", ring: "ring-cyan-400/30", button: "bg-cyan-500/20 text-cyan-200 ring-cyan-400/30" }

  const sidebarTone =
    theme === "slate"
      ? {
          shell: "from-[#061425] via-[#051026] to-[#040b1d]",
          glow: "bg-sky-400/20",
          edge: "from-sky-400/70 via-sky-300/20 to-transparent",
          active: "bg-sky-500/18 text-sky-100 ring-sky-300/35",
          idle: "text-white/75 hover:bg-white/5 hover:text-white",
        }
      : theme === "violet"
        ? {
            shell: "from-[#130624] via-[#0c0f22] to-[#090d1a]",
            glow: "bg-violet-400/20",
            edge: "from-violet-400/75 via-fuchsia-300/20 to-transparent",
            active: "bg-violet-500/20 text-violet-100 ring-violet-300/35",
            idle: "text-white/75 hover:bg-white/5 hover:text-white",
          }
        : {
            shell: "from-[#04172a] via-[#04142e] to-[#041022]",
            glow: "bg-cyan-400/20",
            edge: "from-cyan-400/75 via-teal-300/20 to-transparent",
            active: "bg-cyan-500/20 text-cyan-100 ring-cyan-300/35",
            idle: "text-white/75 hover:bg-white/5 hover:text-white",
          }

  useEffect(() => {
    if (!state.alerts.find(a => a.id === selectedAlert)) {
      setSelectedAlert(state.alerts[0]?.id ?? "")
    }
  }, [state.alerts, selectedAlert])

  useEffect(() => {
    if (!autoPlay) return
    const id = setInterval(() => { doAgentStep() }, speed)
    return () => clearInterval(id)
  }, [autoPlay, speed])

  const filteredAlerts = useMemo(() => {
    return state.alerts.filter(a =>
      (filterSev === "all" || a.severity === filterSev) &&
      (filterType === "all" || a.type === filterType)
    )
  }, [state.alerts, filterSev, filterType])

  const doReset = () => {
    const s = coreRef.current!.reset()
    setState(s)
  }

  const doStep = (kind: ActionKind) => {
    const res = coreRef.current!.step({ kind, alertId: selectedAlert })
    setState(res.state)
  }

  const doAgentStep = () => {
    const open = state.alerts.filter(a => a.status === "open" || a.status === "investigating")
    const high = open.find(a => a.severity === "high")
    const med = open.find(a => a.severity === "medium")
    const next = high ?? med ?? open[0]
    const kind: ActionKind = high ? "block_ip" : med ? "investigate" : "escalate"
    if (next) {
      setSelectedAlert(next.id)
      const res = coreRef.current!.step({ kind, alertId: next.id })
      setState(res.state)
    } else {
      const res = coreRef.current!.step({ kind: "noop" })
      setState(res.state)
    }
  }

  const runManualStep = () => {
    const res = coreRef.current!.step({ kind: "noop", alertId: selectedAlert })
    setState(res.state)
  }

  return (
    <div className="min-h-screen bg-[#070a0f] text-zinc-100">
      <div className={`pointer-events-none fixed inset-0 -z-10 opacity-[0.2] ${theme === "violet" ? "bg-[radial-gradient(ellipse_at_top,_rgba(167,139,250,0.2),_transparent_60%)]" : theme === "slate" ? "bg-[radial-gradient(ellipse_at_top,_rgba(56,189,248,0.2),_transparent_60%)]" : "bg-[radial-gradient(ellipse_at_top,_rgba(34,211,238,0.2),_transparent_60%)]"}`} />
      <div className="pointer-events-none fixed inset-0 -z-10 opacity-[0.12]">
        <svg className="absolute inset-0 h-full w-full" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(148,163,184,0.15)" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>
      </div>

      <div className="flex min-h-screen">
        <aside className={`relative sticky top-0 flex h-screen w-[218px] shrink-0 flex-col border-r border-white/10 bg-gradient-to-b ${sidebarTone.shell} px-3 py-4`}>
          <div className={`absolute inset-y-0 left-0 w-[2px] bg-gradient-to-b ${sidebarTone.edge}`} />
          <div className={`absolute left-0 top-0 h-16 w-full blur-2xl ${sidebarTone.glow}`} />
          <button
            onClick={() => {
              setInfoSection("how")
              setShowInfoPanel(true)
            }}
            className="relative w-fit text-left"
          >
            <div className="text-[10px] uppercase tracking-[0.22em] text-white/45">SOC</div>
            <div className="text-[16px] font-semibold tracking-tight text-white">Sentinel-Core</div>
          </button>

          <div className="mt-9 space-y-2.5">
            <button
              onClick={() => setCurrentPage(1)}
              className={`flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-base ring-1 ring-transparent transition ${currentPage === 1 ? sidebarTone.active : sidebarTone.idle}`}
            >
              <GridIcon />
              <span className="text-[17px]">Operation</span>
            </button>
            <button
              onClick={() => setCurrentPage(2)}
              className={`flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-base ring-1 ring-transparent transition ${currentPage === 2 ? sidebarTone.active : sidebarTone.idle}`}
            >
              <ChartIconSmall />
              <span className="text-[17px]">Analytics</span>
            </button>
          </div>

          <div className="mt-auto border-t border-white/10 pt-4">
            <div className="flex items-center gap-3">
              <div className="grid h-9 w-9 place-items-center rounded-full bg-blue-600 text-white ring-1 ring-blue-300/30">
                <UserIcon />
              </div>
              <div>
                <div className="text-[15px] font-semibold leading-tight text-white">Security Analyst</div>
                <div className="text-xs text-white/60">ID: SOC-001</div>
              </div>
            </div>
            <button onClick={onLogout} className="mt-4 text-xs text-white/50 hover:text-white/80">Sign out</button>
          </div>
        </aside>

        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-20 border-b border-white/10 bg-black/35 px-5 py-3 backdrop-blur-xl">
            <div className="flex flex-wrap items-center gap-3">
              <div>
                <div className="text-sm font-medium">{currentPage === 1 ? "Operations Center" : "Analytics Center"}</div>
                <div className="text-xs text-zinc-500">Autonomous Cloud-Native SOC Analyst</div>
              </div>
              <BadgeScore score={state.score} />
              <div className="rounded-lg bg-zinc-900/70 px-2.5 py-1 text-xs ring-1 ring-white/10">Selected Alert: <span className="font-mono text-zinc-300">{selectedAlert || "N/A"}</span></div>
              <button onClick={doReset} className="rounded-lg bg-zinc-900/70 px-2.5 py-1 text-xs ring-1 ring-white/10 hover:bg-zinc-800/80">Reset Environment</button>
              <button onClick={runManualStep} className={`rounded-lg px-2.5 py-1 text-xs ring-1 ${themeTone.button}`}>Run Step</button>
              <button onClick={() => setAutoPlay(v => !v)} className={`rounded-lg px-2.5 py-1 text-xs ring-1 ${autoPlay ? "bg-emerald-500/20 text-emerald-200 ring-emerald-400/30" : "bg-zinc-900/70 text-zinc-200 ring-white/10"}`}>
                Auto-play: {autoPlay ? "On" : "Off"}
              </button>
              <input type="range" min={400} max={1800} step={100} value={speed} onChange={e => setSpeed(+e.target.value)} className="h-2 w-28 accent-cyan-500" title="Autoplay speed (ms/step)" />
            </div>
          </header>

          <main className="px-5 py-6">
        {currentPage === 1 ? (
          /* Page 1: Operations - Alerts, Actions, Logs */
          <div className="grid grid-cols-12 gap-4">
            <section className="col-span-12 lg:col-span-8 space-y-4">
              <Card title="Alerts Panel" subtitle="Real-time detections across VPC, EDR, WAF, CloudTrail" icon={<AlertIcon />}>
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  <Select label="Severity" value={filterSev} onChange={v => setFilterSev(v as any)} options={["all", "high", "medium", "low"]} />
                  <Select label="Type" value={filterType} onChange={v => setFilterType(v as any)} options={["all", "BruteForce", "Malware", "Exfiltration", "Phishing", "PortScan", "Lateral", "Ransomware"]} />
                  <div className="ml-auto text-xs text-zinc-400">{filteredAlerts.length} / {state.alerts.length} shown</div>
                </div>

                <div className="overflow-hidden rounded-xl ring-1 ring-white/10">
                  <div className="max-h-[400px] overflow-auto">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 z-10 bg-zinc-950/90 backdrop-blur supports-[backdrop-filter]:bg-zinc-950/60">
                        <tr className="text-left text-zinc-400">
                          <Th>ID</Th><Th>Time</Th><Th>Type</Th><Th>Severity</Th><Th>Confidence</Th><Th>Src IP</Th><Th>Host</Th><Th>Status</Th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {filteredAlerts.map(a => (
                          <tr key={a.id} onClick={() => setSelectedAlert(a.id)} className={`cursor-pointer hover:bg-white/[0.03] transition ${selectedAlert === a.id ? "bg-cyan-500/5" : ""}`}>
                            <Td mono>{a.id}</Td>
                            <Td>{fmtTime(a.ts)}</Td>
                            <Td>{a.type}</Td>
                            <Td><SeverityPill sev={a.severity} /></Td>
                            <Td>{Math.round(a.confidence * 100)}%</Td>
                            <Td mono>{a.srcIp}</Td>
                            <Td mono>{a.host}</Td>
                            <Td><StatusPill status={a.status} /></Td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </Card>

              <Card title="Action Controls" subtitle="Respond to selected alert" icon={<BoltIcon />}>
                <div className="flex flex-wrap items-center gap-2">
                  <div className="mr-2 text-xs text-zinc-400">Selected</div>
                  <div className="rounded-lg bg-zinc-900 px-2.5 py-1.5 text-sm ring-1 ring-white/10 font-mono">{selectedAlert || "—"}</div>
                  <div className="ml-auto flex flex-wrap gap-2">
                    <button onClick={() => doStep("investigate")} className="btn"><SearchIcon /> Investigate</button>
                    <button onClick={() => doStep("block_ip")} className="btn"><BanIcon /> Block IP</button>
                    <button onClick={() => doStep("isolate_host")} className="btn"><ShieldLockIcon /> Isolate Host</button>
                    <button onClick={() => doStep("ignore")} className="btn-danger"><EyeOffIcon /> Ignore</button>
                    <button onClick={() => doStep("escalate")} className="btn"><ArrowUpIcon /> Escalate</button>
                    <button onClick={() => doStep("resolve")} className="btn-success"><CheckIcon /> Resolve</button>
                  </div>
                </div>
                <div className="mt-3 text-[11px] text-zinc-500">Tip: Use keyboard shortcuts — <kbd className="kbd">B</kbd> Block • <kbd className="kbd">I</kbd> Investigate • <kbd className="kbd">S</kbd> Isolate</div>
              </Card>
            </section>

            <section className="col-span-12 lg:col-span-4 space-y-4">
              <Card title="Activity Logs" subtitle="Actions, rewards, and system changes" icon={<LogsIcon />}>
                <div className="max-h-[500px] overflow-auto pr-1">
                  <ul className="space-y-2">
                    {state.logs.map(l => (
                      <li key={l.id} className="flex items-start gap-3 rounded-lg bg-zinc-950/60 p-2.5 ring-1 ring-white/5">
                        <div className={`mt-0.5 h-2 w-2 rounded-full ${l.kind === "success" ? "bg-emerald-400" : l.kind === "warn" ? "bg-amber-400" : l.kind === "error" ? "bg-red-400" : "bg-zinc-500"}`} />
                        <div className="flex-1">
                          <div className="text-[13px] leading-snug text-zinc-200">{l.msg}</div>
                          <div className="mt-0.5 text-[11px] text-zinc-500">{fmtTime(l.ts)} {typeof l.reward === "number" && <span className="ml-2 text-zinc-400">reward {l.reward > 0 ? "+" : ""}{l.reward.toFixed(2)}</span>}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              </Card>

              {/* Quick Metrics Summary for Page 1 */}
              <Card title="Quick Status" subtitle="Current system state" icon={<GaugeIcon />}>
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-lg bg-zinc-950/60 p-3 ring-1 ring-white/5">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Compromised</div>
                    <div className="text-2xl font-semibold text-red-400">{state.metrics.compromisedHosts}</div>
                    <div className="text-[11px] text-zinc-500">of {state.hosts.length} hosts</div>
                  </div>
                  <div className="rounded-lg bg-zinc-950/60 p-3 ring-1 ring-white/5">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Threat Level</div>
                    <div className="text-2xl font-semibold text-amber-400">{Math.round(state.metrics.threatLevel * 100)}%</div>
                    <div className="text-[11px] text-zinc-500">{state.metrics.threatLevel > 0.6 ? 'Critical' : state.metrics.threatLevel > 0.3 ? 'Elevated' : 'Normal'}</div>
                  </div>
                </div>
              </Card>
            </section>
          </div>
        ) : (
          /* Page 2: Analytics - Metrics & Charts */
          <div className="grid grid-cols-12 gap-4">
            <section className="col-span-12 space-y-4">
              {/* System Metrics - Full Width */}
              <Card title="System Metrics" subtitle="Live cloud SOC health monitoring" icon={<GaugeIcon />}>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <MetricTile label="Compromised Hosts" value={`${state.metrics.compromisedHosts}`} sub={`${state.hosts.length} total`} accent="red" />
                  <MetricTile label="Anomaly Score" value={`${(state.metrics.anomalyScore * 100).toFixed(0)}%`} sub="higher is worse" accent="amber" />
                  <MetricTile label="CPU Usage" value={`${(state.metrics.cpu * 100).toFixed(0)}%`} sub="cluster average" accent="cyan" />
                  <MetricTile label="Active Threats" value={`${state.history[state.history.length-1]?.threats || 0}`} sub="current count" accent="violet" />
                </div>
                <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="rounded-xl bg-zinc-950/60 p-4 ring-1 ring-white/5">
                    <div className="mb-3 text-xs text-zinc-400">Threat Level Gauge</div>
                    <div className="h-3 w-full overflow-hidden rounded-full bg-zinc-800">
                      <div className="h-full bg-gradient-to-r from-emerald-400 via-amber-400 to-red-500 transition-all duration-500" style={{ width: `${Math.round(state.metrics.threatLevel * 100)}%` }} />
                    </div>
                    <div className="mt-2 flex justify-between text-[11px]">
                      <span className="text-zinc-500">0%</span>
                      <span className={`font-medium ${state.metrics.threatLevel > 0.7 ? 'text-red-400' : state.metrics.threatLevel > 0.4 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {Math.round(state.metrics.threatLevel * 100)}%
                      </span>
                      <span className="text-zinc-500">100%</span>
                    </div>
                  </div>
                  <div className="rounded-xl bg-zinc-950/60 p-4 ring-1 ring-white/5">
                    <div className="mb-3 text-xs text-zinc-400">Anomaly Score Trend</div>
                    <div className="h-[60px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={state.history.slice(-20)}>
                          <defs>
                            <linearGradient id="anomalyMini" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.5}/>
                              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <Area type="monotone" dataKey="anomaly" stroke="#f59e0b" fill="url(#anomalyMini)" strokeWidth={2} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="rounded-xl bg-zinc-950/60 p-4 ring-1 ring-white/5">
                    <div className="mb-3 text-xs text-zinc-400">Host Risk Distribution</div>
                    <div className="h-[60px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={state.hosts.map(h => ({ id: h.id, risk: Math.round(h.risk * 100) }))}>
                          <Bar dataKey="risk" fill="#22d3ee" radius={[2,2,0,0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>
              </Card>

              {/* System Health Timeline - Full Width */}
              <Card title="System Health Timeline" subtitle="Comprehensive view: Anomaly, CPU, Threats, Compromised hosts over time" icon={<TimelineIcon />}>
                <div className="h-[300px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={state.history} margin={{ left: 0, right: 20, top: 10, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="step" tick={{ fill: "#9ca3af", fontSize: 11 }} />
                      <YAxis yAxisId="left" domain={[0, 1]} tick={{ fill: "#9ca3af", fontSize: 11 }} />
                      <YAxis yAxisId="right" orientation="right" domain={[0, Math.max(12, ...state.history.map(h => Math.max(h.threats, h.compromised) + 2))]} tick={{ fill: "#9ca3af", fontSize: 11 }} />
                      <Tooltip 
                        contentStyle={{ background: "#0a0f17", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, color: "#e5e7eb" }} 
                      />
                      <Legend wrapperStyle={{ color: "#9ca3af", fontSize: 12 }} />
                      <Line yAxisId="left" type="monotone" dataKey="anomaly" stroke="#f59e0b" strokeWidth={2} dot={false} name="Anomaly Score" />
                      <Line yAxisId="left" type="monotone" dataKey="cpu" stroke="#22d3ee" strokeWidth={2} dot={false} name="CPU Usage" />
                      <Line yAxisId="right" type="monotone" dataKey="threats" stroke="#a78bfa" strokeWidth={2} dot={false} name="Active Threats" />
                      <Line yAxisId="right" type="monotone" dataKey="compromised" stroke="#f43f5e" strokeWidth={2} dot={false} name="Compromised Hosts" />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </Card>

              {/* CPU & Anomaly Trend - Detailed View */}
              <Card title="CPU & Anomaly Trend" subtitle="Detailed performance metrics over time" icon={<ChartIcon />}>
                <div className="h-[280px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={state.history.slice(-60)} margin={{ left: 0, right: 20, top: 10, bottom: 0 }}>
                      <defs>
                        <linearGradient id="cpuArea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="anomalyArea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="step" tick={{ fill: "#9ca3af", fontSize: 11 }} />
                      <YAxis domain={[0, 1]} tick={{ fill: "#9ca3af", fontSize: 11 }} />
                      <Tooltip 
                        contentStyle={{ background: "#0a0f17", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, color: "#e5e7eb" }} 
                      />
                      <Legend wrapperStyle={{ color: "#9ca3af", fontSize: 12 }} />
                      <Area type="monotone" dataKey="cpu" stroke="#22d3ee" fill="url(#cpuArea)" name="CPU Usage" strokeWidth={2} />
                      <Area type="monotone" dataKey="anomaly" stroke="#f59e0b" fill="url(#anomalyArea)" name="Anomaly Score" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Card>

              {/* Host Risk Heatmap */}
              <Card title="Host Risk Heatmap" subtitle="Per-host risk levels across infrastructure" icon={<GridIcon />}>
                <div className="grid grid-cols-6 md:grid-cols-12 gap-2">
                  {state.hosts.map(host => {
                    const riskLevel = host.risk > 0.75 ? 'critical' : host.risk > 0.5 ? 'high' : host.risk > 0.25 ? 'medium' : 'low'
                    const colors = {
                      critical: 'bg-red-500/40 border-red-500/60 text-red-200',
                      high: 'bg-amber-500/30 border-amber-500/50 text-amber-200',
                      medium: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-200',
                      low: 'bg-emerald-500/20 border-emerald-500/40 text-emerald-200'
                    }
                    return (
                      <div 
                        key={host.id} 
                        className={`rounded-lg p-3 border ${colors[riskLevel]} transition-all hover:scale-105 cursor-pointer`}
                        title={`${host.id}: Risk ${(host.risk * 100).toFixed(0)}% | CPU ${(host.cpu * 100).toFixed(0)}% | ${host.compromised ? 'COMPROMISED' : 'Clean'}`}
                      >
                        <div className="text-[10px] font-mono opacity-70">{host.id}</div>
                        <div className="text-lg font-semibold">{(host.risk * 100).toFixed(0)}%</div>
                        <div className="text-[9px] opacity-60">{host.compromised ? '⚠️ COMPROMISED' : '✓ Clean'}</div>
                      </div>
                    )
                  })}
                </div>
              </Card>
            </section>
          </div>
        )}
          </main>

          <footer className="px-5 pb-8">
        <div className="rounded-xl border border-white/5 bg-zinc-950/60 p-3 text-xs text-zinc-500">
          <div className="flex flex-wrap items-center gap-3">
            <span className="inline-flex items-center gap-1.5"><Dot className="text-cyan-400" /> Session: {user.name} • {new Date().toLocaleTimeString()}</span>
            <span className="inline-flex items-center gap-1.5"><Dot className="text-emerald-400" /> Simulation mode: frontend mirror</span>
            <span className="inline-flex items-center gap-1.5"><Dot className="text-amber-400" /> Keyboard: B=Block, I=Investigate, S=Isolate, R=Resolve</span>
          </div>
        </div>
          </footer>
        </div>
      </div>

      {showInfoPanel && (
        <div className="fixed inset-0 z-40 flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="h-full w-full max-w-xl border-l border-white/10 bg-zinc-950 p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <div className="text-lg font-semibold">Sentinel-Core</div>
                <div className="text-xs text-zinc-500">Platform information and settings</div>
              </div>
              <button onClick={() => setShowInfoPanel(false)} className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm ring-1 ring-white/10 hover:bg-zinc-800">Close</button>
            </div>

            <div className="space-y-3">
              <InfoPanelSection
                title="How it works"
                isOpen={infoSection === "how"}
                onToggle={() => setInfoSection(prev => prev === "how" ? null : "how")}
                themeTone={themeTone}
              >
                <div className="space-y-2 text-sm text-zinc-300">
                  <p>Sentinel-Core simulates a cloud SOC workflow where alerts are generated from synthetic VPC, EDR, WAF, and CloudTrail telemetry.</p>
                  <p>You triage alerts on the Operation page, run response actions, and receive rewards based on decision quality.</p>
                  <p className="text-zinc-400">Data flow: User action -&gt; /step endpoint -&gt; backend simulation updates state -&gt; UI refreshes alerts, logs, and charts.</p>
                </div>
              </InfoPanelSection>

              <InfoPanelSection
                title="Change theme"
                isOpen={infoSection === "theme"}
                onToggle={() => setInfoSection(prev => prev === "theme" ? null : "theme")}
                themeTone={themeTone}
              >
                <div className="space-y-2 text-sm text-zinc-300">
                  <p>Select the dashboard theme.</p>
                  <div className="grid gap-2">
                    <button onClick={() => setTheme("cyber")} className={`rounded-lg px-3 py-2 text-left ring-1 ${theme === "cyber" ? "bg-cyan-500/20 text-cyan-200 ring-cyan-400/30" : "bg-zinc-900 ring-white/10"}`}>Cyber Teal</button>
                    <button onClick={() => setTheme("slate")} className={`rounded-lg px-3 py-2 text-left ring-1 ${theme === "slate" ? "bg-sky-500/20 text-sky-200 ring-sky-400/30" : "bg-zinc-900 ring-white/10"}`}>Slate Blue</button>
                    <button onClick={() => setTheme("violet")} className={`rounded-lg px-3 py-2 text-left ring-1 ${theme === "violet" ? "bg-violet-500/20 text-violet-200 ring-violet-400/30" : "bg-zinc-900 ring-white/10"}`}>Midnight Violet</button>
                  </div>
                </div>
              </InfoPanelSection>

              <InfoPanelSection
                title="About us"
                isOpen={infoSection === "about"}
                onToggle={() => setInfoSection(prev => prev === "about" ? null : "about")}
                themeTone={themeTone}
              >
                <div className="space-y-2 text-sm text-zinc-300">
                  <p>Sentinel-Core is an autonomous cloud-native SOC analyst built for simulation, analyst training, and agent benchmarking.</p>
                  <p>Core capabilities include alert handling, response orchestration, and reward-based policy evaluation.</p>
                  <p className="text-zinc-400">Contact: research@sentinel-core.local</p>
                </div>
              </InfoPanelSection>
            </div>
          </div>
        </div>
      )}

      <KeyboardShortcuts onBlock={() => doStep("block_ip")} onInvestigate={() => doStep("investigate")} onIsolate={() => doStep("isolate_host")} onResolve={() => doStep("resolve")} />

      <style>{`
        :root { color-scheme: dark; }
        html, body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial; }
        .font-mono, .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
        .btn { display:inline-flex; align-items:center; gap:.5rem; border-radius:.6rem; padding:.5rem .75rem; font-size:.85rem; background:rgba(24,24,27,.7); box-shadow: inset 0 0 0 1px rgba(255,255,255,.08); transition: all .15s; }
        .btn:hover { background: rgba(39,39,42,.8); }
        .btn-success { display:inline-flex; align-items:center; gap:.5rem; border-radius:.6rem; padding:.5rem .75rem; font-size:.85rem; background: rgba(16,185,129,.15); box-shadow: inset 0 0 0 1px rgba(16,185,129,.35); color: rgb(167,243,208); }
        .btn-success:hover { background: rgba(16,185,129,.22); }
        .btn-danger { display:inline-flex; align-items:center; gap:.5rem; border-radius:.6rem; padding:.5rem .75rem; font-size:.85rem; background: rgba(244,63,94,.12); box-shadow: inset 0 0 0 1px rgba(244,63,94,.35); color: rgb(254,205,211); }
        .btn-danger:hover { background: rgba(244,63,94,.2); }
        .kbd { border:1px solid rgba(255,255,255,.15); background: rgba(255,255,255,.06); padding:.05rem .35rem; border-radius:.35rem; font-family:"JetBrains Mono", monospace; font-size:11px; }
      `}</style>
    </div>
  )
}

// ---------- UI Components ----------
function InfoPanelSection({
  title,
  isOpen,
  onToggle,
  themeTone,
  children,
}: {
  title: string
  isOpen: boolean
  onToggle: () => void
  themeTone: { accent: string; ring: string; button: string }
  children: React.ReactNode
}) {
  return (
    <section className="rounded-xl border border-white/10 bg-zinc-900/40">
      <button
        onClick={onToggle}
        className={`flex w-full items-center justify-between rounded-xl px-3 py-2 text-left text-sm ring-1 ring-transparent transition ${isOpen ? themeTone.button : "text-zinc-200 hover:bg-white/[0.04]"}`}
      >
        <span className="font-medium">{title}</span>
        <span className="text-xs text-zinc-400">{isOpen ? "Hide" : "Open"}</span>
      </button>
      {isOpen && <div className="px-3 pb-3">{children}</div>}
    </section>
  )
}

function Card({ title, subtitle, icon, children }: { title: string; subtitle?: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-white/5 bg-gradient-to-b from-zinc-900/70 to-zinc-950/70 p-4 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.03)]">
      <div className="mb-3 flex items-center gap-2">
        {icon && <div className="grid h-7 w-7 place-items-center rounded-lg bg-white/5 ring-1 ring-white/10">{icon}</div>}
        <div>
          <div className="text-[15px] font-medium tracking-wide">{title}</div>
          {subtitle && <div className="text-[12px] text-zinc-400">{subtitle}</div>}
        </div>
      </div>
      {children}
    </div>
  )
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-zinc-500">{children}</th>
}
function Td({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  return <td className={`px-3 py-2 align-middle text-zinc-200 ${mono ? "font-mono text-[12px]" : "text-[13px]"}`}>{children}</td>
}

function SeverityPill({ sev }: { sev: Severity }) {
  const map = {
    high: "bg-red-500/15 text-red-300 ring-red-500/30",
    medium: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
    low: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  } as const
  return <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] ring-1 ${map[sev]}`}>{sev.toUpperCase()}</span>
}
function StatusPill({ status }: { status: AlertStatus }) {
  const color =
    status === "open" ? "text-zinc-300 ring-white/15 bg-white/5" :
    status === "investigating" ? "text-cyan-300 ring-cyan-400/30 bg-cyan-500/10" :
    status === "blocked" ? "text-emerald-300 ring-emerald-400/30 bg-emerald-500/10" :
    status === "isolated" ? "text-violet-300 ring-violet-400/30 bg-violet-500/10" :
    status === "ignored" ? "text-amber-300 ring-amber-400/30 bg-amber-500/10" :
    status === "escalated" ? "text-sky-300 ring-sky-400/30 bg-sky-500/10" :
    "text-zinc-300 ring-white/15 bg-white/5"
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] ring-1 ${color}`}>{status}</span>
}
function MetricTile({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent: "red" | "amber" | "cyan" | "violet" }) {
  const ring = accent === "red" ? "ring-red-400/30" : accent === "amber" ? "ring-amber-400/30" : accent === "violet" ? "ring-violet-400/30" : "ring-cyan-400/30"
  const bg = accent === "red" ? "from-red-500/10" : accent === "amber" ? "from-amber-500/10" : accent === "violet" ? "from-violet-500/10" : "from-cyan-500/10"
  return (
    <div className={`relative overflow-hidden rounded-xl bg-gradient-to-b ${bg} to-transparent p-3 ring-1 ${ring}`}>
      <div className="text-[11px] uppercase tracking-wider text-zinc-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {sub && <div className="text-[11px] text-zinc-500">{sub}</div>}
    </div>
  )
}
function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <div>
      <div className="mb-1 text-xs text-zinc-400">{label}</div>
      <select value={value} onChange={e => onChange(e.target.value)} className="rounded-lg bg-zinc-900/70 px-2.5 py-1.5 text-sm ring-1 ring-white/10 outline-none focus:ring-cyan-400/40">
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  )
}
function BadgeScore({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  const color = pct >= 70 ? "text-emerald-300 ring-emerald-400/30 bg-emerald-500/10" : pct >= 40 ? "text-amber-300 ring-amber-400/30 bg-amber-500/10" : "text-red-300 ring-red-400/30 bg-red-500/10"
  return (
    <div className={`hidden sm:flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs ring-1 ${color}`}>
      <span className="opacity-70">Score</span>
      <span className="font-mono">{pct}%</span>
    </div>
  )
}
function Dot({ className = "" }: { className?: string }) {
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${className}`} />
}

// ---------- Icons ----------
function ShieldIconBig() { return <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3.5v6c0 5.5-3.8 9.5-8 11-4.2-1.5-8-5.5-8-11v-6L12 2z" stroke="white" strokeWidth="1.5" fill="white" fillOpacity="0.1"/></svg> }
function ChartIconSmall() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M4 20V9M10 20V4M16 20v-7M22 20v-4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"/></svg> }
function GridIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="3" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5"/><rect x="14" y="3" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5"/><rect x="3" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5"/><rect x="14" y="14" width="7" height="7" rx="1" stroke="currentColor" strokeWidth="1.5"/></svg> }
function AlertIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3L12 3z" stroke="#f59e0b" strokeWidth="1.5" fill="rgba(245,158,11,.15)"/></svg> }
function BoltIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" stroke="#a78bfa" strokeWidth="1.5" fill="rgba(167,139,250,.18)"/></svg> }
function LogsIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h10M4 18h7" stroke="#94a3b8" strokeWidth="1.5"/></svg> }
function GaugeIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="13" r="8" stroke="#22d3ee" strokeWidth="1.5"/><path d="M12 13l4-2" stroke="#22d3ee" strokeWidth="1.5"/></svg> }
function TimelineIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M3 12h18M7 7v10M17 7v10" stroke="#94a3b8" strokeWidth="1.5"/></svg> }
function ChartIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M4 19V5M4 19h16M9 15V9m4 6V7m4 8v-4" stroke="#94a3b8" strokeWidth="1.5"/></svg> }
function SearchIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5"/><path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="1.5"/></svg> }
function BanIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5"/><path d="M6 18l12-12" stroke="currentColor" strokeWidth="1.5"/></svg> }
function ShieldLockIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6l7-3z" stroke="currentColor" strokeWidth="1.3"/><rect x="9" y="11" width="6" height="5" rx="1.2" stroke="currentColor" strokeWidth="1.3"/><path d="M10.5 11V9.5a1.5 1.5 0 113 0V11" stroke="currentColor" strokeWidth="1.3"/></svg> }
function EyeOffIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M3 3l18 18M10.6 10.6A3 3 0 0012 15a3 3 0 002.4-4.4M6.5 6.7C4.3 8 2.9 9.7 2 12c1.7 4.3 5.4 7 10 7 1.5 0 2.8-.3 4-.8M17.5 17.3c2.2-1.3 3.6-3 4.5-5.3-1-2.5-2.7-4.4-5-5.7" stroke="currentColor" strokeWidth="1.4"/></svg> }
function ArrowUpIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 19V5M5 12l7-7 7 7" stroke="currentColor" strokeWidth="1.5"/></svg> }
function CheckIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M5 13l4 4 10-10" stroke="currentColor" strokeWidth="1.8"/></svg> }
function UserIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="4" stroke="currentColor" strokeWidth="1.5"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="currentColor" strokeWidth="1.5"/></svg> }
function LockIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="1.5"/><path d="M8 11V8a4 4 0 118 0v3" stroke="currentColor" strokeWidth="1.5"/></svg> }
function KeyIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="8" cy="15" r="4" stroke="currentColor" strokeWidth="1.5"/><path d="M11 12l8-8" stroke="currentColor" strokeWidth="1.5"/><path d="M19 4h-3v3" stroke="currentColor" strokeWidth="1.5"/></svg> }
function ErrorIcon() { return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5"/><path d="M12 8v5M12 16h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg> }
function CautionIcon() { return <svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3L12 3z" stroke="currentColor" strokeWidth="1.5" fill="currentColor" fillOpacity="0.2"/></svg> }
function RadarIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.2" opacity="0.5"/><circle cx="12" cy="12" r="5" stroke="currentColor" strokeWidth="1.2" opacity="0.7"/><path d="M12 3v9l6-3" stroke="currentColor" strokeWidth="1.2"/></svg> }
function BrainIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M9 4a3 3 0 00-3 3v1a3 3 0 003 3h0M15 4a3 3 0 013 3v1a3 3 0 01-3 3h0M9 13a3 3 0 00-3 3v1a3 3 0 003 3h0M15 13a3 3 0 013 3v1a3 3 0 01-3 3h0" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg> }
function BoltBigIcon() { return <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" stroke="currentColor" strokeWidth="1.2" fill="currentColor" fillOpacity="0.2"/></svg> }
function KeyboardShortcuts({ onBlock, onInvestigate, onIsolate, onResolve }: { onBlock: () => void; onInvestigate: () => void; onIsolate: () => void; onResolve: () => void }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const k = e.key.toLowerCase()
      if (k === "b") onBlock()
      if (k === "i") onInvestigate()
      if (k === "s") onIsolate()
      if (k === "r") onResolve()
    }
    window.addEventListener("keydown", h)
    return () => window.removeEventListener("keydown", h)
  }, [onBlock, onInvestigate, onIsolate, onResolve])
  return null
}