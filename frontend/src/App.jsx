import { useState, useEffect, useCallback } from "react";
import {
  ShieldCheck, ShieldAlert, ShieldX, Check, X, ArrowRight, RotateCcw,
  Link2, Mail, Clock, Shuffle, Radar, RefreshCw, WifiOff, LayoutDashboard,
  History, GraduationCap, Network, Brain, Fingerprint, Activity,
  TrendingUp, Users, Github,
} from "lucide-react";

const API_BASE = "http://localhost:5000";

/* =========================================================================
   SHARED STYLES / HELPERS
   ========================================================================= */

const VERDICT_STYLE = {
  phishing: { label: "Phishing", icon: ShieldX, ring: "border-rose-400", bg: "bg-rose-400/10", text: "text-rose-300", badge: "bg-rose-400/15 text-rose-300", dot: "bg-rose-400" },
  caution: { label: "Caution", icon: ShieldAlert, ring: "border-amber-400", bg: "bg-amber-400/10", text: "text-amber-300", badge: "bg-amber-400/15 text-amber-300", dot: "bg-amber-400" },
  safe: { label: "Safe", icon: ShieldCheck, ring: "border-emerald-400", bg: "bg-emerald-400/10", text: "text-emerald-300", badge: "bg-emerald-400/15 text-emerald-300", dot: "bg-emerald-400" },
};
const REASON_ICONS = { model: Brain, masking: Shuffle, anomaly: Radar, content: Clock, clean: ShieldCheck };

function Card({ children, className = "" }) {
  return <div className={`bg-slate-800/60 border border-slate-700 rounded-2xl ${className}`}>{children}</div>;
}

/* =========================================================================
   RESULT CARD (shared by Checker)
   ========================================================================= */

function ResultCard({ result }) {
  if (!result) return null;
  if (result.error) {
    return <div className="mt-5 bg-slate-800 border border-rose-400 rounded-2xl p-5 text-rose-300 text-sm">{result.error}</div>;
  }
  const cfg = VERDICT_STYLE[result.verdict];
  const Icon = cfg.icon;
  return (
    <div className={`mt-5 bg-slate-800 border ${cfg.ring} rounded-2xl p-5`}>
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-full ${cfg.bg} flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-5 h-5 ${cfg.text}`} />
        </div>
        <div>
          <p className={`font-semibold ${cfg.text}`}>{cfg.label === "Phishing" ? "Likely phishing" : cfg.label === "Caution" ? "Use caution" : "Looks safe"}</p>
          <p className="text-xs text-slate-400">Risk score {result.score} / 100</p>
        </div>
        <span className={`ml-auto text-xs px-3 py-1 rounded-md ${cfg.badge}`}>
          {result.verdict === "phishing" ? "High risk" : result.verdict === "caution" ? "Medium risk" : "Low risk"}
        </span>
      </div>
      <div className="border-t border-slate-700 my-4" />
      <p className="text-xs text-slate-400 mb-2">Why this result</p>
      <div className="grid gap-2">
        {result.reasons.map((r, i) => {
          const RIcon = REASON_ICONS[r.type] || ShieldAlert;
          return (
            <div key={i} className="flex items-center gap-2 text-sm text-slate-200">
              <RIcon className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span>{r.text}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* =========================================================================
   HOME / DASHBOARD SCREEN
   ========================================================================= */

const PIPELINE_STEPS = [
  { icon: Brain, title: "Supervised Classifier", text: "Random Forest trained on labeled phishing vs legitimate URLs \u2014 catches known attack patterns." },
  { icon: Shuffle, title: "Masking Detector", text: "Checks for punycode domains, suspicious redirect chains, and cloaking \u2014 disguise techniques, not just blacklists." },
  { icon: Radar, title: "Anomaly Detector", text: "Isolation Forest trained only on legitimate URLs \u2014 flags novel, zero-hour phishing no one has seen before." },
];

function StatBlock({ label, value, icon: Icon, color }) {
  return (
    <Card className="p-4 flex items-center gap-3">
      <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${color}`}>
        <Icon className="w-5 h-5 text-slate-900" />
      </div>
      <div>
        <p className="text-2xl font-bold text-white leading-none">{value}</p>
        <p className="text-xs text-slate-400 mt-1">{label}</p>
      </div>
    </Card>
  );
}

function HomeScreen({ onNavigate }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/stats`).then((r) => r.json()).then(setStats).catch(() => setStats(null));
  }, []);

  return (
    <div className="max-w-5xl mx-auto p-6 md:p-10">
      {/* Hero */}
      <div className="mb-10">
        <div className="inline-flex items-center gap-2 text-xs text-cyan-300 bg-cyan-400/10 border border-cyan-400/30 rounded-full px-3 py-1 mb-4">
          <Fingerprint className="w-3.5 h-3.5" /> Three-layer detection · Network + application layer
        </div>
        <h1 className="text-3xl md:text-4xl font-bold text-white leading-tight mb-3">
          Catch phishing attacks <span className="text-cyan-400">before they catch you</span>
        </h1>
        <p className="text-slate-400 max-w-xl leading-relaxed">
          PhishGuard combines a supervised classifier, a masking/cloaking detector, and a non-signature
          anomaly engine with live network monitoring via Snort — so a link doesn't need to match a known
          threat to get flagged.
        </p>
        <div className="flex gap-3 mt-6">
          <button onClick={() => onNavigate("checker")} className="flex items-center gap-2 bg-cyan-400 text-slate-900 font-semibold px-5 py-2.5 rounded-lg hover:bg-cyan-300 transition-colors">
            Run a scan <ArrowRight className="w-4 h-4" />
          </button>
          <button onClick={() => onNavigate("awareness")} className="flex items-center gap-2 border border-slate-700 text-slate-300 px-5 py-2.5 rounded-lg hover:border-slate-500 transition-colors">
            Try the awareness quiz
          </button>
        </div>
      </div>

      {/* Live stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-10">
        <StatBlock label="Total scans" value={stats?.total_scans ?? "\u2014"} icon={Activity} color="bg-cyan-400" />
        <StatBlock label="Flagged phishing" value={stats?.phishing ?? "\u2014"} icon={ShieldX} color="bg-rose-400" />
        <StatBlock label="URLs checked" value={stats?.urls_scanned ?? "\u2014"} icon={Link2} color="bg-amber-400" />
        <StatBlock label="Emails checked" value={stats?.emails_scanned ?? "\u2014"} icon={Mail} color="bg-emerald-400" />
      </div>

      {/* Detection pipeline */}
      <p className="text-sm font-semibold text-white mb-3">How a scan is actually decided</p>
      <div className="grid md:grid-cols-3 gap-4 mb-10">
        {PIPELINE_STEPS.map((s, i) => {
          const Icon = s.icon;
          return (
            <Card key={i} className="p-5">
              <div className="w-9 h-9 rounded-full bg-cyan-400/10 flex items-center justify-center mb-3">
                <Icon className="w-4 h-4 text-cyan-400" />
              </div>
              <p className="text-sm font-semibold text-white mb-1">{s.title}</p>
              <p className="text-xs text-slate-400 leading-relaxed">{s.text}</p>
            </Card>
          );
        })}
      </div>

      {/* Team footer */}
      <Card className="p-5 flex items-center gap-3">
        <Users className="w-4 h-4 text-slate-500 flex-shrink-0" />
        <p className="text-xs text-slate-500">
          Built by J. Rishi, Akshit Kukshal &amp; Ali Azmi — Dept. of Computer Science &amp; Engineering, Sharda University
        </p>
      </Card>
    </div>
  );
}

/* =========================================================================
   CHECKER SCREEN
   ========================================================================= */

function CheckerScreen() {
  const [mode, setMode] = useState("url");
  const [urlInput, setUrlInput] = useState("http://secure-paypa1-login.com");
  const [emailInput, setEmailInput] = useState("Your account will be suspended in 24 hours. Verify now to avoid interruption.");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleScan() {
    setLoading(true);
    setResult(null);
    try {
      const endpoint = mode === "url" ? "/check-url" : "/check-email";
      const body = mode === "url" ? { url: urlInput } : { text: emailInput };
      const res = await fetch(`${API_BASE}${endpoint}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      setResult(await res.json());
    } catch (e) {
      setResult({ error: "Could not reach the backend. Is app.py running on port 5000?" });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-xl mx-auto p-6 md:p-10">
      <p className="text-sm font-semibold text-white mb-1">URL / Email Checker</p>
      <p className="text-xs text-slate-500 mb-5">Scored by three detection layers at once — classifier, masking, and anomaly detection.</p>

      <div className="flex gap-2 mb-3">
        <button onClick={() => { setMode("url"); setResult(null); }} className={`flex items-center gap-1.5 text-sm px-3.5 py-1.5 rounded-lg border transition-colors ${mode === "url" ? "border-cyan-400 text-cyan-300 bg-cyan-400/10" : "border-slate-700 text-slate-400 hover:border-slate-500"}`}>
          <Link2 className="w-3.5 h-3.5" /> URL
        </button>
        <button onClick={() => { setMode("email"); setResult(null); }} className={`flex items-center gap-1.5 text-sm px-3.5 py-1.5 rounded-lg border transition-colors ${mode === "email" ? "border-cyan-400 text-cyan-300 bg-cyan-400/10" : "border-slate-700 text-slate-400 hover:border-slate-500"}`}>
          <Mail className="w-3.5 h-3.5" /> Email
        </button>
      </div>

      {mode === "url" ? (
        <input type="text" value={urlInput} onChange={(e) => setUrlInput(e.target.value)} placeholder="Paste a link, e.g. https://example.com" className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-100 font-mono focus:outline-none focus:border-cyan-400" />
      ) : (
        <textarea value={emailInput} onChange={(e) => setEmailInput(e.target.value)} placeholder="Paste the email content here" rows={4} className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-400 resize-none" />
      )}

      <button onClick={handleScan} disabled={loading} className="mt-3 w-full flex items-center justify-center gap-2 bg-cyan-400 text-slate-900 font-semibold py-2.5 rounded-lg hover:bg-cyan-300 transition-colors disabled:opacity-60">
        {loading ? "Scanning\u2026" : `Scan ${mode === "url" ? "link" : "email"}`}
        {!loading && <ArrowRight className="w-4 h-4" />}
      </button>

      <ResultCard result={result} />
    </div>
  );
}

/* =========================================================================
   HISTORY SCREEN
   ========================================================================= */

function HistoryScreen() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchHistory = useCallback(() => {
    fetch(`${API_BASE}/history?limit=30`).then((r) => r.json()).then((d) => setScans(d.scans || [])).catch(() => setScans([])).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  return (
    <div className="max-w-3xl mx-auto p-6 md:p-10">
      <div className="flex items-center justify-between mb-5">
        <div>
          <p className="text-sm font-semibold text-white">Scan History</p>
          <p className="text-xs text-slate-500">Every URL and email checked this session, newest first.</p>
        </div>
        <button onClick={fetchHistory} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-300 transition-colors">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {loading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : scans.length === 0 ? (
        <Card className="p-8 text-center">
          <p className="text-sm text-slate-400">No scans yet — run a check from the Checker tab to see it here.</p>
        </Card>
      ) : (
        <div className="space-y-2">
          {scans.map((s) => {
            const cfg = VERDICT_STYLE[s.verdict];
            const TypeIcon = s.type === "url" ? Link2 : Mail;
            return (
              <Card key={s.id} className="p-4 flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
                <TypeIcon className="w-4 h-4 text-slate-500 flex-shrink-0" />
                <p className="text-sm text-slate-200 font-mono truncate flex-1">{s.input}</p>
                <span className={`text-xs px-2 py-0.5 rounded flex-shrink-0 ${cfg.badge}`}>{cfg.label}</span>
                <span className="text-xs text-slate-500 flex-shrink-0 hidden sm:block">{s.timestamp}</span>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* =========================================================================
   AWARENESS QUIZ SCREEN
   ========================================================================= */

const QUESTIONS = [
  { type: "compare", icon: Link2, prompt: "Which of these links actually leads to PayPal?", options: ["https://www.paypal.com/signin", "https://www.paypa1-secure-login.com/signin"], correct: 0, explanation: "Option B swaps the letter L for the digit 1. Always check the exact domain, not just that it \u201clooks like\u201d the brand." },
  { type: "compare", icon: Link2, prompt: "Which domain is the real one for a bank called Meridian Bank?", options: ["https://meridianbank.com/login", "https://meridianbank.com.secure-verify.net/login"], correct: 0, explanation: "In option B, \u201cmeridianbank.com\u201d is just a subdomain of the real attacker-owned domain \u201csecure-verify.net\u201d." },
  { type: "scenario", icon: Mail, prompt: "\u201cYour account will be suspended in 2 hours. Click below to verify immediately.\u201d \u2014 from billing@amaz0n-support.com", isPhish: true, explanation: "Urgency plus a countdown is a classic pressure tactic, and the sender domain uses a zero instead of the letter O." },
  { type: "scenario", icon: Mail, prompt: "\u201cYour order #48213 has shipped. Track your package.\u201d \u2014 from orders@amazon.com, no login required.", isPhish: false, explanation: "No urgency, no request for credentials, and the domain matches the real company exactly." },
];

function ProgressBar({ current, total }) {
  const pct = Math.round((current / total) * 100);
  return <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-cyan-400 transition-all duration-300" style={{ width: `${pct}%` }} /></div>;
}

function AwarenessScreen() {
  const [step, setStep] = useState(0);
  const [selected, setSelected] = useState(null);
  const [score, setScore] = useState(0);
  const [answered, setAnswered] = useState(false);

  const total = QUESTIONS.length;
  const finished = step >= total;
  const q = !finished ? QUESTIONS[step] : null;

  function choose(idx, isCorrectChoice) {
    if (answered) return;
    setSelected(idx);
    setAnswered(true);
    if (isCorrectChoice) setScore((s) => s + 1);
  }
  function next() { setSelected(null); setAnswered(false); setStep((s) => s + 1); }
  function restart() { setStep(0); setSelected(null); setScore(0); setAnswered(false); }

  if (finished) {
    const pct = Math.round((score / total) * 100);
    return (
      <div className="max-w-md mx-auto text-center py-16 px-6">
        <div className="w-16 h-16 rounded-full bg-cyan-400/10 flex items-center justify-center mx-auto mb-5">
          <GraduationCap className="w-8 h-8 text-cyan-400" />
        </div>
        <p className="text-sm uppercase tracking-wide text-slate-400 mb-1">Quiz complete</p>
        <h2 className="text-3xl font-bold text-white mb-1">{score} / {total}</h2>
        <p className="text-slate-300 mb-8">{pct}% correct</p>
        <button onClick={restart} className="inline-flex items-center gap-2 bg-cyan-400 text-slate-900 font-semibold px-5 py-2.5 rounded-lg hover:bg-cyan-300 transition-colors">
          <RotateCcw className="w-4 h-4" /> Try again
        </button>
      </div>
    );
  }

  const Icon = q.icon;
  return (
    <div className="max-w-xl mx-auto p-6 md:p-10">
      <p className="text-sm font-semibold text-white mb-1">Awareness Quiz</p>
      <p className="text-xs text-slate-500 mb-5">Spot the phishing — same red flags the detection engine looks for.</p>
      <div className="flex items-center justify-between mb-3">
        <span className="text-white font-semibold text-sm">Question {step + 1}</span>
        <span className="text-sm text-slate-400">{step + 1} / {total}</span>
      </div>
      <ProgressBar current={step} total={total} />
      <div className="mt-5 bg-slate-800 rounded-2xl p-6">
        <div className="flex items-start gap-3 mb-5">
          <div className="w-9 h-9 rounded-full bg-cyan-400/10 flex items-center justify-center flex-shrink-0">
            <Icon className="w-4 h-4 text-cyan-400" />
          </div>
          <p className="text-slate-100 text-base leading-relaxed pt-1">{q.prompt}</p>
        </div>

        {q.type === "compare" && (
          <div className="grid gap-3">
            {q.options.map((opt, idx) => {
              const isCorrect = idx === q.correct;
              const isPicked = selected === idx;
              let style = "border-slate-700 bg-slate-900 text-slate-200 hover:border-slate-500";
              if (answered && isCorrect) style = "border-emerald-400 bg-emerald-400/10 text-emerald-200";
              else if (answered && isPicked && !isCorrect) style = "border-rose-400 bg-rose-400/10 text-rose-200";
              return (
                <button key={idx} onClick={() => choose(idx, isCorrect)} disabled={answered} className={`flex items-center justify-between gap-3 text-left border rounded-xl px-4 py-3 font-mono text-sm transition-colors ${style}`}>
                  <span className="break-all">{opt}</span>
                  {answered && isCorrect && <Check className="w-4 h-4 flex-shrink-0 text-emerald-400" />}
                  {answered && isPicked && !isCorrect && <X className="w-4 h-4 flex-shrink-0 text-rose-400" />}
                </button>
              );
            })}
          </div>
        )}

        {q.type === "scenario" && (
          <div className="grid grid-cols-2 gap-3">
            {[{ label: "Looks safe", isPhishChoice: false }, { label: "Phishing", isPhishChoice: true }].map((opt, idx) => {
              const isCorrect = opt.isPhishChoice === q.isPhish;
              const isPicked = selected === idx;
              let style = "border-slate-700 bg-slate-900 text-slate-200 hover:border-slate-500";
              if (answered && isCorrect) style = "border-emerald-400 bg-emerald-400/10 text-emerald-200";
              else if (answered && isPicked && !isCorrect) style = "border-rose-400 bg-rose-400/10 text-rose-200";
              return (
                <button key={idx} onClick={() => choose(idx, isCorrect)} disabled={answered} className={`flex items-center justify-center gap-2 border rounded-xl px-4 py-3 font-semibold text-sm transition-colors ${style}`}>
                  {opt.label}
                  {answered && isCorrect && <Check className="w-4 h-4" />}
                  {answered && isPicked && !isCorrect && <X className="w-4 h-4" />}
                </button>
              );
            })}
          </div>
        )}

        {answered && (
          <div className="mt-5 flex items-start gap-3 bg-slate-900 border border-slate-700 rounded-xl p-4">
            <ShieldAlert className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-slate-300 leading-relaxed">{q.explanation}</p>
          </div>
        )}

        {answered && (
          <button onClick={next} className="mt-5 w-full flex items-center justify-center gap-2 bg-cyan-400 text-slate-900 font-semibold py-2.5 rounded-lg hover:bg-cyan-300 transition-colors">
            {step + 1 === total ? "See your score" : "Next question"}
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}

/* =========================================================================
   NETWORK MONITOR SCREEN (Snort integration)
   ========================================================================= */

const PRIORITY_STYLE = {
  "1": { label: "Critical", color: "text-rose-300", bg: "bg-rose-400/10", dot: "bg-rose-400" },
  "2": { label: "Medium", color: "text-amber-300", bg: "bg-amber-400/10", dot: "bg-amber-400" },
  "3": { label: "Low", color: "text-slate-300", bg: "bg-slate-400/10", dot: "bg-slate-400" },
};

function AlertRow({ alert }) {
  const pstyle = PRIORITY_STYLE[alert.priority] || PRIORITY_STYLE["3"];
  return (
    <Card className={`p-4 flex items-start gap-3 ${alert.is_custom_rule ? "border-cyan-400 bg-cyan-400/5" : ""}`}>
      <span className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${pstyle.dot}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-sm font-medium text-slate-100">{alert.message}</p>
          {alert.is_custom_rule && <span className="text-[10px] uppercase tracking-wide bg-cyan-400/15 text-cyan-300 px-2 py-0.5 rounded">Our rule</span>}
        </div>
        <p className="text-xs text-slate-500 mt-1 font-mono">{alert.source} <ArrowRight className="inline w-3 h-3 mx-1" /> {alert.destination} · {alert.protocol}</p>
      </div>
      <div className="text-right flex-shrink-0">
        <span className={`text-xs px-2 py-0.5 rounded ${pstyle.bg} ${pstyle.color}`}>{pstyle.label}</span>
        <p className="text-[10px] text-slate-600 mt-1">{alert.timestamp}</p>
      </div>
    </Card>
  );
}

function NetworkMonitorScreen() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/network-alerts`);
      setData(await res.json());
      setLastUpdated(new Date());
    } catch (e) {
      setData({ source: "error", alerts: [], error: "Could not reach the backend." });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  return (
    <div className="max-w-2xl mx-auto p-6 md:p-10">
      <div className="flex items-center justify-between mb-2">
        <div>
          <p className="text-sm font-semibold text-white">Network Monitor</p>
          <p className="text-xs text-slate-500">Live alerts from Snort — signature-based, network-layer detection.</p>
        </div>
        <button onClick={fetchAlerts} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-300 transition-colors flex-shrink-0">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {data?.source === "demo" && (
        <div className="mt-4 mb-4 flex items-center gap-2 text-xs text-amber-300 bg-amber-400/10 border border-amber-400/30 rounded-lg px-3 py-2">
          <WifiOff className="w-3.5 h-3.5 flex-shrink-0" /> Snort isn't running yet — showing a sample alert.
        </div>
      )}
      {data?.source === "error" && (
        <div className="mt-4 mb-4 flex items-center gap-2 text-xs text-rose-300 bg-rose-400/10 border border-rose-400/30 rounded-lg px-3 py-2">
          <WifiOff className="w-3.5 h-3.5 flex-shrink-0" /> {data.error || "Could not reach the backend."}
        </div>
      )}

      <div className="mt-4 space-y-2">
        {loading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : data?.alerts?.length ? (
          data.alerts.map((a, i) => <AlertRow key={i} alert={a} />)
        ) : (
          <p className="text-sm text-slate-500">No alerts captured yet.</p>
        )}
      </div>

      {lastUpdated && <p className="text-[11px] text-slate-600 mt-4 text-center">Last updated {lastUpdated.toLocaleTimeString()} — auto-refreshes every 5s</p>}
    </div>
  );
}

/* =========================================================================
   APP SHELL — sidebar navigation
   ========================================================================= */

const NAV_ITEMS = [
  { id: "home", label: "Overview", icon: LayoutDashboard },
  { id: "checker", label: "Checker", icon: ShieldCheck },
  { id: "history", label: "History", icon: History },
  { id: "awareness", label: "Awareness", icon: GraduationCap },
  { id: "network", label: "Network Monitor", icon: Network },
];

export default function App() {
  const [tab, setTab] = useState("home");

  return (
    <div className="min-h-[680px] bg-slate-900 flex">
      {/* Sidebar */}
      <div className="w-56 flex-shrink-0 border-r border-slate-800 flex flex-col">
        <div className="flex items-center gap-2 px-5 py-5">
          <div className="w-8 h-8 rounded-lg bg-cyan-400/10 flex items-center justify-center">
            <ShieldCheck className="w-4.5 h-4.5 text-cyan-400" />
          </div>
          <div>
            <p className="text-white font-semibold text-sm leading-none">PhishGuard</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Detection &amp; Awareness</p>
          </div>
        </div>

        <div className="flex-1 px-3 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`w-full flex items-center gap-2.5 text-sm px-3 py-2 rounded-lg transition-colors ${active ? "bg-cyan-400/10 text-cyan-300" : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"}`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {item.label}
              </button>
            );
          })}
        </div>

        <div className="px-5 py-4 border-t border-slate-800">
          <p className="text-[10px] text-slate-600 flex items-center gap-1.5">
            <Github className="w-3 h-3" /> Sharda University PBL
          </p>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-auto">
        {tab === "home" && <HomeScreen onNavigate={setTab} />}
        {tab === "checker" && <CheckerScreen />}
        {tab === "history" && <HistoryScreen />}
        {tab === "awareness" && <AwarenessScreen />}
        {tab === "network" && <NetworkMonitorScreen />}
      </div>
    </div>
  );
}
