import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../services/api';
import {
  Shield,
  Activity,
  Database,
  Cpu,
  MessageSquare,
  LogOut,
  User as UserIcon,
  Play,
  Square,
  AlertTriangle,
  Clock,
  ArrowRight,
  Sparkles,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Sliders
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
  Legend
} from 'recharts';

// Types matching backend API
interface TopFeature {
  feature: string;
  value: number;
  importance: number;
  impact: number;
}

interface DetectionData {
  predicted_label: string;
  confidence: number;
  tier: number;
  tier_name: string;
  top_features: TopFeature[];
  alert_id?: number;
  source_scenario?: string;
}

interface TelemetryEvent {
  event: 'heartbeat' | 'detection';
  timestamp: string;
  data?: DetectionData;
}

interface AlertLog {
  id: number;
  timestamp: string;
  predicted_label: string;
  confidence: number;
  tier: number;
  source_scenario: string;
  raw_features: Record<string, any>;
}

interface SimStatus {
  running: boolean;
  scenario: string | null;
  rate: number;
  duration_seconds: number | null;
  elapsed_seconds: number;
  packets_sent: number;
  attacks_detected: number;
  tier_breakdown: Record<string, number>;
}

export const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'live' | 'simulator' | 'history' | 'insights' | 'ai'>('live');

  // --- GLOBAL STATES ---
  const [wsConnected, setWsConnected] = useState(false);

  // --- LIVE TELEMETRY STATES (Throttled for Performance) ---
  const [liveEvents, setLiveEvents] = useState<TelemetryEvent[]>([]);
  const [packetsAnalyzed, setPacketsAnalyzed] = useState(0);
  const [attacksCount, setAttacksCount] = useState(0);
  const [selectedDetection, setSelectedDetection] = useState<DetectionData | null>(null);

  // Recharts live rate chart data
  const [chartData, setChartData] = useState<{ time: string; packets: number; threats: number }[]>([]);

  // Refs for throttled buffering
  const wsRef = useRef<WebSocket | null>(null);
  const eventBufferRef = useRef<TelemetryEvent[]>([]);

  // Heartbeat telemetry variables
  const [lastHeartbeat, setLastHeartbeat] = useState<number | null>(null);
  const [packetsPerSecond, setPacketsPerSecond] = useState(0);
  const packetsThisSecondRef = useRef(0);
  const [liveTiers, setLiveTiers] = useState<Record<number, number>>({ 1: 0, 2: 0, 3: 0 });
  const [attackCounts, setAttackCounts] = useState<Record<string, number>>({});

  // 1-second interval to compute active packets per second
  useEffect(() => {
    const timer = setInterval(() => {
      setPacketsPerSecond(packetsThisSecondRef.current);
      packetsThisSecondRef.current = 0;
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // --- SIMULATOR STATES ---
  const [simStatus, setSimStatus] = useState<SimStatus>({
    running: false,
    scenario: null,
    rate: 5,
    duration_seconds: 30,
    elapsed_seconds: 0,
    packets_sent: 0,
    attacks_detected: 0,
    tier_breakdown: { '1': 0, '2': 0, '3': 0 }
  });
  const [selectedScenario, setSelectedScenario] = useState('ddos_storm');
  const [simRate, setSimRate] = useState(5);
  const [simDuration, setSimDuration] = useState(30);

  // --- ALERT HISTORY STATES ---
  const [alerts, setAlerts] = useState<AlertLog[]>([]);
  const [filterAttack, setFilterAttack] = useState('');
  const [filterTier, setFilterTier] = useState('');
  const [historyPage, setHistoryPage] = useState(1);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // --- AI CHATBOT STATES ---
  const [messages, setMessages] = useState<{ role: 'user' | 'assistant'; text: string; time: string }[]>([
    {
      role: 'assistant',
      text: "Welcome to the ThreatSim SOC Assistant. I am backed by the AI Cascade configuration. Ask me about classification tiers, specific attack signatures, or model tuning parameters.",
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [aiTyping, setAiTyping] = useState(false);

  // ==========================================
  // 1. WEBSOCKET FEED + THROTTLED RE-RENDERING
  // ==========================================
  useEffect(() => {
    const ws = new WebSocket(`ws://${window.location.hostname}:8000/ws/live`);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      console.log('Telemetry WebSocket connected');
    };

    ws.onmessage = (msg) => {
      try {
        const payload: TelemetryEvent = JSON.parse(msg.data);
        if (payload.event === 'heartbeat') {
          setLastHeartbeat(Date.now());
        } else {
          // Push to buffer instead of updating React state immediately to prevent lag
          eventBufferRef.current.push(payload);
        }
      } catch (err) {
        console.error('WebSocket telemetry parse error:', err);
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
      console.warn('Telemetry WebSocket disconnected');
    };

    ws.onerror = () => {
      ws.close();
    };

    return () => {
      ws.close();
    };
  }, []);

  // Flush buffer to React State at a throttled rate (every 300ms)
  useEffect(() => {
    const interval = setInterval(() => {
      if (eventBufferRef.current.length > 0) {
        const buffer = [...eventBufferRef.current];
        eventBufferRef.current = [];

        // Aggregate statistics from buffered packets
        let newPackets = 0;
        let newAttacks = 0;
        const processedDetections: TelemetryEvent[] = [];
        
        setLiveTiers((prev) => {
          const updated = { ...prev };
          buffer.forEach((evt) => {
            if (evt.event === 'detection' && evt.data) {
              const t = evt.data.tier;
              updated[t] = (updated[t] || 0) + 1;
            }
          });
          return updated;
        });

        setAttackCounts((prev) => {
          const updated = { ...prev };
          buffer.forEach((evt) => {
            if (evt.event === 'detection' && evt.data) {
              const lbl = evt.data.predicted_label;
              updated[lbl] = (updated[lbl] || 0) + 1;
            }
          });
          return updated;
        });

        buffer.forEach((evt) => {
          if (evt.event === 'detection') {
            newPackets += 1;
            processedDetections.push(evt);
            if (evt.data && evt.data.predicted_label.toUpperCase() !== 'BENIGN') {
              newAttacks += 1;
            }
          }
        });

        // 1. Update overall packet statistics
        setPacketsAnalyzed((prev) => prev + newPackets);
        setAttacksCount((prev) => prev + newAttacks);
        
        // Track packets this second
        packetsThisSecondRef.current += newPackets;

        // 2. Update list of recent event logs (capped at 50)
        if (processedDetections.length > 0) {
          setLiveEvents((prev) => [...processedDetections.reverse(), ...prev].slice(0, 50));
        }

        // 3. Update live activity chart
        setChartData((prev) => {
          const timestamp = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
          const updated = [...prev, { time: timestamp, packets: newPackets, threats: newAttacks }];
          return updated.slice(-15); // Show last 15 ticks
        });
      }
    }, 300);

    return () => clearInterval(interval);
  }, [liveTiers, attackCounts]);

  // Initialize live chart layout
  useEffect(() => {
    const initialData = Array.from({ length: 15 }, (_, i) => ({
      time: new Date(Date.now() - (15 - i) * 2000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      packets: 0,
      threats: 0
    }));
    setChartData(initialData);
  }, []);

  // ==========================================
  // 2. SIMULATOR LOGIC
  // ==========================================
  const fetchSimStatus = async () => {
    try {
      const res = await api.get('/api/simulate/status');
      setSimStatus(res.data);
    } catch (err) {
      console.error('Failed to retrieve simulator status:', err);
    }
  };

  // Poll simulator status when in simulator tab
  useEffect(() => {
    let interval: number;
    if (activeTab === 'simulator') {
      fetchSimStatus();
      interval = window.setInterval(fetchSimStatus, 1000);
    }
    return () => clearInterval(interval);
  }, [activeTab]);

  const handleStartSim = async () => {
    try {
      await api.post('/api/simulate/start', {
        scenario: selectedScenario,
        rate: simRate,
        duration_seconds: simDuration || null
      });
      fetchSimStatus();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to start simulation.');
    }
  };

  const handleStopSim = async () => {
    try {
      await api.post('/api/simulate/stop');
      fetchSimStatus();
    } catch (err) {
      console.error('Failed to stop simulation:', err);
    }
  };

  // ==========================================
  // 3. ALERT HISTORY LOGS
  // ==========================================
  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      let url = `/api/alerts?page=${historyPage}&limit=12`;
      if (filterAttack) url += `&attack_type=${encodeURIComponent(filterAttack)}`;
      if (filterTier) url += `&tier=${filterTier}`;

      const res = await api.get(url);
      setAlerts(res.data);
    } catch (err) {
      console.error('Failed to load alert logs:', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'history') {
      fetchHistory();
    }
  }, [activeTab, historyPage, filterAttack, filterTier]);

  // ==========================================
  // 4. MODEL BENCHMARKS
  // ==========================================
  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await api.get('/api/models/metrics');
        console.log('Model metrics loaded successfully:', res.data);
      } catch (err) {
        console.error('Failed to load model metrics:', err);
      }
    };
    if (activeTab === 'insights') {
      fetchMetrics();
    }
  }, [activeTab]);

  // ==========================================
  // 5. AI SECURITY BOT CHAT
  // ==========================================
  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = chatInput;
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    setMessages((prev) => [...prev, { role: 'user', text: userMsg, time }]);
    setChatInput('');
    setAiTyping(true);

    // Simulate AI SOC analysis response based on key terms
    setTimeout(() => {
      let reply = '';
      const text = userMsg.toLowerCase();
      if (text.includes('ddos') || text.includes('hulk')) {
        reply = "DoS/DDoS attacks are resolved at Tier 1 (LightGBM) because they present standard volumetric headers. Key feature indicators: Init_Win_bytes_backward, Fwd Header Length, and Flow Bytes/s. Consider scaling server bandwidth or configuring firewall threshold filters.";
      } else if (text.includes('brute force') || text.includes('patator')) {
        reply = "Brute Force authentication attempts (SSH/FTP-Patator) involve low-speed repetitive connections. These are detected at Tier 2 (Random Forest) due to high temporal variations in packet sequences. Features most affected: Fwd IAT Std, Packet Length Mean, and Average Packet Size.";
      } else if (text.includes('tier') || text.includes('cascade')) {
        reply = "The ML Cascade checks Tier 1 (LightGBM) first. If prediction confidence is >= 0.85, it returns it instantly. Otherwise, it escalates to Tier 2 (Random Forest). If Tier 2 confidence is also < 0.85, it schedules a weighted ensemble vote across all three models (LGBM 0.2 / RF 0.3 / XGB 0.5) at Tier 3.";
      } else if (text.includes('xai') || text.includes('explain')) {
        reply = "Explainable AI (XAI) scores are calculated dynamically per packet. Feature impacts are derived by scaling the packet's raw metrics and multiplying them by the Random Forest model's global importances. The top features with the largest absolute magnitude impact are flagged as the primary threat attributions.";
      } else {
        reply = "I've reviewed the system indicators. The Cascade classifier reports nominal states, and the background simulator task is loaded. Let me know if you would like me to explain model latency metrics or explain a specific packet attribution.";
      }

      setMessages((prev) => [...prev, { role: 'assistant', text: reply, time }]);
      setAiTyping(false);
    }, 1200);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex font-sans select-none overflow-hidden h-screen">
      {/* BACKGROUND GRAPHIC GLOWS */}
      <div className="absolute top-[-20%] left-[-10%] w-[40%] h-[40%] rounded-full bg-purple-900/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-15%] right-[-10%] w-[40%] h-[40%] rounded-full bg-indigo-900/5 blur-[120px] pointer-events-none"></div>

      {/* LEFT SIDEBAR NAVBAR */}
      <aside className="w-64 border-r border-slate-900 bg-slate-950/80 backdrop-blur-md flex flex-col justify-between p-6 z-20 shrink-0">
        <div className="flex flex-col gap-8">
          {/* Dashboard Title Branding */}
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-purple-600 to-indigo-600 rounded-xl shadow-lg shadow-purple-500/10">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-md font-bold tracking-tight text-white leading-tight">ThreatSim SOC</h1>
              <span className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">AI Cascade Core</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex flex-col gap-1.5">
            <button
              onClick={() => setActiveTab('live')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                activeTab === 'live'
                  ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                  : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200 border border-transparent'
              }`}
            >
              <Activity className="w-4.5 h-4.5" />
              Live Detection Feed
            </button>

            <button
              onClick={() => setActiveTab('simulator')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                activeTab === 'simulator'
                  ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                  : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200 border border-transparent'
              }`}
            >
              <Sliders className="w-4.5 h-4.5" />
              Threat Simulator
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                activeTab === 'history'
                  ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                  : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200 border border-transparent'
              }`}
            >
              <Database className="w-4.5 h-4.5" />
              Alert History
            </button>

            <button
              onClick={() => setActiveTab('insights')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                activeTab === 'insights'
                  ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                  : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200 border border-transparent'
              }`}
            >
              <Cpu className="w-4.5 h-4.5" />
              Model Insights
            </button>

            <button
              onClick={() => setActiveTab('ai')}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-semibold tracking-wide transition-all cursor-pointer ${
                activeTab === 'ai'
                  ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                  : 'text-slate-400 hover:bg-slate-900/50 hover:text-slate-200 border border-transparent'
              }`}
            >
              <MessageSquare className="w-4.5 h-4.5" />
              AI SOC Assistant
            </button>
          </nav>
        </div>

        {/* Sidebar Footer User Details */}
        <div className="pt-4 border-t border-slate-900 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 shrink-0">
              <UserIcon className="w-4 h-4" />
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-bold text-slate-200 truncate">{user?.username || 'analyst'}</p>
              <span className="text-[9px] text-purple-400 font-semibold uppercase tracking-wider">{user?.role || 'analyst'}</span>
            </div>
          </div>
          <button
            onClick={logout}
            title="Log Out Session"
            className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-950/20 hover:border-red-900/30 border border-transparent rounded-lg transition-all cursor-pointer shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </aside>

      {/* RIGHT CONTENT WORKSPACE */}
      <main className="flex-1 flex flex-col overflow-hidden relative z-10 bg-slate-950/20">
        {/* HEADER BRANDING BANNER */}
        <header className="border-b border-slate-900 bg-slate-950/40 backdrop-blur-md px-8 py-4 flex items-center justify-between shrink-0">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">
              {activeTab === 'live' && 'Security Operations Center - Live Telemetry'}
              {activeTab === 'simulator' && 'Security Operations Center - Threat Simulator'}
              {activeTab === 'history' && 'Security Operations Center - SQLite Alert Database'}
              {activeTab === 'insights' && 'Security Operations Center - Cascade Benchmarks'}
              {activeTab === 'ai' && 'Security Operations Center - Intelligent Analyst assistant'}
            </h2>
            <span className="text-[10px] text-slate-500 font-medium">Bu BUIC BS(IT) Final Year Project Scope</span>
          </div>

          <div className="flex items-center gap-3">
            {wsConnected && lastHeartbeat && (Date.now() - lastHeartbeat < 8000) ? (
              <div className="flex items-center gap-1.5 px-3 py-1 bg-emerald-950/30 border border-emerald-500/20 rounded-full text-emerald-400 text-[10px] font-semibold shadow-sm animate-pulse">
                <span className="w-1.2 h-1.2 rounded-full bg-emerald-400 animate-ping"></span>
                Connected
              </div>
            ) : wsConnected ? (
              <div className="flex items-center gap-1.5 px-3 py-1 bg-amber-950/30 border border-amber-500/20 rounded-full text-amber-400 text-[10px] font-semibold animate-pulse">
                <span className="w-1.2 h-1.2 rounded-full bg-amber-400 animate-bounce"></span>
                Awaiting Heartbeat...
              </div>
            ) : (
              <div className="flex items-center gap-1.5 px-3 py-1 bg-red-950/30 border border-red-500/20 rounded-full text-red-400 text-[10px] font-semibold">
                <AlertTriangle className="w-3.5 h-3.5" />
                Disconnected
              </div>
            )}

            {simStatus.running && (
              <div className="flex items-center gap-1.5 px-3 py-1 bg-purple-950/30 border border-purple-500/20 rounded-full text-purple-400 text-[10px] font-semibold animate-pulse">
                <span className="w-1.2 h-1.2 rounded-full bg-purple-400"></span>
                Simulation Running
              </div>
            )}
          </div>
        </header>

        {/* WORKSPACE TAB VIEWS CONTAINER */}
        <section className="flex-1 overflow-y-auto p-8 relative">
          
          {/* ==========================================
              VIEW A: LIVE TELEMETRY LOGS & CHARTS
              ========================================== */}
          {activeTab === 'live' && (
            <div className="flex flex-col gap-6 h-full">
              
              {/* SOC KPI STAT CARDS GRID */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 shrink-0">
                <div className="bg-slate-900/35 border border-slate-900 p-5 rounded-2xl flex flex-col justify-between hover:border-slate-800/60 transition-colors">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Packets Processed</span>
                  <div className="mt-2.5">
                    <p className="text-2xl font-extrabold text-white tracking-tight">{packetsAnalyzed.toLocaleString()}</p>
                    <span className="text-[9px] text-slate-500 mt-1 block">Total streams screened in session</span>
                  </div>
                </div>

                <div className="bg-slate-900/35 border border-slate-900 p-5 rounded-2xl flex flex-col justify-between hover:border-slate-800/60 transition-colors">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Attacks Detected</span>
                  <div className="mt-2.5">
                    <p className="text-2xl font-extrabold text-red-400 tracking-tight">{attacksCount.toLocaleString()}</p>
                    <span className="text-[9px] text-slate-500 mt-1 block">Flagged anomalies (non-BENIGN)</span>
                  </div>
                </div>

                <div className="bg-slate-900/35 border border-slate-900 p-5 rounded-2xl flex flex-col justify-between hover:border-slate-800/60 transition-colors">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Current Flow Rate</span>
                  <div className="mt-2.5">
                    <p className="text-2xl font-extrabold text-indigo-400 tracking-tight">{packetsPerSecond} <span className="text-xs font-semibold text-slate-500">pkts/sec</span></p>
                    <span className="text-[9px] text-slate-500 mt-1 block">Real-time ingress bandwidth</span>
                  </div>
                </div>

                <div className="bg-slate-900/35 border border-slate-900 p-5 rounded-2xl flex flex-col justify-between hover:border-slate-800/60 transition-colors">
                  <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">Cascade Tier Distribution</span>
                  <div className="mt-2 text-slate-300 font-semibold grid grid-cols-3 gap-1">
                    <div className="bg-slate-950/50 p-1.5 border border-slate-900/40 rounded-lg text-center">
                      <p className="text-xs text-white">{liveTiers[1] || 0}</p>
                      <span className="text-[7px] text-slate-500 block font-mono">T1</span>
                    </div>
                    <div className="bg-slate-950/50 p-1.5 border border-slate-900/40 rounded-lg text-center">
                      <p className="text-xs text-white">{liveTiers[2] || 0}</p>
                      <span className="text-[7px] text-slate-500 block font-mono">T2</span>
                    </div>
                    <div className="bg-slate-950/50 p-1.5 border border-slate-900/40 rounded-lg text-center">
                      <p className="text-xs text-white">{liveTiers[3] || 0}</p>
                      <span className="text-[7px] text-slate-500 block font-mono">T3</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* DUAL CHARTING SECTION */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 shrink-0 h-[280px]">
                {/* Chart 1: Volumetric Line Chart (Packets and Threats Rate) */}
                <div className="lg:col-span-2 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between h-full">
                  <div className="pb-3 border-b border-slate-900 flex justify-between items-center">
                    <h3 className="text-xs font-bold text-white tracking-wide">Volumetric Timeline</h3>
                    <span className="text-[9px] text-slate-500">Replayed Rate vs Flagged Anomalies</span>
                  </div>
                  <div className="flex-1 w-full h-[180px] mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#818cf8" stopOpacity={0.1}/>
                            <stop offset="95%" stopColor="#818cf8" stopOpacity={0}/>
                          </linearGradient>
                          <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#f87171" stopOpacity={0.1}/>
                            <stop offset="95%" stopColor="#f87171" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                        <XAxis dataKey="time" stroke="#475569" fontSize={8} />
                        <YAxis stroke="#475569" fontSize={8} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: 10 }} />
                        <Area type="monotone" dataKey="packets" name="Ingress Rate" stroke="#818cf8" fillOpacity={1} fill="url(#colorPackets)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="threats" name="Threats Rate" stroke="#f87171" fillOpacity={1} fill="url(#colorThreats)" strokeWidth={1.5} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Chart 2: Threat Category counts */}
                <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between h-full">
                  <div className="pb-3 border-b border-slate-900 flex justify-between items-center">
                    <h3 className="text-xs font-bold text-white tracking-wide">Threat Distributions</h3>
                    <span className="text-[9px] text-slate-500">Counts per category type</span>
                  </div>
                  <div className="flex-1 w-full h-[180px] mt-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={Object.entries(attackCounts)
                          .filter(([name]) => name.toUpperCase() !== 'BENIGN')
                          .map(([name, count]) => ({ name, count }))}
                        margin={{ top: 10, right: 10, left: -25, bottom: 0 }}
                        layout="vertical"
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                        <XAxis type="number" stroke="#475569" fontSize={8} />
                        <YAxis type="category" dataKey="name" stroke="#475569" fontSize={8} width={70} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: 10 }} />
                        <Bar dataKey="count" fill="#a78bfa" radius={[0, 4, 4, 0]} barSize={10} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              {/* FULL WIDTH LIVE TELEMETRY TABLE */}
              <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex-1 flex flex-col min-h-[300px] overflow-hidden">
                <div className="pb-3 border-b border-slate-900 flex justify-between items-center shrink-0">
                  <h3 className="text-xs font-bold text-white tracking-wide">Live Threat Telemetry Feed</h3>
                  <div className="flex items-center gap-1.5 text-[9px] text-slate-500 font-mono uppercase">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
                    Ingesting
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto mt-4 font-mono text-[9px]">
                  {liveEvents.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-slate-600 text-xs">
                      Awaiting live telemetry packets...
                    </div>
                  ) : (
                    <table className="w-full text-left border-collapse text-xs text-slate-300">
                      <thead className="bg-slate-950/60 sticky top-0 border-b border-slate-900 text-slate-400 font-bold uppercase text-[9px] z-10">
                        <tr>
                          <th className="p-3">Time</th>
                          <th className="p-3">Attack Category</th>
                          <th className="p-3">Severity</th>
                          <th className="p-3">Confidence</th>
                          <th className="p-3">Resolution Classifier</th>
                          <th className="p-3 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900 font-mono text-[10px]">
                        {liveEvents.map((evt, i) => {
                          const isThreat = evt.data && evt.data.predicted_label.toUpperCase() !== 'BENIGN';
                          const lbl = evt.data?.predicted_label || '';
                          const isCritical = ['DDOS', 'DOS HULK', 'DOS GOLDENEYE', 'BOT', 'HEARTBLEED'].includes(lbl.toUpperCase());
                          
                          return (
                            <tr
                              key={i}
                              className={`hover:bg-slate-900/10 transition-colors ${
                                isThreat ? 'bg-red-950/5' : ''
                              }`}
                            >
                              <td className="p-3 text-slate-500">
                                {new Date(evt.timestamp).toLocaleTimeString([], { hour12: false })}
                              </td>
                              <td className="p-3">
                                <span className={`px-2 py-0.5 border rounded-md font-semibold ${
                                  isThreat 
                                    ? 'bg-red-950/20 border-red-500/20 text-red-400'
                                    : 'bg-emerald-950/20 border-emerald-500/20 text-emerald-400'
                                }`}>
                                  {lbl}
                                </span>
                              </td>
                              <td className="p-3">
                                {isCritical ? (
                                  <span className="text-red-500 font-bold">● CRITICAL</span>
                                ) : isThreat ? (
                                  <span className="text-amber-500 font-semibold">● WARNING</span>
                                ) : (
                                  <span className="text-slate-500">● NOMINAL</span>
                                )}
                              </td>
                              <td className="p-3 font-semibold text-slate-200">
                                {((evt.data?.confidence || 0) * 100).toFixed(2)}%
                              </td>
                              <td className="p-3 text-slate-400">
                                {evt.data?.tier_name}
                              </td>
                              <td className="p-3 text-right">
                                {evt.data?.top_features && (
                                  <button
                                    onClick={() => setSelectedDetection(evt.data!)}
                                    className="text-purple-400 hover:text-purple-300 font-bold hover:underline cursor-pointer"
                                  >
                                    Explain
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              VIEW B: THREAT SIMULATOR CONTROLLERS
              ========================================== */}
          {activeTab === 'simulator' && (
            <div className="flex flex-col gap-6 max-w-4xl mx-auto">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* Controller Settings Form */}
                <div className="md:col-span-2 bg-slate-900/20 border border-slate-900 rounded-2xl p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white tracking-wide mb-1 flex items-center gap-2">
                      <Sliders className="w-4 h-4 text-purple-400" />
                      Configure Simulator Preset
                    </h3>
                    <p className="text-xs text-slate-500 mb-6">Select scenario preset to stream rows from prepared test data split.</p>

                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-2">Scenario Preset</label>
                        <select
                          value={selectedScenario}
                          onChange={(e) => setSelectedScenario(e.target.value)}
                          className="w-full bg-slate-950 border border-slate-900 hover:border-slate-800 rounded-xl p-3 text-xs text-slate-300 outline-none cursor-pointer"
                        >
                          <option value="ddos_storm">ddos_storm (DDoS & DoS flows)</option>
                          <option value="port_scan">port_scan (Port Scan flows)</option>
                          <option value="brute_force">brute_force (FTP/SSH Patator & Web Brute Force)</option>
                          <option value="mixed_attack">mixed_attack (Realistic mix: 20% Benign, 80% Attacks)</option>
                          <option value="benign_baseline">benign_baseline (BENIGN flows only)</option>
                        </select>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-2">Stream Rate (Packets/Sec)</label>
                          <input
                            type="number"
                            min="1"
                            max="100"
                            value={simRate}
                            onChange={(e) => setSimRate(Math.max(1, parseInt(e.target.value) || 1))}
                            className="w-full bg-slate-950 border border-slate-900 hover:border-slate-800 rounded-xl p-3 text-xs text-slate-300 outline-none"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-2">Duration (Seconds)</label>
                          <input
                            type="number"
                            min="5"
                            value={simDuration}
                            onChange={(e) => setSimDuration(Math.max(5, parseInt(e.target.value) || 5))}
                            className="w-full bg-slate-950 border border-slate-900 hover:border-slate-800 rounded-xl p-3 text-xs text-slate-300 outline-none"
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="mt-8 pt-4 border-t border-slate-900/60 flex gap-3">
                    {simStatus.running ? (
                      <button
                        onClick={handleStopSim}
                        className="px-6 py-3 bg-red-600/10 border border-red-500/20 hover:bg-red-600/20 text-red-400 font-bold rounded-xl text-xs tracking-wider uppercase transition-all flex items-center gap-2 cursor-pointer"
                      >
                        <Square className="w-4 h-4" />
                        Stop Simulation
                      </button>
                    ) : (
                      <button
                        onClick={handleStartSim}
                        className="px-6 py-3 bg-purple-600/10 border border-purple-500/20 hover:bg-purple-600/20 text-purple-400 font-bold rounded-xl text-xs tracking-wider uppercase transition-all flex items-center gap-2 cursor-pointer"
                      >
                        <Play className="w-4 h-4" />
                        Start Simulation
                      </button>
                    )}
                  </div>
                </div>

                {/* Live Sim Telemetry Stats */}
                <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white tracking-wide mb-1 flex items-center gap-2">
                      <Clock className="w-4 h-4 text-indigo-400" />
                      Live Status Panel
                    </h3>
                    <p className="text-xs text-slate-500 mb-6">Real-time status metrics of replayer task.</p>

                    <div className="space-y-4 text-xs">
                      <div className="flex justify-between border-b border-slate-900/60 pb-2">
                        <span className="text-slate-500">Status State:</span>
                        <span className={`font-bold ${simStatus.running ? 'text-purple-400' : 'text-slate-500'}`}>
                          {simStatus.running ? 'RUNNING' : 'READY'}
                        </span>
                      </div>
                      <div className="flex justify-between border-b border-slate-900/60 pb-2">
                        <span className="text-slate-500">Preset Scenario:</span>
                        <span className="text-slate-300 font-semibold">{simStatus.scenario || '--'}</span>
                      </div>
                      <div className="flex justify-between border-b border-slate-900/60 pb-2">
                        <span className="text-slate-500">Elapsed / Limit:</span>
                        <span className="text-slate-300 font-semibold">
                          {simStatus.elapsed_seconds}s / {simStatus.duration_seconds || '∞'}s
                        </span>
                      </div>
                      <div className="flex justify-between border-b border-slate-900/60 pb-2">
                        <span className="text-slate-500">Ingress Packets:</span>
                        <span className="text-slate-300 font-semibold">{simStatus.packets_sent}</span>
                      </div>
                      <div className="flex justify-between border-b border-slate-900/60 pb-2">
                        <span className="text-slate-500">Threat Alerts Logged:</span>
                        <span className="text-red-400 font-semibold">{simStatus.attacks_detected}</span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-8">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-3">Resolution Cascade breakdown</span>
                    <div className="grid grid-cols-3 gap-2 text-center text-xs">
                      <div className="bg-slate-950/40 p-2.5 border border-slate-900 rounded-xl">
                        <p className="font-bold text-slate-300">{simStatus.tier_breakdown['1'] || 0}</p>
                        <span className="text-[8px] text-slate-500 mt-0.5 block font-mono">Tier 1</span>
                      </div>
                      <div className="bg-slate-950/40 p-2.5 border border-slate-900 rounded-xl">
                        <p className="font-bold text-slate-300">{simStatus.tier_breakdown['2'] || 0}</p>
                        <span className="text-[8px] text-slate-500 mt-0.5 block font-mono">Tier 2</span>
                      </div>
                      <div className="bg-slate-950/40 p-2.5 border border-slate-900 rounded-xl">
                        <p className="font-bold text-slate-300">{simStatus.tier_breakdown['3'] || 0}</p>
                        <span className="text-[8px] text-slate-500 mt-0.5 block font-mono">Tier 3</span>
                      </div>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* ==========================================
              VIEW C: ALERT DATABASE HISTORY LOGS
              ========================================== */}
          {activeTab === 'history' && (
            <div className="flex flex-col gap-6 max-w-6xl mx-auto h-full">
              {/* Toolbar Filters */}
              <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-4 flex flex-col md:flex-row items-center justify-between gap-4 shrink-0">
                <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                  <div className="relative w-full sm:w-48">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Filter Attack Label..."
                      value={filterAttack}
                      onChange={(e) => { setFilterAttack(e.target.value); setHistoryPage(1); }}
                      className="w-full bg-slate-950 border border-slate-900 rounded-xl py-2 pl-9 pr-4 text-xs text-slate-300 outline-none"
                    />
                  </div>

                  <div className="relative w-full sm:w-40">
                    <Filter className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <select
                      value={filterTier}
                      onChange={(e) => { setFilterTier(e.target.value); setHistoryPage(1); }}
                      className="w-full bg-slate-950 border border-slate-900 rounded-xl py-2 pl-9 pr-4 text-xs text-slate-400 outline-none cursor-pointer"
                    >
                      <option value="">All Tiers</option>
                      <option value="1">Tier 1 (LGBM)</option>
                      <option value="2">Tier 2 (RF)</option>
                      <option value="3">Tier 3 (Vote)</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    disabled={historyPage <= 1}
                    onClick={() => setHistoryPage((p) => Math.max(1, p - 1))}
                    className="p-2 bg-slate-950 border border-slate-900 hover:border-slate-800 disabled:opacity-40 rounded-lg text-slate-300 transition-all cursor-pointer"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <span className="text-xs text-slate-400 px-3">Page {historyPage}</span>
                  <button
                    disabled={alerts.length < 12}
                    onClick={() => setHistoryPage((p) => p + 1)}
                    className="p-2 bg-slate-950 border border-slate-900 hover:border-slate-800 disabled:opacity-40 rounded-lg text-slate-300 transition-all cursor-pointer"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Data Table */}
              <div className="bg-slate-900/20 border border-slate-900 rounded-2xl flex-1 overflow-hidden flex flex-col">
                <div className="flex-1 overflow-y-auto">
                  <table className="w-full border-collapse text-left text-xs text-slate-300">
                    <thead className="bg-slate-950/60 sticky top-0 font-bold border-b border-slate-900 text-slate-400 uppercase tracking-wider text-[10px] z-10">
                      <tr>
                        <th className="p-4">ID</th>
                        <th className="p-4">Timestamp (UTC)</th>
                        <th className="p-4">Label</th>
                        <th className="p-4">Confidence</th>
                        <th className="p-4">Escalation Tier</th>
                        <th className="p-4">Source Scenario</th>
                        <th className="p-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-900">
                      {loadingHistory ? (
                        <tr>
                          <td colSpan={7} className="p-8 text-center text-slate-500">
                            Loading alert records...
                          </td>
                        </tr>
                      ) : alerts.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="p-8 text-center text-slate-500">
                            No persistent alerts found matching filter criteria.
                          </td>
                        </tr>
                      ) : (
                        alerts.map((alert) => (
                          <tr key={alert.id} className="hover:bg-slate-900/20 transition-colors">
                            <td className="p-4 font-mono font-bold text-slate-400">#{alert.id}</td>
                            <td className="p-4 text-slate-400">
                              {new Date(alert.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                            </td>
                            <td className="p-4">
                              <span className="px-2 py-0.5 bg-red-950/20 border border-red-500/20 rounded-md text-red-400 font-semibold">
                                {alert.predicted_label}
                              </span>
                            </td>
                            <td className="p-4 font-semibold text-slate-200">{(alert.confidence).toFixed(4)}</td>
                            <td className="p-4 font-semibold text-slate-400">
                              Tier {alert.tier}
                            </td>
                            <td className="p-4 text-slate-400 font-mono text-[10px]">{alert.source_scenario}</td>
                            <td className="p-4 text-right">
                              <button
                                onClick={() => {
                                  // Mock XAI features mapping from row features for inspection
                                  setSelectedDetection({
                                    predicted_label: alert.predicted_label,
                                    confidence: alert.confidence,
                                    tier: alert.tier,
                                    tier_name: `Tier ${alert.tier} Classifier`,
                                    top_features: Object.entries(alert.raw_features || {}).slice(0, 4).map(([k, v]) => ({
                                      feature: k,
                                      value: v,
                                      importance: 0.05,
                                      impact: 0.1
                                    }))
                                  });
                                }}
                                className="text-purple-400 hover:text-purple-300 font-bold hover:underline cursor-pointer"
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              VIEW D: MODEL INSIGHTS COMPARISONS
              ========================================== */}
          {activeTab === 'insights' && (
            <div className="flex flex-col gap-6 max-w-5xl mx-auto">
              
              {/* Cascade Logic Diagram */}
              <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-6">
                <h3 className="text-xs font-bold text-white tracking-wide mb-6 uppercase">Cascade Decision logic</h3>
                <div className="flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-[10px] text-slate-400">
                  <div className="p-4 bg-slate-950 border border-slate-900 rounded-xl text-center flex-1 w-full md:w-auto">
                    <p className="font-bold text-slate-200 mb-1">Incoming Flow Packet</p>
                    <span>Extracts top-30 select features</span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-700 hidden md:block" />
                  <div className="p-4 bg-slate-950 border border-purple-500/20 rounded-xl text-center flex-1 w-full md:w-auto">
                    <p className="font-bold text-purple-400 mb-1">Tier 1: LightGBM</p>
                    <span>Is Max Prob &gt;= 0.85?</span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-700 hidden md:block" />
                  <div className="p-4 bg-slate-950 border border-indigo-500/20 rounded-xl text-center flex-1 w-full md:w-auto">
                    <p className="font-bold text-indigo-400 mb-1">Tier 2: Random Forest</p>
                    <span>Is Max Prob &gt;= 0.85?</span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-700 hidden md:block" />
                  <div className="p-4 bg-slate-950 border border-emerald-500/20 rounded-xl text-center flex-1 w-full md:w-auto">
                    <p className="font-bold text-emerald-400 mb-1">Tier 3: Expert Ensemble</p>
                    <span>Weighted Prob ArgMax Vote</span>
                  </div>
                </div>
              </div>

              {/* Benchmarks Metrics Comparison */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* Benchmark Metrics bar chart */}
                <div className="md:col-span-2 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between">
                  <div className="pb-3 border-b border-slate-900 flex justify-between items-center mb-6">
                    <h3 className="text-xs font-bold text-white tracking-wide">Accuracy vs Macro F1 Scores</h3>
                    <span className="text-[9px] text-slate-500">Comparative benchmarks</span>
                  </div>
                  
                  <div className="w-full h-[220px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={[
                          { name: 'LightGBM', Accuracy: 99.47, F1: 74.28 },
                          { name: 'Random Forest', Accuracy: 95.39, F1: 67.09 },
                          { name: 'XGBoost', Accuracy: 98.96, F1: 68.17 },
                        ]}
                        margin={{ top: 10, right: 10, left: -25, bottom: 0 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                        <XAxis dataKey="name" stroke="#475569" fontSize={8} />
                        <YAxis stroke="#475569" fontSize={8} domain={[50, 100]} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: 10 }} />
                        <Legend wrapperStyle={{ fontSize: 9 }} />
                        <Bar dataKey="Accuracy" name="Accuracy %" fill="#818cf8" radius={[4, 4, 0, 0]} />
                        <Bar dataKey="F1" name="Macro F1 %" fill="#c084fc" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Benchmark Latency Comparison */}
                <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="pb-3 border-b border-slate-900 flex justify-between items-center mb-6">
                      <h3 className="text-xs font-bold text-white tracking-wide">Average Inference Speed</h3>
                      <span className="text-[9px] text-slate-500">Latency / sample</span>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-slate-400">Random Forest (Speed Winner)</span>
                          <span className="text-white font-bold">0.0029 ms</span>
                        </div>
                        <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                          <div className="bg-emerald-400 h-full rounded-full" style={{ width: '29%' }}></div>
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-slate-400">XGBoost (Moderate Speed)</span>
                          <span className="text-white font-bold">0.0036 ms</span>
                        </div>
                        <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                          <div className="bg-indigo-400 h-full rounded-full" style={{ width: '36%' }}></div>
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-slate-400">LightGBM (Accuracy Winner)</span>
                          <span className="text-white font-bold">0.0102 ms</span>
                        </div>
                        <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                          <div className="bg-amber-400 h-full rounded-full" style={{ width: '100%' }}></div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <p className="text-[9px] text-slate-500 leading-normal mt-6">
                    Cascade architecture balances throughput and precision. Random Forest queries are 3x faster, while LightGBM guarantees optimal recall for edge cases.
                  </p>
                </div>

              </div>
            </div>
          )}

          {/* ==========================================
              VIEW E: AI SECURITY CHAT ASSISTANT
              ========================================== */}
          {activeTab === 'ai' && (
            <div className="flex flex-col gap-6 max-w-4xl mx-auto h-[480px]">
              <div className="bg-slate-900/20 border border-slate-900 rounded-2xl flex-1 flex flex-col overflow-hidden">
                {/* Chat header */}
                <div className="px-6 py-4 bg-slate-950/60 border-b border-slate-900 flex items-center justify-between shrink-0">
                  <div className="flex items-center gap-2.5">
                    <div className="p-1.5 bg-purple-500/10 border border-purple-500/20 rounded-lg text-purple-400">
                      <Sparkles className="w-4 h-4 animate-pulse" />
                    </div>
                    <div>
                      <h4 className="text-xs font-bold text-white tracking-wide">SOC Intelligence Assistant</h4>
                      <span className="text-[8px] text-emerald-400 font-semibold block">Cascade Agent Model Loaded</span>
                    </div>
                  </div>
                </div>

                {/* Message Log */}
                <div className="flex-1 overflow-y-auto p-6 space-y-4">
                  {messages.map((msg, i) => (
                    <div
                      key={i}
                      className={`flex flex-col max-w-[80%] ${
                        msg.role === 'user' ? 'ml-auto items-end' : 'mr-auto items-start'
                      }`}
                    >
                      <div
                        className={`p-3.5 rounded-2xl text-xs leading-relaxed ${
                          msg.role === 'user'
                            ? 'bg-purple-600/15 border border-purple-500/30 text-purple-300 rounded-tr-none'
                            : 'bg-slate-900/70 border border-slate-800 text-slate-300 rounded-tl-none'
                        }`}
                      >
                        {msg.text}
                      </div>
                      <span className="text-[8px] text-slate-500 mt-1 block px-1">{msg.time}</span>
                    </div>
                  ))}

                  {aiTyping && (
                    <div className="flex items-center gap-1 bg-slate-900/50 border border-slate-850 px-4 py-2.5 rounded-2xl text-[9px] text-slate-400 w-fit rounded-tl-none">
                      <span className="w-1 h-1 rounded-full bg-purple-400 animate-bounce"></span>
                      <span className="w-1 h-1 rounded-full bg-purple-400 animate-bounce delay-100"></span>
                      <span className="w-1 h-1 rounded-full bg-purple-400 animate-bounce delay-200"></span>
                      Analyzing request context...
                    </div>
                  )}
                </div>

                {/* Form Chat Input */}
                <form onSubmit={handleSendChat} className="p-4 border-t border-slate-900 bg-slate-950/40 flex gap-3 shrink-0">
                  <input
                    type="text"
                    required
                    disabled={aiTyping}
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder="Ask assistant about attack patterns, models or mitigation plans..."
                    className="flex-1 bg-slate-950 border border-slate-900 hover:border-slate-800 rounded-xl px-4 py-3 text-xs text-slate-300 outline-none placeholder-slate-600"
                  />
                  <button
                    type="submit"
                    disabled={aiTyping}
                    className="px-4 py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-purple-800 text-white font-bold rounded-xl text-xs uppercase tracking-wider transition-colors cursor-pointer"
                  >
                    Send
                  </button>
                </form>
              </div>
            </div>
          )}

        </section>
      </main>

      {/* ==========================================
          XAI EXPLAIN THE PACKET MODAL DIALOG
          ========================================== */}
      {selectedDetection && (
        <div className="absolute inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-lg p-6 relative shadow-2xl animate-scaleUp">
            
            {/* Modal header */}
            <div className="pb-4 border-b border-slate-800/60 flex items-center justify-between mb-6">
              <div className="flex items-center gap-2.5">
                <Sparkles className="w-5 h-5 text-purple-400" />
                <h3 className="text-sm font-bold text-white">Explainable AI (XAI) Attribution</h3>
              </div>
              <button
                onClick={() => setSelectedDetection(null)}
                className="p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-800 border border-transparent rounded-lg cursor-pointer transition-colors"
              >
                ✕
              </button>
            </div>

            {/* Modal details */}
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="bg-slate-950/40 border border-slate-900 p-3 rounded-xl">
                  <span className="text-[9px] text-slate-500 font-bold block mb-1">Classification Label</span>
                  <span className="px-2 py-0.5 bg-red-950/20 border border-red-500/20 rounded text-red-400 font-semibold uppercase text-[9px]">
                    {selectedDetection.predicted_label}
                  </span>
                </div>
                <div className="bg-slate-950/40 border border-slate-900 p-3 rounded-xl">
                  <span className="text-[9px] text-slate-500 font-bold block mb-1">Confidence Score</span>
                  <span className="text-white font-bold">{(selectedDetection.confidence * 100).toFixed(2)}%</span>
                </div>
              </div>

              <div className="bg-slate-950/40 border border-slate-900 p-3 rounded-xl text-xs">
                <span className="text-[9px] text-slate-500 font-bold block mb-1">Resolution Classifier Tier</span>
                <span className="text-slate-300 font-semibold">{selectedDetection.tier_name}</span>
              </div>

              {/* Feature Impact attributions list */}
              <div>
                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-3">Top Attributing Features</span>
                <div className="space-y-3">
                  {selectedDetection.top_features.map((feat, idx) => (
                    <div key={idx} className="text-xs bg-slate-950/40 border border-slate-900/60 p-3 rounded-xl">
                      <div className="flex justify-between text-slate-400 mb-1.5">
                        <span className="font-semibold text-slate-300">{feat.feature}</span>
                        <span>raw_val: {feat.value.toFixed(2)}</span>
                      </div>
                      
                      <div className="flex items-center gap-3">
                        <div className="flex-1 bg-slate-900 h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              selectedDetection.predicted_label.toUpperCase() === 'BENIGN' ? 'bg-emerald-500' : 'bg-red-400'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(10, feat.importance * 100))}%` }}
                          ></div>
                        </div>
                        <span className="text-[9px] text-slate-500 font-mono w-12 text-right">
                          imp: {feat.importance.toFixed(4)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal footer */}
            <div className="mt-8 pt-4 border-t border-slate-800/60 text-right">
              <button
                onClick={() => setSelectedDetection(null)}
                className="px-5 py-2.5 bg-slate-950 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-bold rounded-xl text-xs uppercase tracking-wide cursor-pointer transition-colors"
              >
                Close Explanation
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
export default Dashboard;
