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
  Sliders,
  Download
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
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis
} from 'recharts';

const CLASS_LABELS = [
  "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", 
  "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", 
  "PortScan", "SSH-Patator", "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS"
];

const CLASS_ABBREVIATIONS = [
  "BNG", "BOT", "DDS", "DGE", "DHK", 
  "DST", "DSL", "FTP", "HBD", "INF", 
  "PSC", "SSH", "WBF", "WSI", "WXS"
];

// Types matching backend API
interface TopFeature {
  feature: string;
  value: number;
  importance: number;
  impact: number;
  benign_avg?: number;
}

interface DetectionData {
  predicted_label: string;
  confidence: number;
  tier: number;
  tier_name: string;
  top_features: TopFeature[];
  alert_id?: number;
  source_scenario?: string;
  raw_features?: Record<string, any>;
  benign_averages?: Record<string, number>;
  severity?: string;
  source_ip?: string;
  dest_ip?: string;
  source_port?: number;
  dest_port?: number;
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
  const [activeVectors, setActiveVectors] = useState<any[]>([]);

  // Prune map vectors after 1.5 seconds to clean up visual threat lines
  useEffect(() => {
    if (activeVectors.length > 0) {
      const timer = setTimeout(() => {
        setActiveVectors((prev) => prev.slice(1));
      }, 1500);
      return () => clearTimeout(timer);
    }
  }, [activeVectors]);

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
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');
  const [historyPage, setHistoryPage] = useState(1);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [smoteData, setSmoteData] = useState<any>(null);

  // --- MODEL INSIGHTS STATES ---
  const [metricsData, setMetricsData] = useState<any>(null);
  const [loadingMetrics, setLoadingMetrics] = useState(false);
  const [selectedCMModel, setSelectedCMModel] = useState<'lightgbm' | 'random_forest' | 'xgboost'>('lightgbm');
  const [numFeaturesToShow, setNumFeaturesToShow] = useState<number>(10);
  const [hoveredCMCell, setHoveredCMCell] = useState<{ row: number; col: number; val: number; pct: number } | null>(null);

  // --- EXPLAINABLE AI (XAI) STATES ---
  const [aiExplanation, setAiExplanation] = useState<string>('');
  const [loadingExplanation, setLoadingExplanation] = useState<boolean>(false);

  // --- AI CHATBOT STATES ---
  const [messages, setMessages] = useState<{ role: 'user' | 'assistant'; text: string; time: string; source?: string }[]>([
    {
      role: 'assistant',
      text: "Welcome to the ThreatSim SOC Assistant. I am backed by the AI Cascade configuration. Ask me about classification tiers, specific attack signatures, or model tuning parameters.",
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      source: 'Rule-Based'
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

        const newVectors: any[] = [];
        buffer.forEach((evt) => {
          if (evt.event === 'detection' && evt.data) {
            newPackets += 1;
            processedDetections.push(evt);
            
            const data = evt.data;
            const label = data.predicted_label;
            const isAttack = label.toUpperCase() !== 'BENIGN';
            if (isAttack) {
              newAttacks += 1;
            }
            
            const fromY = isAttack ? 45 : 105;
            const dest_ip = data.dest_ip || '192.168.10.50';
            const target = dest_ip === '192.168.10.50' ? { x: 410, y: 35 } :
                           dest_ip === '192.168.10.51' ? { x: 410, y: 75 } : { x: 410, y: 115 };
                           
            newVectors.push({
              id: Math.random().toString(36).substr(2, 9),
              fromX: 50,
              fromY,
              toX: target.x,
              toY: target.y,
              label,
              isAttack,
              severity: data.severity || 'Info',
              source_ip: data.source_ip || (isAttack ? '10.0.0.15' : '192.168.10.150'),
              dest_ip,
              source_port: data.source_port || 0,
              dest_port: data.dest_port || 0
            });
          }
        });

        if (newVectors.length > 0) {
          setActiveVectors((prev) => [...prev, ...newVectors].slice(-15));
        }

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
      if (filterDateFrom) url += `&date_from=${filterDateFrom}`;
      if (filterDateTo) url += `&date_to=${filterDateTo}`;

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
  }, [activeTab, historyPage, filterAttack, filterTier, filterDateFrom, filterDateTo]);

  // ==========================================
  // 4. MODEL BENCHMARKS
  // ==========================================
  useEffect(() => {
    const fetchMetrics = async () => {
      setLoadingMetrics(true);
      try {
        const [metricsRes, smoteRes] = await Promise.all([
          api.get('/api/models/metrics'),
          api.get('/api/data/smote-stats')
        ]);
        setMetricsData(metricsRes.data);
        setSmoteData(smoteRes.data);
        console.log('Model metrics & SMOTE loaded successfully');
      } catch (err) {
        console.error('Failed to load model metrics:', err);
      } finally {
        setLoadingMetrics(false);
      }
    };
    if (activeTab === 'insights') {
      fetchMetrics();
    }
  }, [activeTab]);

  // ==========================================
  // 4b. DYNAMIC EXPLAIN THIS PACKET (XAI)
  // ==========================================
  useEffect(() => {
    if (!selectedDetection) {
      setAiExplanation('');
      return;
    }

    const getExplanation = async () => {
      setLoadingExplanation(true);
      try {
        const res = await api.post('/api/xai/explain', {
          predicted_label: selectedDetection.predicted_label,
          confidence: selectedDetection.confidence,
          tier: selectedDetection.tier,
          features: selectedDetection.raw_features || {}
        });
        setAiExplanation(res.data.explanation);
      } catch (err) {
        console.error('Failed to get XAI explanation:', err);
        setAiExplanation('Failed to fetch plain-English attribution from secure AI services.');
      } finally {
        setLoadingExplanation(false);
      }
    };
    
    getExplanation();
  }, [selectedDetection]);

  const handleExportReport = async (format: 'pdf' | 'csv') => {
    try {
      let url = `/api/alerts/export?format=${format}`;
      if (filterAttack) url += `&attack_type=${encodeURIComponent(filterAttack)}`;
      if (filterTier) url += `&tier=${filterTier}`;
      if (filterDateFrom) url += `&date_from=${filterDateFrom}`;
      if (filterDateTo) url += `&date_to=${filterDateTo}`;

      const res = await api.get(url, { responseType: 'blob' });
      const blob = new Blob([res.data], { type: format === 'pdf' ? 'application/pdf' : 'text/csv' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `alerts_report_${new Date().toISOString().slice(0, 19).replace(/[-:]/g, "")}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      console.error('Failed to export alert report:', err);
      alert('Failed to generate export report.');
    }
  };

  const getSmoteChartData = () => {
    if (!smoteData) return [];
    const before = smoteData.before_smote || {};
    const after = smoteData.after_smote || {};
    return Object.keys(before).map((className) => ({
      class: className,
      "Before SMOTE": before[className] || 0,
      "After SMOTE": after[className] || 0
    }));
  };

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

    try {
      const res = await api.post('/api/chat', { message: userMsg });
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: res.data.answer,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          source: res.data.source
        }
      ]);
    } catch (err: any) {
      console.error('Failed to communicate with chat backend:', err);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: 'An error occurred while transmitting your request to security intelligence services. Please check network connections.',
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          source: 'Error Fallback'
        }
      ]);
    } finally {
      setAiTyping(false);
    }
  };

  const getComparisonData = () => {
    if (!metricsData || !metricsData.summary) return [];
    return Object.entries(metricsData.summary).map(([name, data]: [string, any]) => ({
      name,
      accuracy: data.accuracy * 100,
      macro_f1: data.macro_f1 * 100,
      avg_latency: data.avg_inference_latency_ms,
      training_time: data.training_time_seconds
    }));
  };

  const postureScore = React.useMemo(() => {
    const detections = liveEvents.filter(evt => evt.event === 'detection' && evt.data);
    if (detections.length === 0) return 0;
    
    const weightMap: Record<string, number> = {
      'Info': 0,
      'Low': 1,
      'Medium': 2,
      'High': 3,
      'Critical': 4
    };
    
    let totalWeight = 0;
    detections.forEach(evt => {
      const sev = evt.data?.severity || 'Info';
      totalWeight += weightMap[sev] !== undefined ? weightMap[sev] : 2;
    });
    
    const avgWeight = totalWeight / detections.length;
    return Math.round((avgWeight / 4.0) * 100);
  }, [liveEvents]);

  const postureStatus = React.useMemo(() => {
    if (postureScore <= 20) {
      return {
        label: 'Secure',
        color: 'text-emerald-400',
        bg: 'bg-emerald-950/20 border-emerald-500/20',
        barColor: '#10b981',
        description: 'Operational: baseline traffic calm.'
      };
    } else if (postureScore <= 60) {
      return {
        label: 'Elevated Risk',
        color: 'text-amber-400',
        bg: 'bg-amber-950/20 border-amber-500/20',
        barColor: '#f59e0b',
        description: 'Moderate threat anomalies detected.'
      };
    } else {
      return {
        label: 'Under Attack',
        color: 'text-red-400 font-bold tracking-wider animate-pulse',
        bg: 'bg-red-950/20 border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.07)]',
        barColor: '#ef4444',
        description: 'CRITICAL: sustained threat cascades triggered!'
      };
    }
  }, [postureScore]);

  const renderConfusionMatrix = (modelKey: 'lightgbm' | 'random_forest' | 'xgboost') => {
    if (!metricsData || !metricsData.confusion_matrices || !metricsData.confusion_matrices[modelKey]) {
      return <div className="text-slate-500 text-xs py-10 text-center">Matrix data not loaded.</div>;
    }
    const matrix = metricsData.confusion_matrices[modelKey];
    
    return (
      <div className="flex flex-col gap-4">
        {/* Heatmap Grid */}
        <div className="overflow-x-auto pb-4">
          <div className="min-w-[420px] flex flex-col">
            {/* Column Headers */}
            <div className="flex items-center pl-16 mb-1">
              {CLASS_ABBREVIATIONS.map((abb, idx) => (
                <div
                  key={idx}
                  title={CLASS_LABELS[idx]}
                  className="w-6 sm:w-7 text-[8px] font-mono text-center text-slate-500 font-bold select-none truncate"
                >
                  {abb}
                </div>
              ))}
            </div>

            {/* Rows */}
            {matrix.map((rowArr: number[], i: number) => {
              const rowSum = rowArr.reduce((a, b) => a + b, 0);
              return (
                <div key={i} className="flex items-center">
                  {/* Row Label (Left) */}
                  <div
                    title={CLASS_LABELS[i]}
                    className="w-16 pr-2 text-[8px] font-mono text-right text-slate-500 font-bold select-none truncate"
                  >
                    {CLASS_ABBREVIATIONS[i]}
                  </div>

                  {/* Row Cells */}
                  {rowArr.map((val: number, j: number) => {
                    const pct = rowSum > 0 ? (val / rowSum) : 0;
                    const isCorrect = i === j;
                    
                    // Style cell color based on normalized row percentage
                    let bgStyle: React.CSSProperties = {};
                    if (val > 0) {
                      if (isCorrect) {
                        bgStyle = { backgroundColor: `rgba(16, 185, 129, ${0.1 + pct * 0.9})` }; // Green
                      } else {
                        bgStyle = { backgroundColor: `rgba(239, 68, 68, ${0.1 + pct * 0.9})` }; // Red for error
                      }
                    } else {
                      bgStyle = { backgroundColor: 'rgb(15, 23, 42)' }; // Dark Slate for 0
                    }

                    const isHovered = hoveredCMCell && hoveredCMCell.row === i && hoveredCMCell.col === j;

                    return (
                      <div
                        key={j}
                        style={bgStyle}
                        onMouseEnter={() => setHoveredCMCell({ row: i, col: j, val, pct })}
                        onMouseLeave={() => setHoveredCMCell(null)}
                        className={`w-6 h-6 sm:w-7 sm:h-7 border border-slate-950/40 relative flex items-center justify-center text-[7px] font-mono transition-all duration-150 cursor-pointer ${
                          isHovered ? 'ring-2 ring-purple-400 scale-105 z-10 border-transparent shadow-lg shadow-purple-500/20' : ''
                        }`}
                      />
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-[9px] font-mono text-slate-400 border-t border-slate-900/60 pt-4 px-2">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-emerald-500/80 border border-emerald-500/25"></span>
              <span>Correct Class</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-red-500/80 border border-red-500/25"></span>
              <span>Misclassification</span>
            </div>
          </div>
          <span className="text-slate-500">Color intensity maps normalized recall row-wise</span>
        </div>

        {/* Selected Cell Inspector */}
        <div className="bg-slate-950/50 border border-slate-900 rounded-xl p-3 flex flex-col justify-center min-h-[56px] text-xs transition-all">
          {hoveredCMCell ? (
            <div className="grid grid-cols-3 gap-2 text-center">
              <div>
                <span className="text-[9px] text-slate-500 block mb-0.5 uppercase tracking-wider font-bold">Actual Class</span>
                <span className="text-slate-300 font-semibold truncate block">{CLASS_LABELS[hoveredCMCell.row]}</span>
              </div>
              <div>
                <span className="text-[9px] text-slate-500 block mb-0.5 uppercase tracking-wider font-bold">Predicted Class</span>
                <span className="text-slate-300 font-semibold truncate block">{CLASS_LABELS[hoveredCMCell.col]}</span>
              </div>
              <div>
                <span className="text-[9px] text-slate-500 block mb-0.5 uppercase tracking-wider font-bold">Flow Counts (%)</span>
                <span className={`font-mono font-bold ${hoveredCMCell.row === hoveredCMCell.col ? 'text-emerald-400' : hoveredCMCell.val > 0 ? 'text-red-400' : 'text-slate-500'}`}>
                  {hoveredCMCell.val.toLocaleString()} ({(hoveredCMCell.pct * 100).toFixed(2)}%)
                </span>
              </div>
            </div>
          ) : (
            <div className="text-center text-slate-500 text-xs italic font-mono">
              Hover over cells to inspect metrics
            </div>
          )}
        </div>
      </div>
    );
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
              
              {/* SECURITY POSTURE GAUGE & LIVE ATTACK MAP PANEL */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 shrink-0">
                {/* 1. Security Posture Gauge */}
                <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-6 flex flex-col items-center justify-between h-[230px] relative overflow-hidden">
                  <div className="w-full flex justify-between items-center pb-2 border-b border-slate-900">
                    <h3 className="text-xs font-bold text-white tracking-wide">Threat Posture Index</h3>
                    <span className="text-[8px] font-mono text-slate-500 uppercase">2 Min Window</span>
                  </div>
                  
                  <div className="flex-1 flex flex-col items-center justify-center mt-2">
                    <svg width="200" height="110" viewBox="0 0 200 110" className="overflow-visible">
                      <defs>
                        <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                          <stop offset="0%" stopColor="#10b981" />
                          <stop offset="35%" stopColor="#eab308" />
                          <stop offset="70%" stopColor="#f97316" />
                          <stop offset="100%" stopColor="#ef4444" />
                        </linearGradient>
                      </defs>
                      {/* Grey background track */}
                      <path
                        d="M20,100 A80,80 0 0,1 180,100"
                        fill="none"
                        stroke="#1e293b"
                        strokeWidth="10"
                        strokeLinecap="round"
                      />
                      {/* Gradient active progress track */}
                      <path
                        d="M20,100 A80,80 0 0,1 180,100"
                        fill="none"
                        stroke="url(#gaugeGradient)"
                        strokeWidth="10"
                        strokeLinecap="round"
                        strokeDasharray="251.3"
                        strokeDashoffset={251.3 - (251.3 * postureScore) / 100}
                        className="transition-all duration-700 ease-out"
                      />
                      {/* Gauge ticks */}
                      <line x1="20" y1="100" x2="25" y2="100" stroke="#475569" strokeWidth="2" />
                      <line x1="100" y1="20" x2="100" y2="25" stroke="#475569" strokeWidth="2" />
                      <line x1="180" y1="100" x2="175" y2="100" stroke="#475569" strokeWidth="2" />
                      
                      {/* Speedometer Needle */}
                      <line
                        x1="100"
                        y1="100"
                        x2="100"
                        y2="35"
                        stroke="#ffffff"
                        strokeWidth="3.5"
                        strokeLinecap="round"
                        transform={`rotate(${-90 + ((postureScore - 50) / 100) * 180}, 100, 100)`}
                        className="transition-all duration-700 ease-out"
                        style={{ transformOrigin: '100px 100px' }}
                      />
                      {/* Needle Center Pin */}
                      <circle cx="100" cy="100" r="7" fill="#6366f1" />
                      <circle cx="100" cy="100" r="3" fill="#ffffff" />
                    </svg>

                    {/* Numeric Score Overlay */}
                    <div className="text-center -mt-3.5 z-10">
                      <p className="text-2xl font-black text-white tracking-tight leading-none">{postureScore}%</p>
                      <span className="text-[8px] text-slate-500 uppercase tracking-wider font-semibold">Risk Index</span>
                    </div>
                  </div>

                  {/* Status Indicator Bar */}
                  <div className={`w-full flex items-center justify-between px-4 py-2 border rounded-xl ${postureStatus.bg} transition-all duration-500 mt-2 shrink-0`}>
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full bg-current ${postureStatus.color}`} />
                      <span className={`text-[10px] font-extrabold uppercase ${postureStatus.color}`}>
                        {postureStatus.label}
                      </span>
                    </div>
                    <span className="text-[8px] text-slate-400 font-medium truncate max-w-[130px]">
                      {postureStatus.description}
                    </span>
                  </div>
                </div>

                {/* 2. Interactive Live Attack Map */}
                <div className="lg:col-span-2 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between h-[230px] relative overflow-hidden">
                  <div className="w-full flex justify-between items-center pb-2 border-b border-slate-900 shrink-0">
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-purple-400" />
                      <h3 className="text-xs font-bold text-white tracking-wide">Live Attack & Traffic Map</h3>
                    </div>
                    <div className="flex items-center gap-1.5 text-[8px] text-slate-500 font-mono">
                      <span>Telemetry Visualization Layer</span>
                    </div>
                  </div>

                  {/* SVG Attack Vector Canvas */}
                  <div className="flex-1 w-full relative mt-2">
                    <svg width="100%" height="100%" viewBox="0 0 500 150" className="overflow-visible">
                      {/* 1. Draw static topological connections as background mesh */}
                      <path d="M 50 45 Q 230 20 410 35" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
                      <path d="M 50 45 Q 230 60 410 75" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
                      <path d="M 50 45 Q 230 80 410 115" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
                      <path d="M 50 105 Q 230 70 410 35" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
                      <path d="M 50 105 Q 230 90 410 75" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
                      <path d="M 50 105 Q 230 110 410 115" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />

                      {/* 2. Left Node Group: Source Pools */}
                      {/* Attacker Node Pool */}
                      <circle cx="50" cy="45" r="15" fill="#ef4444" opacity="0.05" />
                      <circle cx="50" cy="45" r="10" stroke="#f87171" strokeWidth="1.5" fill="#0f172a" />
                      <text x="50" y="48" fill="#f87171" fontSize="8" textAnchor="middle" fontWeight="bold" className="font-mono select-none">ATK</text>
                      <text x="50" y="24" fill="#f87171" fontSize="7" textAnchor="middle" fontWeight="bold" className="select-none uppercase tracking-wider">Attacker Pool</text>

                      {/* Client Node Pool */}
                      <circle cx="50" cy="105" r="15" fill="#10b981" opacity="0.05" />
                      <circle cx="50" cy="105" r="10" stroke="#34d399" strokeWidth="1.5" fill="#0f172a" />
                      <text x="50" y="108" fill="#34d399" fontSize="8" textAnchor="middle" fontWeight="bold" className="font-mono select-none">USR</text>
                      <text x="50" y="126" fill="#34d399" fontSize="7" textAnchor="middle" fontWeight="bold" className="select-none uppercase tracking-wider">Clients (Benign)</text>

                      {/* 3. Internal Network Boundary (Right) */}
                      <rect x="320" y="10" width="170" height="120" rx="8" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="3 3" />
                      <text x="405" y="124" fill="#475569" fontSize="6" textAnchor="middle" fontWeight="bold" letterSpacing="1" className="select-none">INTERNAL LAN</text>

                      {/* Web Server Node */}
                      <circle cx="340" cy="35" r="6" stroke="#6366f1" strokeWidth="1.5" fill="#0f172a" />
                      <text x="355" y="38" fill="#e2e8f0" fontSize="8" textAnchor="start" fontWeight="semibold" className="select-none">Web Server</text>
                      <text x="355" y="45" fill="#475569" fontSize="6.5" textAnchor="start" className="font-mono select-none">192.168.10.50</text>

                      {/* DB Server Node */}
                      <circle cx="340" cy="75" r="6" stroke="#6366f1" strokeWidth="1.5" fill="#0f172a" />
                      <text x="355" y="78" fill="#e2e8f0" fontSize="8" textAnchor="start" fontWeight="semibold" className="select-none">DB Server</text>
                      <text x="355" y="85" fill="#475569" fontSize="6.5" textAnchor="start" className="font-mono select-none">192.168.10.51</text>

                      {/* Workstation Node */}
                      <circle cx="340" cy="115" r="6" stroke="#6366f1" strokeWidth="1.5" fill="#0f172a" />
                      <text x="355" y="118" fill="#e2e8f0" fontSize="8" textAnchor="start" fontWeight="semibold" className="select-none">Workstation</text>
                      <text x="355" y="125" fill="#475569" fontSize="6.5" textAnchor="start" className="font-mono select-none">192.168.10.100</text>

                      {/* 4. Active flow vectors mapping */}
                      {activeVectors.map((vec) => {
                        const color = 
                          vec.label === 'BENIGN' ? '#10b981' :
                          (vec.label.includes('DDoS') || vec.label.includes('Hulk') || vec.label.includes('GoldenEye') || vec.label.includes('slowloris') || vec.label.includes('Slowhttptest')) ? '#ef4444' :
                          vec.label.includes('PortScan') ? '#f97316' :
                          (vec.label.includes('Brute') || vec.label.includes('Patator')) ? '#a78bfa' :
                          vec.label.includes('Sql Injection') ? '#facc15' : '#ec4899';
                        const strokeWidth = vec.isAttack ? 2.5 : 1.2;
                        const controlOffset = vec.isAttack ? -35 : -15;
                        const pathString = `M ${vec.fromX} ${vec.fromY} Q ${(vec.fromX + vec.toX)/2} ${(vec.fromY + vec.toY)/2 + controlOffset} ${vec.toX} ${vec.toY}`;
                        
                        return (
                          <g key={vec.id}>
                            {/* Animated vector line path */}
                            <path
                              d={pathString}
                              fill="none"
                              stroke={color}
                              strokeWidth={strokeWidth}
                              opacity={vec.isAttack ? 0.65 : 0.3}
                              strokeLinecap="round"
                              className="transition-all duration-1000"
                            />
                            {/* Flying laser bullet */}
                            <circle r={vec.isAttack ? 3 : 2} fill="#ffffff">
                              <animateMotion
                                path={pathString}
                                dur="0.8s"
                                repeatCount="1"
                                fill="freeze"
                              />
                            </circle>

                            {/* Destination server impact flash */}
                            <circle cx={vec.toX} cy={vec.toY} r="10" stroke={color} strokeWidth="1" fill="none" className="animate-ping" opacity="0.3" />

                            {/* Real-time IP address / Port annotation overlay */}
                            <text
                              x={(vec.fromX + vec.toX)/2}
                              y={(vec.fromY + vec.toY)/2 + controlOffset - 12}
                              fill={color}
                              fontSize="6"
                              textAnchor="middle"
                              fontWeight="bold"
                              className="font-mono select-none pointer-events-none drop-shadow shadow-slate-950 animate-pulse bg-slate-950 px-1 py-0.5 rounded"
                            >
                              {vec.isAttack ? `${vec.label} (${vec.source_ip}:${vec.source_port} → ${vec.dest_port})` : `BENIGN (${vec.source_ip} → ${vec.dest_port})`}
                            </text>
                          </g>
                        );
                      })}
                    </svg>

                    {/* Threat Map overlay */}
                    {activeVectors.length === 0 && (
                      <div className="absolute inset-0 flex items-center justify-center pointer-events-none select-none">
                        <span className="text-[9px] text-slate-600 font-mono tracking-wider uppercase animate-pulse">
                          Awaiting Ingress Stream Telemetry...
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Legend Overlay at the bottom */}
                  <div className="flex justify-between items-center bg-slate-950/40 backdrop-blur-sm border border-slate-900/60 rounded-xl px-3 py-1.5 text-[7px] font-mono text-slate-500 shrink-0 mt-2">
                    <div className="flex gap-4">
                      <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-[#10b981]" /> Benign</div>
                      <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" /> DDoS/DoS</div>
                      <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-[#f97316]" /> PortScan</div>
                      <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-[#a78bfa]" /> BruteForce</div>
                      <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-[#facc15]" /> SQLi</div>
                    </div>
                    <span className="text-[6.5px] text-purple-400 font-semibold animate-pulse uppercase tracking-wide">Live Attack Monitor</span>
                  </div>
                </div>
              </div>

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
              <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-4 flex flex-col lg:flex-row items-center justify-between gap-4 shrink-0">
                <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto">
                  <div className="relative w-full sm:w-44">
                    <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      placeholder="Filter Attack Label..."
                      value={filterAttack}
                      onChange={(e) => { setFilterAttack(e.target.value); setHistoryPage(1); }}
                      className="w-full bg-slate-950 border border-slate-900 rounded-xl py-2 pl-9 pr-4 text-xs text-slate-300 outline-none"
                    />
                  </div>

                  <div className="relative w-full sm:w-36">
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

                  <div className="relative w-full sm:w-36 flex items-center bg-slate-950 border border-slate-900 rounded-xl px-3 py-1.5 gap-2 text-xs">
                    <span className="text-slate-500 font-mono text-[9px] uppercase">From</span>
                    <input
                      type="date"
                      value={filterDateFrom}
                      onChange={(e) => { setFilterDateFrom(e.target.value); setHistoryPage(1); }}
                      className="bg-transparent text-slate-300 outline-none w-full text-xs cursor-pointer filter-date-picker"
                    />
                  </div>

                  <div className="relative w-full sm:w-36 flex items-center bg-slate-950 border border-slate-900 rounded-xl px-3 py-1.5 gap-2 text-xs">
                    <span className="text-slate-500 font-mono text-[9px] uppercase">To</span>
                    <input
                      type="date"
                      value={filterDateTo}
                      onChange={(e) => { setFilterDateTo(e.target.value); setHistoryPage(1); }}
                      className="bg-transparent text-slate-300 outline-none w-full text-xs cursor-pointer filter-date-picker"
                    />
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => handleExportReport('pdf')}
                      className="px-3 py-2 bg-purple-600/10 border border-purple-500/20 hover:bg-purple-600/20 text-purple-400 hover:text-purple-300 text-xs font-bold rounded-xl flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      PDF Report
                    </button>
                    <button
                      onClick={() => handleExportReport('csv')}
                      className="px-3 py-2 bg-slate-800/40 border border-slate-750 hover:bg-slate-800/85 text-slate-300 hover:text-slate-200 text-xs font-bold rounded-xl flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      CSV Report
                    </button>
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
            <div className="flex flex-col gap-6 max-w-6xl mx-auto h-full overflow-y-auto pb-8 pr-1">
              
              {/* Lifespan Alert or Loading State */}
              {loadingMetrics && (
                <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-8 flex items-center justify-center">
                  <div className="flex flex-col items-center gap-3">
                    <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
                    <p className="text-xs text-slate-500">Retrieving trained evaluation benchmarks...</p>
                  </div>
                </div>
              )}

              {!loadingMetrics && !metricsData && (
                <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-8 flex items-center justify-center">
                  <div className="text-center text-slate-500 text-xs">
                    Failed to load evaluation metrics. Ensure models are trained and server is running.
                  </div>
                </div>
              )}

              {!loadingMetrics && metricsData && (
                <>
                  {/* Cascade Logic Diagram */}
                  <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-5 shrink-0">
                    <div className="pb-3 border-b border-slate-900/60 mb-5">
                      <h3 className="text-xs font-bold text-white tracking-wide uppercase">AI Cascade Decision logic</h3>
                    </div>
                    <div className="flex flex-col md:flex-row items-center justify-between gap-4 font-mono text-[10px] text-slate-400">
                      <div className="p-4 bg-slate-950 border border-slate-900 rounded-xl text-center flex-1 w-full md:w-auto">
                        <p className="font-bold text-slate-200 mb-1">Incoming Flow Packet</p>
                        <span>Extracts top-30 select features</span>
                      </div>
                      <ArrowRight className="w-4 h-4 text-slate-700 hidden md:block shrink-0" />
                      <div className="p-4 bg-slate-950 border border-purple-500/20 rounded-xl text-center flex-1 w-full md:w-auto shadow-md shadow-purple-500/5">
                        <p className="font-bold text-purple-400 mb-1">Tier 1: LightGBM</p>
                        <span>Is Max Conf &gt;= 0.85?</span>
                      </div>
                      <ArrowRight className="w-4 h-4 text-slate-700 hidden md:block shrink-0" />
                      <div className="p-4 bg-slate-950 border border-indigo-500/20 rounded-xl text-center flex-1 w-full md:w-auto shadow-md shadow-indigo-500/5">
                        <p className="font-bold text-indigo-400 mb-1">Tier 2: Random Forest</p>
                        <span>Is Max Conf &gt;= 0.85?</span>
                      </div>
                      <ArrowRight className="w-4 h-4 text-slate-700 hidden md:block shrink-0" />
                      <div className="p-4 bg-slate-950 border border-emerald-500/20 rounded-xl text-center flex-1 w-full md:w-auto shadow-md shadow-emerald-500/5">
                        <p className="font-bold text-emerald-400 mb-1">Tier 3: Expert Ensemble</p>
                        <span>Weighted Prob ArgMax Vote</span>
                      </div>
                    </div>
                  </div>

                  {/* Benchmarks Metrics Comparison */}
                  <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 shrink-0">
                    {/* 3-Model Comparison Table */}
                    <div className="lg:col-span-3 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col">
                      <div className="pb-3 border-b border-slate-900/60 mb-5 flex justify-between items-center">
                        <h3 className="text-xs font-bold text-white tracking-wide uppercase">Trained Model Performance Comparison</h3>
                        <span className="text-[8px] font-mono text-slate-500 uppercase">Stratified test split validation</span>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse text-slate-300">
                          <thead>
                            <tr className="border-b border-slate-900 text-slate-500 uppercase tracking-wider text-[9px]">
                              <th className="py-2.5 px-3">Classifier Model</th>
                              <th className="py-2.5 px-3 text-right">Accuracy</th>
                              <th className="py-2.5 px-3 text-right">Macro F1</th>
                              <th className="py-2.5 px-3 text-right">Avg Latency</th>
                              <th className="py-2.5 px-3 text-right">Train Time</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-900/80 font-mono text-[10px]">
                            {getComparisonData().map((row) => (
                              <tr key={row.name} className="hover:bg-slate-900/10">
                                <td className="py-3 px-3 font-sans font-bold text-slate-200">{row.name}</td>
                                <td className="py-3 px-3 text-right text-emerald-400 font-semibold">{row.accuracy.toFixed(3)}%</td>
                                <td className="py-3 px-3 text-right text-purple-400 font-semibold">{row.macro_f1.toFixed(3)}%</td>
                                <td className="py-3 px-3 text-right text-indigo-400 font-semibold">{(row.avg_latency * 1000).toFixed(2)} μs</td>
                                <td className="py-3 px-3 text-right text-slate-400">{row.training_time.toFixed(1)}s</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <p className="text-[9px] text-slate-500 mt-4 leading-normal">
                        * Latency counts capture mean inference cycles per sample on hardware. Performance benchmarks are updated dynamically when models are retrained.
                      </p>
                    </div>

                    {/* Order Explanation Panel */}
                    <div className="lg:col-span-2 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between">
                      <div>
                        <div className="pb-3 border-b border-slate-900/60 mb-4">
                          <h3 className="text-xs font-bold text-white tracking-wide uppercase">Cascade Order Rationale</h3>
                        </div>
                        <div className="space-y-3.5 text-xs text-slate-400">
                          <div>
                            <span className="text-[9px] font-bold text-purple-400 uppercase tracking-wider block mb-1">1. Tier 1: LightGBM (Screener)</span>
                            <p className="text-[10px] leading-relaxed text-slate-450">
                              Selected for speed (~10.2 μs). Screens out 90%+ clear-cut BENIGN flows immediately, protecting backend threads from volumetric spikes.
                            </p>
                          </div>
                          <div>
                            <span className="text-[9px] font-bold text-indigo-400 uppercase tracking-wider block mb-1">2. Tier 2: Random Forest (Validator)</span>
                            <p className="text-[10px] leading-relaxed text-slate-450">
                              Queried only on LGBM uncertainty. Extremely fast (~2.88 μs) and highly explainable, driving local XAI feature attributions for logged threat alerts.
                            </p>
                          </div>
                          <div>
                            <span className="text-[9px] font-bold text-emerald-400 uppercase tracking-wider block mb-1">3. Tier 3: Ensemble (Vote Arbiter)</span>
                            <p className="text-[10px] leading-relaxed text-slate-450">
                              Handles low-confidence edge cases. Executes a weighted ensemble vote (LGBM 0.2 / RF 0.3 / XGB 0.5) to minimize false alarm ratios.
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Confusion Matrices Heatmap & Feature Importances */}
                  <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 shrink-0">
                    
                    {/* Heatmap Card */}
                    <div className="lg:col-span-3 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col">
                      <div className="pb-3 border-b border-slate-900/60 mb-5 flex flex-wrap items-center justify-between gap-4">
                        <div className="flex flex-col gap-0.5">
                          <h3 className="text-xs font-bold text-white tracking-wide uppercase">Confusion Matrix Heatmap</h3>
                          <span className="text-[8px] font-mono text-slate-500 uppercase">Actual vs Predicted class flows</span>
                        </div>
                        
                        {/* Selector Buttons */}
                        <div className="flex gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-900">
                          {(['lightgbm', 'random_forest', 'xgboost'] as const).map((m) => (
                            <button
                              key={m}
                              onClick={() => { setSelectedCMModel(m); setHoveredCMCell(null); }}
                              className={`px-3 py-1.5 rounded-lg text-[9px] font-bold font-mono tracking-wide uppercase transition-all cursor-pointer ${
                                selectedCMModel === m
                                  ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                                  : 'text-slate-500 hover:text-slate-300 border border-transparent'
                              }`}
                            >
                              {m === 'lightgbm' ? 'LGBM' : m === 'random_forest' ? 'RF' : 'XGB'}
                            </button>
                          ))}
                        </div>
                      </div>
                      
                      {renderConfusionMatrix(selectedCMModel)}
                    </div>

                    {/* RF Feature Importances Bar Chart */}
                    <div className="lg:col-span-2 bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between">
                      <div>
                        <div className="pb-3 border-b border-slate-900/60 mb-5 flex items-center justify-between">
                          <div className="flex flex-col gap-0.5">
                            <h3 className="text-xs font-bold text-white tracking-wide uppercase">RF Feature Importances</h3>
                            <span className="text-[8px] font-mono text-slate-500 uppercase">Top random forest global weights</span>
                          </div>
                          
                          {/* Toggle features count */}
                          <div className="flex gap-1 bg-slate-950 p-1 rounded-xl border border-slate-900">
                            {[10, 20].map((num) => (
                              <button
                                key={num}
                                onClick={() => setNumFeaturesToShow(num)}
                                className={`px-2.5 py-1 rounded-lg text-[9px] font-bold font-mono transition-all cursor-pointer ${
                                  numFeaturesToShow === num
                                    ? 'bg-purple-600/10 border border-purple-500/20 text-purple-300'
                                    : 'text-slate-500 hover:text-slate-350 border border-transparent'
                                }`}
                              >
                                Top {num}
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Chart Render container */}
                        <div className="relative w-full h-[320px] mt-2 shrink-0">
                          <ResponsiveContainer width="99%" height="100%">
                            <BarChart
                              data={(metricsData?.feature_importances || []).slice(0, numFeaturesToShow)}
                              layout="vertical"
                              margin={{ top: 5, right: 10, left: -25, bottom: 5 }}
                            >
                              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                              <XAxis type="number" stroke="#475569" fontSize={8} />
                              <YAxis type="category" dataKey="feature" stroke="#475569" fontSize={7.5} width={120} />
                              <Tooltip
                                contentStyle={{
                                  backgroundColor: '#0f172a',
                                  borderColor: '#1e293b',
                                  borderRadius: '12px',
                                  fontSize: 10
                                }}
                              />
                              <Bar dataKey="importance" name="Global weight" fill="#a78bfa" radius={[0, 4, 4, 0]} barSize={numFeaturesToShow === 10 ? 12 : 6} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      </div>
                    </div>

                    {/* SMOTE Class Balancing Analysis */}
                    {smoteData && (
                      <div className="lg:col-span-2 grid grid-cols-1 lg:grid-cols-2 gap-6 shrink-0 mt-2">
                        {/* Before SMOTE */}
                        <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between">
                          <div>
                            <div className="pb-3 border-b border-slate-900/60 mb-5">
                              <h3 className="text-xs font-bold text-white tracking-wide uppercase">Class Distribution Before SMOTE</h3>
                              <span className="text-[8px] font-mono text-slate-500 uppercase">Severe class imbalance (Raw training set proportions)</span>
                            </div>
                            <div className="relative w-full h-[340px] mt-2 shrink-0">
                              <ResponsiveContainer width="99%" height="100%">
                                <BarChart
                                  data={getSmoteChartData()}
                                  layout="vertical"
                                  margin={{ top: 5, right: 10, left: -20, bottom: 5 }}
                                >
                                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                                  <XAxis type="number" stroke="#475569" fontSize={8} />
                                  <YAxis type="category" dataKey="class" stroke="#475569" fontSize={7.5} width={110} />
                                  <Tooltip
                                    contentStyle={{
                                      backgroundColor: '#0f172a',
                                      borderColor: '#1e293b',
                                      borderRadius: '12px',
                                      fontSize: 10
                                    }}
                                    formatter={(value: any) => [Number(value).toLocaleString(), "Samples"]}
                                  />
                                  <Bar dataKey="Before SMOTE" fill="#f87171" radius={[0, 4, 4, 0]} barSize={8} />
                                </BarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        </div>

                        {/* After SMOTE */}
                        <div className="bg-slate-900/20 border border-slate-900 rounded-2xl p-5 flex flex-col justify-between">
                          <div>
                            <div className="pb-3 border-b border-slate-900/60 mb-5">
                              <h3 className="text-xs font-bold text-white tracking-wide uppercase">Class Distribution After SMOTE</h3>
                              <span className="text-[8px] font-mono text-slate-500 uppercase">Oversampled synthetic balance (SMOTE synthesized training set)</span>
                            </div>
                            <div className="relative w-full h-[340px] mt-2 shrink-0">
                              <ResponsiveContainer width="99%" height="100%">
                                <BarChart
                                  data={getSmoteChartData()}
                                  layout="vertical"
                                  margin={{ top: 5, right: 10, left: -20, bottom: 5 }}
                                >
                                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                                  <XAxis type="number" stroke="#475569" fontSize={8} />
                                  <YAxis type="category" dataKey="class" stroke="#475569" fontSize={7.5} width={110} />
                                  <Tooltip
                                    contentStyle={{
                                      backgroundColor: '#0f172a',
                                      borderColor: '#1e293b',
                                      borderRadius: '12px',
                                      fontSize: 10
                                    }}
                                    formatter={(value: any) => [Number(value).toLocaleString(), "Samples"]}
                                  />
                                  <Bar dataKey="After SMOTE" fill="#34d399" radius={[0, 4, 4, 0]} barSize={8} />
                                </BarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                  </div>
                </>
              )}

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
                        <div>{msg.text}</div>
                        {msg.role === 'assistant' && msg.source && (
                          <div className="mt-2 flex items-center justify-end">
                            <span className={`px-2 py-0.5 rounded text-[8px] font-mono font-bold tracking-wider uppercase ${
                              msg.source === 'AI Gemini'
                                ? 'bg-purple-950/40 border border-purple-500/35 text-purple-300'
                                : msg.source === 'Rule-Based'
                                ? 'bg-indigo-950/40 border border-indigo-500/35 text-indigo-300'
                                : 'bg-slate-950/50 border border-slate-850 text-slate-450'
                            }`}>
                              {msg.source}
                            </span>
                          </div>
                        )}
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
      {selectedDetection && (() => {
        const RADAR_FEATURES = [
          { name: 'Init Fwd Win', key: 'Init_Win_bytes_forward', max: 65535 },
          { name: 'Init Bwd Win', key: 'Init_Win_bytes_backward', max: 65535 },
          { name: 'Max Bwd Pkt', key: 'Bwd Packet Length Max', max: 2000 },
          { name: 'Max Fwd Pkt', key: 'Fwd Packet Length Max', max: 2000 },
          { name: 'Avg Pkt Size', key: 'Average Packet Size', max: 1500 },
          { name: 'Pkt Var', key: 'Packet Length Variance', max: 500000 },
          { name: 'Total Fwd Len', key: 'Total Length of Fwd Packets', max: 10000 },
          { name: 'Bwd Pkts/s', key: 'Bwd Packets/s', max: 5000 }
        ];

        const radarData = RADAR_FEATURES.map(f => {
          const rawVal = selectedDetection.raw_features?.[f.key] ?? 0.0;
          const benignAvg = selectedDetection.benign_averages?.[f.key] ?? 0.0;
          const normAttack = Math.min(1.0, Math.max(0.0, rawVal / f.max));
          const normBenign = Math.min(1.0, Math.max(0.0, benignAvg / f.max));
          return {
            subject: f.name,
            "This Attack": parseFloat(normAttack.toFixed(3)),
            "Normal Baseline": parseFloat(normBenign.toFixed(3))
          };
        });

        return (
          <div className="absolute inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-3xl w-full max-w-4xl p-6 relative shadow-2xl animate-scaleUp">
              
              {/* Modal header */}
              <div className="pb-4 border-b border-slate-800/60 flex items-center justify-between mb-6">
                <div className="flex items-center gap-2.5">
                  <Sparkles className="w-5 h-5 text-purple-400 animate-pulse" />
                  <h3 className="text-sm font-bold text-white">Explain This Packet</h3>
                </div>
                <button
                  onClick={() => setSelectedDetection(null)}
                  className="p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-800 border border-transparent rounded-lg cursor-pointer transition-colors"
                >
                  ✕
                </button>
              </div>

              {/* 2-Column layout grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* LEFT COLUMN: VERDICTS & RADAR SIGNATURE */}
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div className="bg-slate-950/40 border border-slate-900 p-3.5 rounded-xl">
                      <span className="text-[9px] text-slate-500 font-bold block mb-1">Classification Verdict</span>
                      <span className={`px-2 py-0.5 border rounded font-semibold uppercase text-[9px] ${
                        selectedDetection.predicted_label.toUpperCase() !== 'BENIGN'
                          ? 'bg-red-950/20 border-red-500/20 text-red-400'
                          : 'bg-emerald-950/20 border-emerald-500/20 text-emerald-400'
                      }`}>
                        {selectedDetection.predicted_label}
                      </span>
                    </div>
                    <div className="bg-slate-950/40 border border-slate-900 p-3.5 rounded-xl">
                      <span className="text-[9px] text-slate-500 font-bold block mb-1">Confidence Score</span>
                      <span className="text-white font-bold">{(selectedDetection.confidence * 100).toFixed(2)}%</span>
                    </div>
                  </div>

                  <div className="bg-slate-950/40 border border-slate-900 p-3.5 rounded-xl text-xs">
                    <span className="text-[9px] text-slate-500 font-bold block mb-1">Deciding ML Classifier Tier</span>
                    <span className="text-slate-300 font-semibold">{selectedDetection.tier_name}</span>
                  </div>

                  {/* Attack DNA Radar Chart Container */}
                  <div className="bg-slate-950/40 border border-slate-900/60 p-4 rounded-xl flex flex-col items-center">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block self-start mb-2">Threat DNA Signature (Normalized 0-1)</span>
                    <div className="w-full h-[220px] flex items-center justify-center">
                      <ResponsiveContainer width="100%" height="100%">
                        <RadarChart cx="50%" cy="50%" outerRadius="75%" data={radarData}>
                          <PolarGrid stroke="#1e293b" opacity={0.6} />
                          <PolarAngleAxis dataKey="subject" stroke="#94a3b8" fontSize={8} />
                          <PolarRadiusAxis angle={30} domain={[0, 1.0]} stroke="#475569" fontSize={7} tickCount={3} />
                          <Radar name="This Attack" dataKey="This Attack" stroke="#a78bfa" fill="#8b5cf6" fillOpacity={0.25} />
                          <Radar name="Normal Baseline" dataKey="Normal Baseline" stroke="#334155" fill="#1e293b" fillOpacity={0.15} />
                          <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: 10 }} />
                        </RadarChart>
                      </ResponsiveContainer>
                    </div>
                    {/* Legend */}
                    <div className="flex gap-4 mt-1 text-[9px] font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 bg-purple-500/30 border border-purple-450 rounded animate-pulse"></span>
                        <span className="text-purple-300 font-bold">This Flow</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 bg-slate-800/30 border border-slate-700 rounded"></span>
                        <span className="text-slate-400">Normal Baseline</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* RIGHT COLUMN: ATTRIBUTIONS & NATURAL LANGUAGE */}
                <div className="space-y-4 flex flex-col justify-between">
                  {/* Feature Impact comparisons bar charts */}
                  <div>
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-3">Top Attributing Features (This vs Benign Avg)</span>
                    <div className="space-y-2.5">
                      {selectedDetection.top_features.map((feat, idx) => {
                        const val = feat.value;
                        const benignAvg = feat.benign_avg ?? 0.0;
                        const maxVal = Math.max(val, benignAvg) || 1.0;
                        const valPct = (val / maxVal) * 100;
                        const benignPct = (benignAvg / maxVal) * 100;

                        return (
                          <div key={idx} className="text-xs bg-slate-950/40 border border-slate-900/60 p-3 rounded-xl space-y-1.5">
                            <div className="flex justify-between text-slate-400 font-mono text-[9px]">
                              <span className="font-semibold text-slate-350">{feat.feature}</span>
                            </div>
                            
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="text-[8px] text-purple-400 w-16 font-semibold shrink-0">This Flow:</span>
                                <div className="flex-1 bg-slate-950 h-1.5 rounded-full overflow-hidden relative">
                                  <div
                                    className="h-full bg-gradient-to-r from-purple-500 to-indigo-500 rounded-full"
                                    style={{ width: `${valPct}%` }}
                                  ></div>
                                </div>
                                <span className="text-[8px] text-slate-200 font-mono w-16 text-right shrink-0">
                                  {val.toLocaleString(undefined, {maximumFractionDigits: 2})}
                                </span>
                              </div>

                              <div className="flex items-center gap-2">
                                <span className="text-[8px] text-slate-500 w-16 font-semibold shrink-0">Benign Avg:</span>
                                <div className="flex-1 bg-slate-950 h-1.5 rounded-full overflow-hidden relative">
                                  <div
                                    className="h-full bg-slate-800 rounded-full"
                                    style={{ width: `${benignPct}%` }}
                                  ></div>
                                </div>
                                <span className="text-[8px] text-slate-400 font-mono w-16 text-right shrink-0">
                                  {benignAvg.toLocaleString(undefined, {maximumFractionDigits: 2})}
                                </span>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Natural English explanation sentence */}
                  <div className="bg-slate-950/40 border border-slate-900 p-3.5 rounded-xl space-y-1.5 mt-auto">
                    <span className="text-[9px] text-purple-400 font-bold uppercase tracking-wider block">Natural AI Threat Attribution</span>
                    {loadingExplanation ? (
                      <div className="space-y-2 py-1 animate-pulse">
                        <div className="h-3 bg-slate-850 rounded w-full"></div>
                        <div className="h-3 bg-slate-850 rounded w-5/6"></div>
                      </div>
                    ) : (
                      <p className="text-[11px] leading-relaxed text-slate-200 font-sans">
                        {aiExplanation || "Unable to retrieve explanation attribution details."}
                      </p>
                    )}
                  </div>
                </div>

              </div>

              {/* Modal footer */}
              <div className="mt-6 pt-4 border-t border-slate-800/60 text-right">
                <button
                  onClick={() => setSelectedDetection(null)}
                  className="px-5 py-2 bg-slate-950 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-bold rounded-xl text-xs uppercase tracking-wide cursor-pointer transition-colors"
                >
                  Close Explanation
                </button>
              </div>

            </div>
          </div>
        );
      })()}

    </div>
  );
};
export default Dashboard;
