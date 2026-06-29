import React, { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import RadarBackground from '../components/ui/RadarBackground';
import GlowPanel from '../components/ui/GlowPanel';
import GlowButton from '../components/ui/GlowButton';
import StatusBadge from '../components/ui/StatusBadge';
import { Shield, Lock, User, RefreshCw } from 'lucide-react';

export const Login: React.FC = () => {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // If already logged in, redirect to dashboard
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      // Form-urlencode payload to fit OAuth2 Password Flow
      const params = new URLSearchParams();
      params.append('username', username);
      params.append('password', password);

      const response = await axios.post('/api/auth/login', params, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      if (response.data && response.data.access_token) {
        login(response.data.access_token);
        navigate('/', { replace: true });
      } else {
        setError('Authentication returned an empty token.');
      }
    } catch (err: any) {
      console.error('Login error:', err);
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Failed to connect to authentication services.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)] flex items-center justify-center font-sans relative overflow-hidden px-4 select-none">
      {/* Ambient Console Sweep in background */}
      <RadarBackground />

      <div className="w-full max-w-md relative z-10 space-y-6">
        
        {/* Logo/Identity Section */}
        <div className="flex flex-col items-center gap-2.5 text-center">
          <div className="p-3 bg-gradient-to-br from-amber-500/20 to-amber-700/20 border border-[var(--border-subtle)] rounded-2xl shadow-xl shadow-amber-500/5">
            <Shield className="w-7 h-7 text-[var(--accent-amber)] animate-pulse" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight leading-tight uppercase font-display">
              ThreatSim AI
            </h1>
            <p className="text-[var(--text-secondary)] text-[10px] tracking-widest uppercase font-semibold mt-0.5">
              SOC Command Console
            </p>
          </div>
        </div>

        {/* GlowPanel form wrapper */}
        <GlowPanel className="p-7">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="text-[var(--text-secondary)] text-[10px] uppercase font-semibold block mb-2">
                Analyst Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  disabled={loading}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter analyst ID"
                  className="w-full bg-[var(--bg-base)] border border-[var(--border-subtle)] focus:border-[var(--accent-amber)] focus:ring-1 focus:ring-[var(--accent-amber)] rounded-[var(--radius-sm)] py-2.5 pl-10 pr-4 text-xs text-white placeholder-slate-600 outline-none transition-all"
                />
              </div>
            </div>

            <div>
              <label className="text-[var(--text-secondary)] text-[10px] uppercase font-semibold block mb-2">
                Analyst Passcode
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  required
                  disabled={loading}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter secure passcode"
                  className="w-full bg-[var(--bg-base)] border border-[var(--border-subtle)] focus:border-[var(--accent-amber)] focus:ring-1 focus:ring-[var(--accent-amber)] rounded-[var(--radius-sm)] py-2.5 pl-10 pr-4 text-xs text-white placeholder-slate-600 outline-none transition-all"
                />
              </div>
            </div>

            {error && (
              <div className="p-3 bg-orange-950/15 border border-orange-500/20 rounded-[var(--radius-sm)] flex items-start gap-2.5 text-xs text-orange-400 animate-headShake">
                <StatusBadge status="High" className="shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-white">Access Denied:</span> {error}
                </div>
              </div>
            )}

            <GlowButton
              type="submit"
              disabled={loading}
              variant="primary"
              className="w-full py-2.5 mt-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Console Auth Sequence...
                </>
              ) : (
                'Access Security Console'
              )}
            </GlowButton>
          </form>
        </GlowPanel>

        {/* Footer with Replay trigger and Seeding notes */}
        <div className="text-center space-y-3">
          <button 
            type="button"
            onClick={() => {
              sessionStorage.removeItem('hasSeenIntro');
              window.dispatchEvent(new Event('replay-intro'));
            }}
            className="text-[9px] uppercase tracking-wider text-[var(--accent-amber)] hover:text-white transition-colors cursor-pointer select-none font-bold focus:outline-none focus:underline"
          >
            Replay console initialization sequence
          </button>
          <div className="text-[10px] text-slate-500 leading-normal">
            <p>Seeded credentials can be found in the server log outputs on first run.</p>
            <p className="mt-1">All session activities are tracked and cryptographically audited.</p>
          </div>
        </div>
      </div>
    </div>
  );
};
export default Login;
