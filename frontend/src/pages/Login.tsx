import React, { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, User, AlertCircle, RefreshCw } from 'lucide-react';

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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center font-sans relative overflow-hidden px-4">
      {/* Background glow graphics */}
      <div className="absolute top-[-20%] left-[-20%] w-[60%] h-[60%] rounded-full bg-purple-900/10 blur-[150px] pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-20%] w-[60%] h-[60%] rounded-full bg-indigo-900/10 blur-[150px] pointer-events-none"></div>

      <div className="w-full max-w-md bg-slate-900/50 border border-slate-800/80 rounded-3xl p-8 backdrop-blur-md relative z-10 shadow-2xl shadow-purple-500/5">
        <div className="flex flex-col items-center gap-3 mb-8">
          <div className="p-3 bg-gradient-to-br from-purple-600 to-indigo-600 rounded-2xl shadow-xl shadow-purple-500/20">
            <Shield className="w-8 h-8 text-white animate-pulse" />
          </div>
          <div className="text-center">
            <h2 className="text-2xl font-extrabold text-white tracking-tight leading-tight">
              ThreatSim AI - SOC Portal
            </h2>
            <p className="text-slate-400 text-xs mt-1">
              Authorized cybersecurity analysts only
            </p>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-950/20 border border-red-500/20 rounded-2xl flex items-start gap-3 animate-headShake text-red-400 text-xs">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">Access Denied: </span>
              {error}
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="text-slate-400 text-xs font-semibold block mb-2">
              Username
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
                <User className="w-4 h-4" />
              </div>
              <input
                type="text"
                required
                disabled={loading}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full bg-slate-950 border border-slate-800/80 hover:border-slate-700/80 focus:border-purple-500 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-100 placeholder-slate-600 outline-none transition-all"
              />
            </div>
          </div>

          <div>
            <label className="text-slate-400 text-xs font-semibold block mb-2">
              Password
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                required
                disabled={loading}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter secure password"
                className="w-full bg-slate-950 border border-slate-800/80 hover:border-slate-700/80 focus:border-purple-500 rounded-xl py-3 pl-11 pr-4 text-sm text-slate-100 placeholder-slate-600 outline-none transition-all"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:from-purple-800 disabled:to-indigo-800 text-white font-semibold rounded-xl text-sm transition-all shadow-lg shadow-purple-500/25 flex items-center justify-center gap-2 cursor-pointer"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Authenticating Credentials...
              </>
            ) : (
              'Access Security Operations'
            )}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-slate-800/50 text-center">
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
