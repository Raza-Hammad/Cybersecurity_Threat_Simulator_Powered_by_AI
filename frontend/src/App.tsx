import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import DesignSystemDemo from './pages/DesignSystemDemo';
import Intro from './pages/Intro';

// ProtectedRoute component redirects users to /login if not authenticated
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  
  // Check if token exists in state or storage
  const hasToken = isAuthenticated || !!localStorage.getItem('token');
  
  return hasToken ? <>{children}</> : <Navigate to="/login" replace />;
};

function App() {
  const [showIntro, setShowIntro] = useState(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mediaQuery.matches) return false;
    return !sessionStorage.getItem('hasSeenIntro');
  });

  useEffect(() => {
    const handleReplay = () => {
      setShowIntro(true);
    };
    window.addEventListener('replay-intro', handleReplay);
    return () => window.removeEventListener('replay-intro', handleReplay);
  }, []);

  const handleIntroComplete = () => {
    sessionStorage.setItem('hasSeenIntro', 'true');
    setShowIntro(false);
  };

  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route 
            path="/login" 
            element={
              showIntro ? <Intro onComplete={handleIntroComplete} /> : <Login />
            } 
          />
          <Route path="/design-system" element={<DesignSystemDemo />} />
          <Route
            path="/"
            element={
              showIntro ? (
                <Intro onComplete={handleIntroComplete} />
              ) : (
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              )
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
