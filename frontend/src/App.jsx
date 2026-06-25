import { useState, useEffect, useRef } from 'react';
import { Shield, Play, Square, Activity, AlertTriangle, ShieldAlert, Server, Radio, Menu, X } from 'lucide-react';
import './index.css';

const API_BASE = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws/traffic';

function App() {
  const [isRunning, setIsRunning] = useState(false);
  const [protocol, setProtocol] = useState('ALL');
  const [port, setPort] = useState('');
  const [status, setStatus] = useState('disconnected'); // 'disconnected', 'connecting', 'connected', 'error'
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  
  const [stats, setStats] = useState({
    total: 0,
    tcp: 0,
    udp: 0,
    alerts: 0
  });
  
  const [trafficLogs, setTrafficLogs] = useState([]);
  const [alertLogs, setAlertLogs] = useState([]);
  
  const wsRef = useRef(null);
  const trafficLogEndRef = useRef(null);
  const alertLogEndRef = useRef(null);

  // Auto-scroll logs
  useEffect(() => {
    trafficLogEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [trafficLogs]);

  useEffect(() => {
    alertLogEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [alertLogs]);

  // WebSocket Connection
  useEffect(() => {
    const connectWS = () => {
      setStatus('connecting');
      const ws = new WebSocket(WS_URL);
      
      ws.onopen = () => setStatus('connected');
      
      ws.onclose = () => {
        setStatus('disconnected');
        // Auto reconnect logic could go here
      };
      
      ws.onerror = () => setStatus('error');
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'packet') {
          setStats(data.stats);
          
          // Format traffic log
          const { info, warnings } = data;
          const sport = info.src_port ? `:${info.src_port}` : '';
          const dport = info.dst_port ? `:${info.dst_port}` : '';
          
          setTrafficLogs(prev => {
            const newLog = {
              id: Date.now() + Math.random(),
              time: new Date().toLocaleTimeString(),
              msg: `${info.protocol.padEnd(4)} | ${info.src_ip}${sport} → ${info.dst_ip}${dport} | Len: ${info.length}`
            };
            return [...prev, newLog].slice(-100); // Keep last 100
          });
          
          if (warnings && warnings.length > 0) {
            setAlertLogs(prev => {
              const newAlerts = warnings.map(w => ({
                id: Date.now() + Math.random(),
                time: new Date().toLocaleTimeString(),
                msg: w
              }));
              return [...prev, ...newAlerts].slice(-50); // Keep last 50
            });
          }
        }
      };
      
      wsRef.current = ws;
    };
    
    connectWS();
    return () => wsRef.current?.close();
  }, []);

  // Fetch initial status
  useEffect(() => {
    fetch(`${API_BASE}/api/status`)
      .then(res => res.json())
      .then(data => {
        setIsRunning(data.is_running);
        if (data.stats) setStats(data.stats);
      })
      .catch(console.error);
  }, []);

  const handleStart = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          protocol, 
          port: port ? parseInt(port) : null 
        })
      });
      const data = await res.json();
      if (data.status === 'success') {
        setIsRunning(true);
      }
    } catch (err) {
      console.error('Failed to start capture', err);
    }
  };

  const handleStop = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/stop`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.status === 'success') {
        setIsRunning(false);
      }
    } catch (err) {
      console.error('Failed to stop capture', err);
    }
  };

  return (
    <div className="app-container">
      {/* Mobile Top Bar */}
      <header className="mobile-top-bar">
        <button className="menu-toggle-btn" onClick={() => setIsSidebarOpen(true)} aria-label="Open controls menu">
          <Menu size={24} />
        </button>
        <div className="mobile-logo">
          <Shield className="logo-icon-small" size={20} color="var(--primary-color)" />
          <span className="mobile-logo-text">Sentinel AI</span>
        </div>
        <div className="mobile-status">
          <div className={`status-dot ${status === 'connected' ? 'active' : status === 'error' ? 'error' : ''}`} title={`API Connection: ${status}`}></div>
        </div>
      </header>

      {/* Sidebar Overlay */}
      {isSidebarOpen && <div className="sidebar-overlay" onClick={() => setIsSidebarOpen(false)}></div>}

      {/* Sidebar / Controls */}
      <aside className={`glass-panel sidebar ${isSidebarOpen ? 'open' : ''}`}>
        <button className="close-sidebar-btn" onClick={() => setIsSidebarOpen(false)} aria-label="Close controls menu">
          <X size={20} />
        </button>
        <div className="logo-container">
          <Shield className="logo-icon" style={{ color: 'var(--primary-color)' }} />
          <div className="logo-text">Sentinel AI</div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Security Analyzer</div>
        </div>

        <div className="controls">
          <div className="control-group">
            <label className="control-label">Protocol Filter</label>
            <select 
              className="glass-select" 
              value={protocol} 
              onChange={(e) => setProtocol(e.target.value)}
              disabled={isRunning}
            >
              <option value="ALL">ALL TRAFFIC</option>
              <option value="TCP">TCP ONLY</option>
              <option value="UDP">UDP ONLY</option>
              <option value="ICMP">ICMP ONLY</option>
            </select>
          </div>

          <div className="control-group">
            <label className="control-label">Target Port</label>
            <input 
              type="number" 
              className="glass-input" 
              placeholder="e.g., 80 or 443" 
              value={port}
              onChange={(e) => setPort(e.target.value)}
              disabled={isRunning}
            />
          </div>

          <div style={{ marginTop: '2rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {!isRunning ? (
              <button className="btn btn-start" onClick={() => { handleStart(); setIsSidebarOpen(false); }}>
                <Play size={20} /> Start Capture
              </button>
            ) : (
              <button className="btn btn-stop" onClick={() => { handleStop(); setIsSidebarOpen(false); }}>
                <Square size={20} /> Stop Capture
              </button>
            )}
          </div>
        </div>

        <div className="status-indicator">
          <div className={`status-dot ${status === 'connected' ? 'active' : status === 'error' ? 'error' : ''}`}></div>
          <span>API Connection: {status}</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {/* Top Stats */}
        <div className="stats-grid">
          <div className="glass-panel stat-card">
            <Activity className="mb-2" color="var(--primary-color)" />
            <div className="stat-title">Total Packets</div>
            <div className="stat-value">{stats.total.toLocaleString()}</div>
          </div>
          <div className="glass-panel stat-card">
            <Server className="mb-2" color="var(--primary-color)" />
            <div className="stat-title">TCP Traffic</div>
            <div className="stat-value">{stats.tcp.toLocaleString()}</div>
          </div>
          <div className="glass-panel stat-card">
            <Radio className="mb-2" color="var(--primary-color)" />
            <div className="stat-title">UDP Traffic</div>
            <div className="stat-value">{stats.udp.toLocaleString()}</div>
          </div>
          <div className="glass-panel stat-card" style={{ borderColor: stats.alerts > 0 ? 'rgba(239, 68, 68, 0.4)' : '' }}>
            <ShieldAlert className="mb-2" color={stats.alerts > 0 ? 'var(--alert-color)' : 'var(--primary-color)'} />
            <div className="stat-title">Security Alerts</div>
            <div className={`stat-value ${stats.alerts > 0 ? 'alert' : ''}`}>{stats.alerts.toLocaleString()}</div>
          </div>
        </div>

        {/* Logs Area */}
        <div className="logs-container">
          <div className="glass-panel log-panel">
            <div className="log-header">
              <div className="log-title">
                <Activity size={20} color="var(--primary-color)" />
                Live Network Traffic
              </div>
            </div>
            <div className="log-content">
              {trafficLogs.length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', textAlign: 'center', marginTop: '2rem' }}>
                  No traffic captured yet. Start the engine.
                </div>
              ) : (
                trafficLogs.map(log => (
                  <div key={log.id} className="log-entry">
                    <div className="log-meta">{log.time}</div>
                    {log.msg}
                  </div>
                ))
              )}
              <div ref={trafficLogEndRef} />
            </div>
          </div>

          <div className="glass-panel log-panel" style={{ borderColor: alertLogs.length > 0 ? 'rgba(239, 68, 68, 0.2)' : '' }}>
            <div className="log-header">
              <div className={`log-title ${alertLogs.length > 0 ? 'alert' : ''}`}>
                <AlertTriangle size={20} />
                Threat Detections
              </div>
            </div>
            <div className="log-content">
              {alertLogs.length === 0 ? (
                <div style={{ color: 'var(--success-color)', textAlign: 'center', marginTop: '2rem' }}>
                  No threats detected. Network is secure.
                </div>
              ) : (
                alertLogs.map(log => (
                  <div key={log.id} className="log-entry alert">
                    <div className="log-meta">{log.time}</div>
                    {log.msg}
                  </div>
                ))
              )}
              <div ref={alertLogEndRef} />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
