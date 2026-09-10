import { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { ShieldAlert, MailWarning, CheckCircle, Activity, Search } from 'lucide-react';
import { Link } from 'react-router-dom';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [recentCases, setRecentCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const statsRes = await axios.get(`${API_URL}/dashboard/stats`);
        setStats(statsRes.data);
        
        const casesRes = await axios.get(`${API_URL}/cases?limit=5`);
        setRecentCases(casesRes.data);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  if (loading) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>Loading...</div>;
  }

  const phishingCount = stats?.classification_breakdown?.Phishing || 0;
  const malwareCount = stats?.classification_breakdown?.Malware || 0;
  const safeCount = (stats?.classification_breakdown?.Safe || 0) + 
                    (stats?.classification_breakdown?.Benign || 0) + 
                    (stats?.classification_breakdown?.Legitimate || 0) || 
                    (stats?.benign_cases || 0);

  const chartData = [
    { name: 'Phishing', value: phishingCount, color: '#f59e0b' },
    { name: 'Malware', value: malwareCount, color: '#ef4444' },
    { name: 'Safe', value: safeCount, color: '#10b981' },
  ];

  const getBadgeClass = (classification?: string) => {
    const c = (classification || '').toLowerCase();
    if (c === 'benign' || c === 'safe' || c === 'legitimate') return 'badge-benign';
    if (c === 'phishing') return 'badge-phishing';
    if (c === 'malware') return 'badge-malware';
    return 'badge-unknown';
  };

  const getDisplayClassification = (classification?: string) => {
    const c = (classification || '').toLowerCase();
    if (c === 'benign' || c === 'safe' || c === 'legitimate') return 'SAFE';
    return (classification || 'UNKNOWN').toUpperCase();
  };

  return (
    <div>
      {/* Top Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '0.25rem' }}>Dashboard Overview</h1>
          <p className="text-muted" style={{ fontSize: '0.875rem' }}>Real-time threat intelligence and case metrics.</p>
        </div>
        <Link to="/investigate" className="btn btn-primary" style={{ padding: '0.625rem 1.25rem', fontSize: '0.875rem' }}>
          <Search size={16} /> New Investigation
        </Link>
      </div>

      {/* Top 4 Stat Cards */}
      <div className="dashboard-stats-grid">
        {/* Card 1: Total Cases */}
        <div className="glass-card" style={{ padding: '1.25rem 1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-muted)' }}>Total Cases</span>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              border: '1px solid var(--panel-border)',
              background: 'rgba(255, 255, 255, 0.04)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-muted)'
            }}>
              <Activity size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.25rem', fontWeight: 700, lineHeight: 1, color: 'var(--text-main)' }}>
            {stats?.total_cases || 0}
          </div>
        </div>

        {/* Card 2: Active Investigations */}
        <div className="glass-card" style={{ padding: '1.25rem 1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-muted)' }}>Active Investigations</span>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              border: '1px solid var(--panel-border)',
              background: 'rgba(255, 255, 255, 0.04)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-muted)'
            }}>
              <ShieldAlert size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.25rem', fontWeight: 700, lineHeight: 1, color: 'var(--text-main)' }}>
            {stats?.open_cases || 0}
          </div>
        </div>

        {/* Card 3: Malware Detected */}
        <div className="glass-card" style={{ padding: '1.25rem 1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-muted)' }}>Malware Detected</span>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              border: '1px solid var(--panel-border)',
              background: 'rgba(255, 255, 255, 0.04)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-muted)'
            }}>
              <MailWarning size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.25rem', fontWeight: 700, lineHeight: 1, color: 'var(--text-main)' }}>
            {malwareCount}
          </div>
        </div>

        {/* Card 4: Safe Emails */}
        <div className="glass-card" style={{ padding: '1.25rem 1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.875rem', fontWeight: 500, color: 'var(--text-muted)' }}>Safe Emails</span>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              border: '1px solid var(--panel-border)',
              background: 'rgba(255, 255, 255, 0.04)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-muted)'
            }}>
              <CheckCircle size={18} />
            </div>
          </div>
          <div style={{ fontSize: '2.25rem', fontWeight: 700, lineHeight: 1, color: 'var(--text-main)' }}>
            {safeCount}
          </div>
        </div>
      </div>

      {/* Main Content: Threat Breakdown & Recent Investigations Side-by-Side */}
      <div className="dashboard-main-grid">
        {/* Left Panel: Threat Classification Breakdown */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
              Threat Classification Breakdown
            </h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b', display: 'inline-block' }}></span>
                Phishing
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444', display: 'inline-block' }}></span>
                Malware
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }}></span>
                Safe
              </span>
            </div>
          </div>
          
          <div style={{ height: '320px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 20, right: 20, left: -10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--panel-border)" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  stroke="var(--text-muted)" 
                  fontSize={12} 
                  tickLine={false} 
                  axisLine={{ stroke: 'var(--panel-border)' }} 
                />
                <YAxis 
                  stroke="var(--text-muted)" 
                  fontSize={12} 
                  tickLine={false} 
                  axisLine={false} 
                  allowDecimals={false} 
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'var(--panel-bg)', 
                    borderColor: 'var(--panel-border)', 
                    borderRadius: 'var(--radius-md)', 
                    backdropFilter: 'blur(10px)',
                    color: 'var(--text-main)',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)'
                  }}
                  itemStyle={{ color: 'var(--text-main)' }}
                />
                <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={48}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right Panel: Recent Investigations */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, margin: 0, color: 'var(--text-main)' }}>
              Recent Investigations
            </h2>
            <Link to="/cases" style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', textDecoration: 'none', fontWeight: 500 }}>
              View All
            </Link>
          </div>
          
          <div>
            {recentCases.map((c, index) => {
              const isLast = index === recentCases.length - 1;
              return (
                <div 
                  key={c.id} 
                  style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    padding: '0.875rem 0', 
                    borderBottom: isLast ? 'none' : '1px solid var(--panel-border)' 
                  }}
                >
                  <div style={{ maxWidth: '62%', minWidth: 0 }}>
                    <div style={{ 
                      fontWeight: 600, 
                      fontSize: '0.875rem', 
                      color: 'var(--text-main)', 
                      marginBottom: '0.2rem', 
                      whiteSpace: 'nowrap', 
                      overflow: 'hidden', 
                      textOverflow: 'ellipsis' 
                    }}>
                      {c.subject || 'No Subject'}
                    </div>
                    <div style={{ 
                      fontSize: '0.75rem', 
                      color: 'var(--text-muted)', 
                      whiteSpace: 'nowrap', 
                      overflow: 'hidden', 
                      textOverflow: 'ellipsis' 
                    }}>
                      From: {c.sender_email}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexShrink: 0 }}>
                    <span 
                      className={`badge ${getBadgeClass(c.ai_classification)}`}
                      style={{ fontSize: '0.6875rem', padding: '0.2rem 0.55rem' }}
                    >
                      {getDisplayClassification(c.ai_classification)}
                    </span>
                    <Link 
                      to={`/cases/${c.id}`} 
                      className="btn btn-secondary" 
                      style={{ 
                        padding: '0.25rem 0.75rem', 
                        fontSize: '0.75rem', 
                        borderRadius: 'var(--radius-sm)' 
                      }}
                    >
                      Details
                    </Link>
                  </div>
                </div>
              );
            })}
            
            {recentCases.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2.5rem 0', fontSize: '0.875rem' }}>
                No cases found. Start a new investigation.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
