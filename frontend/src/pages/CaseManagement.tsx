import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { Search, Filter, X, RotateCcw, Trash2 } from 'lucide-react';
import ReportDownloadModal from '../components/ReportDownloadModal';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function CaseManagement() {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Search and Filter States
  const [searchQuery, setSearchQuery] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Report Download Modal States
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [selectedCaseForReport, setSelectedCaseForReport] = useState<any>(null);
  const [isCompletedAction, setIsCompletedAction] = useState(false);

  useEffect(() => {
    const fetchCases = async () => {
      try {
        const response = await axios.get(`${API_URL}/cases?limit=100`);
        setCases(response.data);
      } catch (error) {
        console.error('Error fetching cases:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchCases();
  }, []);

  const handleComplete = async (id: number) => {
    try {
      await axios.put(`${API_URL}/cases/${id}/status?status=Closed`);
      setCases(prev => prev.map(c => c.id === id ? { ...c, status: 'Closed' } : c));
      
      // DO NOT autodownload. Ask user which format to download:
      const targetCase = cases.find(c => c.id === id) || { id, status: 'Closed' };
      setSelectedCaseForReport({ ...targetCase, status: 'Closed' });
      setIsCompletedAction(true);
      setDownloadModalOpen(true);
    } catch (error) {
      console.error('Error completing case:', error);
    }
  };

  const handleOpenReportModal = (caseItem: any) => {
    setSelectedCaseForReport(caseItem);
    setIsCompletedAction(false);
    setDownloadModalOpen(true);
  };

  const handleDelete = async (id: number, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const confirmed = window.confirm(`Are you sure you want to delete Case #${id}? This will permanently remove the case and its forensic evidence.`);
    if (!confirmed) return;

    try {
      await axios.delete(`${API_URL}/cases/${id}`);
      setCases(prevCases => prevCases.filter(c => c.id !== id));
    } catch (error) {
      console.error('Error deleting case:', error);
      alert('Failed to delete case. Please try again.');
    }
  };

  // Badge class helper
  const getBadgeClass = (classification?: string) => {
    const c = (classification || '').toLowerCase();
    if (c === 'benign' || c === 'safe' || c === 'legitimate') return 'badge-benign';
    if (c === 'phishing') return 'badge-phishing';
    if (c === 'malware') return 'badge-malware';
    if (c === 'suspicious' || c === 'spam') return 'badge-suspicious';
    return 'badge-unknown';
  };

  const formatClassification = (classification?: string) => {
    const c = (classification || '').toLowerCase();
    if (c === 'benign' || c === 'safe' || c === 'legitimate') return 'SAFE';
    return (classification || 'UNKNOWN').toUpperCase();
  };

  // Compute live counts
  const counts = useMemo(() => {
    const total = cases.length;
    const open = cases.filter(c => (c.status || '').toLowerCase() === 'open').length;
    const investigating = cases.filter(c => (c.status || '').toLowerCase() === 'investigating').length;
    const closed = cases.filter(c => (c.status || '').toLowerCase() === 'closed').length;

    const phishing = cases.filter(c => (c.ai_classification || '').toLowerCase() === 'phishing').length;
    const malware = cases.filter(c => (c.ai_classification || '').toLowerCase() === 'malware').length;
    const benign = cases.filter(c => ['benign', 'safe', 'legitimate'].includes((c.ai_classification || '').toLowerCase())).length;
    const suspicious = cases.filter(c => ['suspicious', 'spam'].includes((c.ai_classification || '').toLowerCase())).length;

    return { total, open, investigating, closed, phishing, malware, benign, suspicious };
  }, [cases]);

  // Filtered cases based on search query, classification, and status
  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      // 1. Search query match
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const subject = (c.subject || '').toLowerCase();
        const sender = (c.sender_email || '').toLowerCase();
        const sourceIp = (c.source_ip || '').toLowerCase();
        const caseId = String(c.id);
        const caseIdHash = `#${c.id}`;
        const classification = (c.ai_classification || '').toLowerCase();
        const status = (c.status || '').toLowerCase();

        const matchesQuery =
          subject.includes(query) ||
          sender.includes(query) ||
          sourceIp.includes(query) ||
          caseId === query ||
          caseIdHash === query ||
          classification.includes(query) ||
          status.includes(query);

        if (!matchesQuery) return false;
      }

      // 2. Classification filter match
      if (classificationFilter !== 'ALL') {
        const cClass = (c.ai_classification || '').toLowerCase();
        if (classificationFilter === 'BENIGN') {
          if (!['benign', 'safe', 'legitimate'].includes(cClass)) return false;
        } else if (classificationFilter === 'PHISHING') {
          if (cClass !== 'phishing') return false;
        } else if (classificationFilter === 'MALWARE') {
          if (cClass !== 'malware') return false;
        } else if (classificationFilter === 'SUSPICIOUS') {
          if (!['suspicious', 'spam'].includes(cClass)) return false;
        } else if (cClass !== classificationFilter.toLowerCase()) {
          return false;
        }
      }

      // 3. Status filter match
      if (statusFilter !== 'ALL') {
        if ((c.status || '').toLowerCase() !== statusFilter.toLowerCase()) return false;
      }

      return true;
    });
  }, [cases, searchQuery, classificationFilter, statusFilter]);

  const isFiltered = searchQuery.trim() !== '' || classificationFilter !== 'ALL' || statusFilter !== 'ALL';

  const handleResetFilters = () => {
    setSearchQuery('');
    setClassificationFilter('ALL');
    setStatusFilter('ALL');
  };

  if (loading) {
    return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>Loading...</div>;
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 style={{ fontSize: '2rem', marginBottom: '0.25rem' }}>Case Management</h1>
          <p className="text-muted">Review, investigate, and close active email threat incidents.</p>
        </div>
      </div>

      <div className="glass-panel p-6">
        {/* Controls Header */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
          {/* Top Search & Filter Bar */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', flex: 1, minWidth: '320px' }}>
              {/* Search Bar */}
              <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: '380px' }}>
                <Search size={18} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input 
                  type="text" 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search by subject, sender, IP, ID..." 
                  className="input-field" 
                  style={{ paddingLeft: '2.75rem', paddingRight: searchQuery ? '2.5rem' : '1rem', width: '100%', height: '42px' }}
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    style={{
                      position: 'absolute',
                      right: '0.75rem',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      cursor: 'pointer',
                      color: 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      padding: '0.25rem'
                    }}
                    title="Clear search"
                  >
                    <X size={16} />
                  </button>
                )}
              </div>

              {/* Classification Filter Dropdown */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <label htmlFor="classification-select" style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  Classification:
                </label>
                <select
                  id="classification-select"
                  value={classificationFilter}
                  onChange={(e) => setClassificationFilter(e.target.value)}
                  className="input-field"
                  style={{ height: '42px', padding: '0 1rem', cursor: 'pointer', minWidth: '160px' }}
                >
                  <option value="ALL">All Classifications ({counts.total})</option>
                  <option value="PHISHING">Phishing ({counts.phishing})</option>
                  <option value="MALWARE">Malware ({counts.malware})</option>
                  <option value="BENIGN">Safe / Benign ({counts.benign})</option>
                  <option value="SUSPICIOUS">Suspicious / Spam ({counts.suspicious})</option>
                </select>
              </div>

              {/* Status Filter Dropdown */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <label htmlFor="status-select" style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  Status:
                </label>
                <select
                  id="status-select"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="input-field"
                  style={{ height: '42px', padding: '0 1rem', cursor: 'pointer', minWidth: '140px' }}
                >
                  <option value="ALL">All Statuses ({counts.total})</option>
                  <option value="Open">Open ({counts.open})</option>
                  <option value="Investigating">Investigating ({counts.investigating})</option>
                  <option value="Closed">Closed ({counts.closed})</option>
                </select>
              </div>

              {/* Reset / Clear Filters button */}
              {isFiltered && (
                <button
                  onClick={handleResetFilters}
                  className="btn btn-secondary"
                  style={{ height: '42px', padding: '0 0.875rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
                  title="Reset all filters"
                >
                  <RotateCcw size={15} /> Reset
                </button>
              )}
            </div>

            {/* Results Counter */}
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.5rem', whiteSpace: 'nowrap' }}>
              <Filter size={15} />
              <span>Showing <strong>{filteredCases.length}</strong> of {cases.length} cases</span>
            </div>
          </div>

          {/* Quick Filter Pills Row */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center', paddingTop: '0.75rem', borderTop: '1px solid var(--panel-border)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginRight: '0.25rem' }}>
              Status:
            </span>
            
            {/* Status Pills */}
            <button
              type="button"
              onClick={() => setStatusFilter('ALL')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: statusFilter === 'ALL' ? 'var(--primary-color)' : 'var(--panel-border)',
                background: statusFilter === 'ALL' ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
                color: statusFilter === 'ALL' ? 'var(--primary-color)' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              All Status ({counts.total})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'Open' ? 'ALL' : 'Open')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: statusFilter === 'Open' ? 'var(--warning-color)' : 'var(--panel-border)',
                background: statusFilter === 'Open' ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
                color: statusFilter === 'Open' ? '#d97706' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              Open ({counts.open})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'Investigating' ? 'ALL' : 'Investigating')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: statusFilter === 'Investigating' ? 'var(--primary-color)' : 'var(--panel-border)',
                background: statusFilter === 'Investigating' ? 'rgba(37, 99, 235, 0.15)' : 'transparent',
                color: statusFilter === 'Investigating' ? 'var(--primary-color)' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              Investigating ({counts.investigating})
            </button>
            <button
              type="button"
              onClick={() => setStatusFilter(statusFilter === 'Closed' ? 'ALL' : 'Closed')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: statusFilter === 'Closed' ? '#64748b' : 'var(--panel-border)',
                background: statusFilter === 'Closed' ? 'rgba(100, 116, 139, 0.15)' : 'transparent',
                color: statusFilter === 'Closed' ? 'var(--text-main)' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              Closed ({counts.closed})
            </button>

            <div style={{ width: '1px', height: '18px', background: 'var(--panel-border)', margin: '0 0.5rem' }}></div>

            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginRight: '0.25rem' }}>
              Classification:
            </span>

            {/* Classification Pills */}
            <button
              type="button"
              onClick={() => setClassificationFilter('ALL')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: classificationFilter === 'ALL' ? 'var(--primary-color)' : 'var(--panel-border)',
                background: classificationFilter === 'ALL' ? 'rgba(37, 99, 235, 0.1)' : 'transparent',
                color: classificationFilter === 'ALL' ? 'var(--primary-color)' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              All Types
            </button>
            <button
              type="button"
              onClick={() => setClassificationFilter(classificationFilter === 'PHISHING' ? 'ALL' : 'PHISHING')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: classificationFilter === 'PHISHING' ? 'rgba(245, 158, 11, 0.5)' : 'var(--panel-border)',
                background: classificationFilter === 'PHISHING' ? 'rgba(245, 158, 11, 0.15)' : 'transparent',
                color: classificationFilter === 'PHISHING' ? '#d97706' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              Phishing ({counts.phishing})
            </button>
            <button
              type="button"
              onClick={() => setClassificationFilter(classificationFilter === 'MALWARE' ? 'ALL' : 'MALWARE')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: classificationFilter === 'MALWARE' ? 'rgba(239, 68, 68, 0.5)' : 'var(--panel-border)',
                background: classificationFilter === 'MALWARE' ? 'rgba(239, 68, 68, 0.15)' : 'transparent',
                color: classificationFilter === 'MALWARE' ? '#dc2626' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              Malware ({counts.malware})
            </button>
            <button
              type="button"
              onClick={() => setClassificationFilter(classificationFilter === 'BENIGN' ? 'ALL' : 'BENIGN')}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: 'var(--radius-full)',
                fontSize: '0.75rem',
                fontWeight: 500,
                border: '1px solid',
                borderColor: classificationFilter === 'BENIGN' ? 'rgba(16, 185, 129, 0.5)' : 'var(--panel-border)',
                background: classificationFilter === 'BENIGN' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
                color: classificationFilter === 'BENIGN' ? '#059669' : 'var(--text-muted)',
                cursor: 'pointer',
                transition: 'all var(--transition-fast)'
              }}
            >
              Safe ({counts.benign})
            </button>
            {counts.suspicious > 0 && (
              <button
                type="button"
                onClick={() => setClassificationFilter(classificationFilter === 'SUSPICIOUS' ? 'ALL' : 'SUSPICIOUS')}
                style={{
                  padding: '0.25rem 0.65rem',
                  borderRadius: 'var(--radius-full)',
                  fontSize: '0.75rem',
                  fontWeight: 500,
                  border: '1px solid',
                  borderColor: classificationFilter === 'SUSPICIOUS' ? 'rgba(139, 92, 246, 0.5)' : 'var(--panel-border)',
                  background: classificationFilter === 'SUSPICIOUS' ? 'rgba(139, 92, 246, 0.15)' : 'transparent',
                  color: classificationFilter === 'SUSPICIOUS' ? '#7c3aed' : 'var(--text-muted)',
                  cursor: 'pointer',
                  transition: 'all var(--transition-fast)'
                }}
              >
                Suspicious ({counts.suspicious})
              </button>
            )}
          </div>
        </div>

        {/* Cases Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.02)', borderBottom: '1px solid var(--panel-border)' }}>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem' }}>ID</th>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem' }}>Subject</th>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem' }}>Sender</th>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem' }}>Classification</th>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem' }}>Status</th>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem' }}>Created</th>
                <th style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontWeight: 500, fontSize: '0.875rem', width: '220px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredCases.map((c) => (
                <tr key={c.id} style={{ borderBottom: '1px solid var(--panel-border)', transition: 'background var(--transition-fast)' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,0,0,0.02)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '1rem 1.5rem', fontWeight: 500 }}>#{c.id}</td>
                  <td style={{ padding: '1rem 1.5rem', maxWidth: '220px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {c.subject || 'N/A'}
                  </td>
                  <td style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', maxWidth: '200px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {c.sender_email}
                  </td>
                  <td style={{ padding: '1rem 1.5rem' }}>
                    <span className={`badge ${getBadgeClass(c.ai_classification)}`}>
                      {formatClassification(c.ai_classification)}
                    </span>
                  </td>
                  <td style={{ padding: '1rem 1.5rem' }}>
                    <span style={{ 
                      display: 'inline-flex', alignItems: 'center', gap: '0.375rem',
                      fontSize: '0.875rem' 
                    }}>
                      <span style={{ 
                        width: '8px', height: '8px', borderRadius: '50%', 
                        background: c.status === 'Open' ? 'var(--warning-color)' : (c.status === 'Closed' ? 'var(--text-muted)' : 'var(--primary-color)') 
                      }}></span>
                      {c.status}
                    </span>
                  </td>
                  <td style={{ padding: '1rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ padding: '1rem 1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', whiteSpace: 'nowrap' }}>
                    <Link to={`/cases/${c.id}`} className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>View</Link>
                    {c.status !== 'Closed' ? (
                      <button className="btn btn-primary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', whiteSpace: 'nowrap' }} onClick={() => handleComplete(c.id)}>Complete</button>
                    ) : (
                      <button className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', whiteSpace: 'nowrap' }} onClick={() => handleOpenReportModal(c)}>Report</button>
                    )}
                    <button 
                      className="btn btn-danger" 
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }} 
                      onClick={(e) => handleDelete(c.id, e)}
                      title={`Delete Case #${c.id}`}
                    >
                      <Trash2 size={13} /> Delete
                    </button>
                  </td>
                </tr>
              ))}
              
              {filteredCases.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ padding: '3.5rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem', maxWidth: '360px', margin: '0 auto' }}>
                      <Filter size={32} style={{ opacity: 0.3 }} />
                      <div>
                        <p style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.25rem', fontSize: '1rem' }}>No matching cases found</p>
                        <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: 0 }}>
                          {isFiltered ? 'No cases match your active search and filter criteria. Try adjusting or resetting them.' : 'No cases recorded in the system yet.'}
                        </p>
                      </div>
                      {isFiltered && (
                        <button className="btn btn-secondary" onClick={handleResetFilters} style={{ fontSize: '0.8125rem', marginTop: '0.5rem' }}>
                          <RotateCcw size={14} /> Clear All Filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Download Format Chooser Modal */}
      <ReportDownloadModal
        isOpen={downloadModalOpen}
        onClose={() => setDownloadModalOpen(false)}
        caseData={selectedCaseForReport}
        isCompletedAction={isCompletedAction}
      />
    </div>
  );
}
