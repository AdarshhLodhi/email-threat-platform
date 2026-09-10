import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';
import { 
  ArrowLeft, ShieldCheck, ShieldAlert, AlertTriangle, Shield, Globe, MapPin, 
  FileText, Download, Activity, CheckCircle2
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import EmailHopVisualizer from '../components/EmailHopVisualizer';
import ReportDownloadModal from '../components/ReportDownloadModal';
import SteganographySection from '../components/SteganographySection';
import OriginAttributionModule from '../components/OriginAttributionModule';
import SenderAuthModule from '../components/SenderAuthModule';

// Fix Leaflet marker icon issue in React
import L from 'leaflet';
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';
let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconAnchor: [12, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const getClassificationMeta = (classification?: string) => {
  const c = (classification || '').toLowerCase();
  if (c === 'benign' || c === 'safe' || c === 'legitimate') {
    return {
      key: 'benign',
      label: classification || 'Safe / Benign',
      badgeClass: 'badge-benign',
      cardClass: 'classification-card-benign',
      color: 'var(--accent-color)',
      accentBg: 'rgba(16, 185, 129, 0.12)',
      borderColor: 'rgba(16, 185, 129, 0.4)',
      icon: ShieldCheck,
      description: 'Verified safe / legitimate communication. No deceptive vectors or malicious payloads detected.'
    };
  }
  if (c === 'phishing') {
    return {
      key: 'phishing',
      label: 'Phishing Threat',
      badgeClass: 'badge-phishing',
      cardClass: 'classification-card-phishing',
      color: 'var(--warning-color)',
      accentBg: 'rgba(245, 158, 11, 0.12)',
      borderColor: 'rgba(245, 158, 11, 0.4)',
      icon: ShieldAlert,
      description: 'Suspicious credential harvesting, deceptive links, or social engineering indicators identified.'
    };
  }
  if (c === 'malware' || c === 'threat' || c === 'toxic' || c === 'abusive' || c === 'hostile') {
    return {
      key: 'malware',
      label: classification || 'Threat Detected',
      badgeClass: 'badge-malware',
      cardClass: 'classification-card-malware',
      color: 'var(--danger-color)',
      accentBg: 'rgba(239, 68, 68, 0.12)',
      borderColor: 'rgba(239, 68, 68, 0.4)',
      icon: AlertTriangle,
      description: 'Hostile threat, abusive vector, or exploit distribution identified in communication.'
    };
  }
  return {
    key: 'unknown',
    label: classification || 'Unknown',
    badgeClass: 'badge-unknown',
    cardClass: '',
    color: 'var(--text-muted)',
    accentBg: 'rgba(100, 116, 139, 0.12)',
    borderColor: 'var(--panel-border)',
    icon: Shield,
    description: 'Threat status unverified or inconclusive analysis.'
  };
};

export default function CaseDetails() {
  const { id } = useParams<{ id: string }>();
  const [caseData, setCaseData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [reportText, setReportText] = useState('');
  const [downloadModalOpen, setDownloadModalOpen] = useState(false);
  const [abuseData, setAbuseData] = useState<any>(null);
  const [abuseLoading, setAbuseLoading] = useState(false);

  useEffect(() => {
    const fetchCase = async () => {
      try {
        const response = await axios.get(`${API_URL}/cases/${id}`);
        setCaseData(response.data);

        // Query live AbuseIPDB intelligence for source IP
        if (response.data?.source_ip) {
          setAbuseLoading(true);
          try {
            const abuseRes = await axios.get(`${API_URL}/intel/abuseipdb/${response.data.source_ip}`);
            setAbuseData(abuseRes.data);
          } catch (e) {
            console.error('Error fetching AbuseIPDB telemetry:', e);
          } finally {
            setAbuseLoading(false);
          }
        }
      } catch (error) {
        console.error('Error fetching case:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchCase();
  }, [id]);

  const generateReport = async () => {
    try {
      const response = await axios.get(`${API_URL}/reports/${id}/forensic`);
      setReportText(response.data);
      setActiveTab('report');
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  if (loading) return <div style={{ padding: '2rem' }}>Loading case details...</div>;
  if (!caseData) return <div style={{ padding: '2rem' }}>Case not found.</div>;

  const classificationMeta = getClassificationMeta(caseData.ai_classification);

  // Parse suspicious domains from database
  let suspiciousDomainsList: any[] = [];
  try {
    if (caseData.suspicious_domains) {
      suspiciousDomainsList = typeof caseData.suspicious_domains === 'string' 
        ? JSON.parse(caseData.suspicious_domains) 
        : caseData.suspicious_domains;
    }
  } catch {
    suspiciousDomainsList = [];
  }

  // Parse extracted URLs from database
  let extractedUrlsList: string[] = [];
  try {
    if (caseData.extracted_urls) {
      extractedUrlsList = typeof caseData.extracted_urls === 'string'
        ? JSON.parse(caseData.extracted_urls)
        : caseData.extracted_urls;
    }
  } catch {
    extractedUrlsList = [];
  }

  // Determine exact coordinates from live geolocation or fallback heuristics
  let geoCoords: [number, number] = [0, 0];
  if (caseData.latitude && caseData.longitude) {
    geoCoords = [caseData.latitude, caseData.longitude];
  } else if (caseData.geo_location && caseData.geo_location.includes("Mountain View")) {
    geoCoords = [37.4224, -122.0842];
  } else if (caseData.geo_location && caseData.geo_location.includes("Australia")) {
    geoCoords = [-27.4730, 153.0142];
  } else if (caseData.geo_location && caseData.geo_location.includes("Russia")) {
    geoCoords = [59.93, 30.31];
  } else if (caseData.geo_location && caseData.geo_location.includes("Netherlands")) {
    geoCoords = [52.36, 4.90];
  }

  // Check if any domain has threat detection
  const hasThreatCount = suspiciousDomainsList.filter(d => {
    return d.virustotal?.is_threat || d.reasons?.some((r: string) => r.toLowerCase().includes("threat") || r.toLowerCase().includes("malicious"));
  }).length;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.5rem' }}>
        <Link 
          to="/cases" 
          className="btn btn-secondary" 
          style={{ 
            width: '40px', 
            height: '40px', 
            padding: 0, 
            borderRadius: '50%', 
            display: 'inline-flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            flexShrink: 0,
            boxShadow: '0 1px 3px rgba(0,0,0,0.06)'
          }}
          title="Back to Case Management"
        >
          <ArrowLeft size={20} />
        </Link>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', flexWrap: 'wrap', minHeight: '40px' }}>
            <h1 style={{ fontSize: '1.875rem', fontWeight: 700, margin: 0, lineHeight: '40px', color: 'var(--text-main)' }}>
              Case #{caseData.id}
            </h1>
            <span 
              className={`badge ${classificationMeta.badgeClass}`} 
              style={{ 
                height: '26px', 
                display: 'inline-flex', 
                alignItems: 'center', 
                padding: '0 0.65rem', 
                fontSize: '0.75rem',
                lineHeight: 1
              }}
            >
              {caseData.ai_classification}
            </span>
            <span style={{ 
              height: '26px',
              display: 'inline-flex', 
              alignItems: 'center', 
              padding: '0 0.65rem', 
              borderRadius: 'var(--radius-full)', 
              fontSize: '0.75rem', 
              fontWeight: 600, 
              background: 'rgba(0,0,0,0.04)', 
              border: '1px solid var(--panel-border)',
              color: 'var(--text-muted)',
              lineHeight: 1
            }}>
              Status: {caseData.status}
            </span>
          </div>
          <p className="text-muted" style={{ margin: '0.25rem 0 0 0', fontSize: '0.9375rem' }}>
            {caseData.subject}
          </p>
        </div>
        
        {activeTab !== 'report' && (
          <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem', alignSelf: 'flex-start', marginTop: '2px' }}>
            <button className="btn btn-secondary" onClick={generateReport}>
              <FileText size={16} /> Generate Report
            </button>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: '2rem' }}>
        {/* Sidebar Nav */}
        <div style={{ width: '220px', display: 'flex', flexDirection: 'column', gap: '0.5rem', flexShrink: 0 }}>
          {['overview', 'authentication', 'infrastructure', 'origin_attribution', 'threat_intel', 'steganography', 'ai_analysis', 'raw_headers', 'report'].map(tab => {
            const label = tab === 'threat_intel' 
              ? 'Threat Intelligence' 
              : tab === 'steganography'
              ? 'Steganography'
              : tab === 'origin_attribution'
              ? 'Origin Attribution'
              : tab.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());

            return (
              <button 
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  textAlign: 'left', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)',
                  background: activeTab === tab ? 'var(--primary-color)' : 'transparent',
                  color: activeTab === tab ? 'white' : 'var(--text-muted)',
                  border: 'none', cursor: 'pointer', fontWeight: 500, fontFamily: 'inherit',
                  transition: 'all var(--transition-fast)'
                }}
                onMouseEnter={(e) => {
                  if (activeTab !== tab) e.currentTarget.style.background = 'rgba(0,0,0,0.05)';
                }}
                onMouseLeave={(e) => {
                  if (activeTab !== tab) e.currentTarget.style.background = 'transparent';
                }}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Content Area */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="glass-panel p-6">
              <h2 style={{ marginBottom: '1.5rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.75rem' }}>Executive Summary</h2>
              
              {/* Metadata Cards Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
                <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <span className="text-muted" style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                    Sender
                  </span>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem', wordBreak: 'break-all', color: 'var(--text-main)' }}>
                    {caseData.sender_email || 'N/A'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <span className="text-muted" style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                    Recipient
                  </span>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem', wordBreak: 'break-all', color: 'var(--text-main)' }}>
                    {caseData.recipient_email || 'N/A'}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <span className="text-muted" style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                    Date Logged
                  </span>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-main)' }}>
                    {new Date(caseData.created_at).toLocaleString()}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <span className="text-muted" style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.375rem' }}>
                    Threat Classification
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                    <span className={`badge ${classificationMeta.badgeClass}`} style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}>
                      {caseData.ai_classification}
                    </span>
                    <span style={{ fontWeight: 600, color: classificationMeta.color, fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>
                      {((caseData.confidence_score || 0) * 100).toFixed(1)}% confidence
                    </span>
                  </div>
                </div>
              </div>

              {/* Live Threat Integrations Quick Status */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
                <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid var(--primary-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.375rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                      Geolocation Intelligence
                    </span>
                    <span className="badge badge-benign" style={{ fontSize: '0.65rem' }}>Active</span>
                  </div>
                  <div style={{ fontWeight: 600, fontSize: '0.9375rem', marginBottom: '0.25rem' }}>{caseData.geo_location || 'Unknown Location'}</div>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>IP: {caseData.source_ip || 'N/A'} • {caseData.asn_info || 'Unknown ASN'}</div>
                </div>

                <div className="glass-card" style={{ padding: '1.25rem', borderLeft: `4px solid ${hasThreatCount > 0 ? 'var(--danger-color)' : 'var(--accent-color)'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.375rem' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
                      Threat Intelligence
                    </span>
                    <span className={`badge ${hasThreatCount > 0 ? 'badge-malware' : 'badge-benign'}`} style={{ fontSize: '0.65rem' }}>
                      {hasThreatCount > 0 ? `${hasThreatCount} Threats Detected` : 'Clean'}
                    </span>
                  </div>
                  <div style={{ fontWeight: 600, fontSize: '0.9375rem', marginBottom: '0.25rem' }}>
                    {hasThreatCount > 0 ? 'Malicious Indicators Identified' : 'No Malicious Domains Found'}
                  </div>
                  <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    {suspiciousDomainsList.length} extracted domains analyzed via multi-engine threat scanner
                  </div>
                </div>
              </div>
              
              <h3 className="text-muted" style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Message Body</h3>
              <div className="glass-card font-mono" style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', maxHeight: '300px', overflowY: 'auto', padding: '1.25rem' }}>
                {caseData.body_content}
              </div>
            </div>
          )}

          {/* TAB 2: AUTHENTICATION */}
          {activeTab === 'authentication' && (
            <SenderAuthModule caseData={caseData} caseId={id || caseData.id} />
          )}
          
          {/* TAB 3: INFRASTRUCTURE & GEOLOCATION */}
          {activeTab === 'infrastructure' && (
            <div className="glass-panel p-6">
              <div className="flex justify-between items-center mb-4 pb-2" style={{ borderBottom: '1px solid var(--panel-border)' }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.25rem' }}>IP Geolocation & Network Infrastructure</h2>
                  <p className="text-muted" style={{ margin: '0.25rem 0 0 0', fontSize: '0.8125rem' }}>
                    Live geospatial routing and network telemetry
                  </p>
                </div>
                <span className="badge badge-benign" style={{ fontSize: '0.75rem' }}>Live Geolocation</span>
              </div>
              
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="glass-card flex items-center gap-4">
                  <Globe size={32} color="var(--primary-color)" />
                  <div>
                    <h3 className="text-muted" style={{ fontSize: '0.8125rem' }}>Originating IP Address</h3>
                    <div style={{ fontSize: '1.25rem', fontWeight: 600 }}>{caseData.source_ip || 'Unknown IP'}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Verified against network routing tables</div>
                  </div>
                </div>

                <div className="glass-card flex items-center gap-4">
                  <MapPin size={32} color="var(--secondary-color)" />
                  <div>
                    <h3 className="text-muted" style={{ fontSize: '0.8125rem' }}>Physical Location & ASN</h3>
                    <div style={{ fontWeight: 600, fontSize: '1rem' }}>{caseData.geo_location || 'Unknown Location'}</div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>{caseData.asn_info || 'Unknown ISP / Network'}</div>
                  </div>
                </div>
              </div>

              {/* MTA Hop Graphical Representation */}
              <EmailHopVisualizer
                rawHeadersJson={caseData.raw_headers}
                sourceIp={caseData.source_ip}
                geoLocation={caseData.geo_location}
                asnInfo={caseData.asn_info}
                senderEmail={caseData.sender_email}
                recipientEmail={caseData.recipient_email}
              />

              {geoCoords[0] !== 0 && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>Global Geospatial Mapping</span>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      Lat: {geoCoords[0].toFixed(4)}, Lon: {geoCoords[1].toFixed(4)}
                    </span>
                  </div>
                  <div style={{ height: '350px', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--panel-border)' }}>
                    <MapContainer center={[geoCoords[0], geoCoords[1]]} zoom={5} style={{ height: '100%', width: '100%' }}>
                      <TileLayer
                        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                      />
                      <Marker position={[geoCoords[0], geoCoords[1]]}>
                        <Popup>
                          <strong>IP: {caseData.source_ip}</strong><br />
                          {caseData.geo_location}<br />
                          {caseData.asn_info}
                        </Popup>
                      </Marker>
                    </MapContainer>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3B: ORIGIN INTELLIGENCE & ATTRIBUTION */}
          {activeTab === 'origin_attribution' && (
            <OriginAttributionModule caseData={caseData} caseId={caseData.id} />
          )}

          {/* TAB 4: THREAT INTELLIGENCE */}
          {activeTab === 'threat_intel' && (
            <div className="glass-panel p-6">
              <div className="flex justify-between items-center mb-4 pb-2" style={{ borderBottom: '1px solid var(--panel-border)' }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Threat Intelligence Engine</h2>
                  <p className="text-muted" style={{ margin: '0.25rem 0 0 0', fontSize: '0.8125rem' }}>
                    Automated multi-engine security vendor analysis and domain reputation
                  </p>
                </div>
                <span className="badge badge-phishing" style={{ fontSize: '0.75rem' }}>Live Threat Intel</span>
              </div>

              {/* Status Banner */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div className="text-muted" style={{ fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Total IOCs Extracted</div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 'bold' }}>{suspiciousDomainsList.length || extractedUrlsList.length}</div>
                </div>

                <div className="glass-card" style={{ padding: '1rem', borderLeft: `4px solid ${hasThreatCount > 0 ? 'var(--danger-color)' : 'var(--accent-color)'}` }}>
                  <div className="text-muted" style={{ fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Malicious Detections</div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 'bold', color: hasThreatCount > 0 ? 'var(--danger-color)' : 'var(--accent-color)' }}>
                    {hasThreatCount}
                  </div>
                </div>

                <div className="glass-card" style={{ padding: '1rem' }}>
                  <div className="text-muted" style={{ fontSize: '0.8125rem', marginBottom: '0.25rem' }}>Reputation Verdict</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: hasThreatCount > 0 ? 'var(--danger-color)' : 'var(--accent-color)' }}>
                    {hasThreatCount > 0 ? 'MALICIOUS' : 'CLEAN'}
                  </div>
                </div>
              </div>

              {/* AbuseIPDB Origin IP Reputation Section */}
              <div className="glass-card mb-6" style={{ padding: '1.25rem', borderLeft: `4px solid ${abuseData?.is_threat ? 'var(--danger-color)' : 'var(--primary-color)'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <Activity size={22} color="var(--primary-color)" />
                    <div>
                      <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700 }}>
                        AbuseIPDB IP Reputation Telemetry
                      </h3>
                      <p className="text-muted" style={{ margin: 0, fontSize: '0.75rem' }}>
                        Source IP: <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{caseData.source_ip || 'N/A'}</span>
                      </p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span className="badge badge-primary" style={{ fontSize: '0.7rem' }}>AbuseIPDB v2 Live</span>
                    {abuseData?.verdict && (
                      <span className={`badge ${abuseData.is_threat ? 'badge-malware' : 'badge-benign'}`} style={{ fontSize: '0.7rem' }}>
                        {abuseData.verdict}
                      </span>
                    )}
                  </div>
                </div>

                {abuseLoading ? (
                  <div className="text-muted" style={{ fontSize: '0.85rem', padding: '0.75rem 0' }}>
                    Querying AbuseIPDB threat database...
                  </div>
                ) : abuseData ? (
                  <div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
                      <div style={{ background: 'rgba(0,0,0,0.03)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)' }}>
                        <div className="text-muted" style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>Abuse Confidence Score</div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                          <span style={{ fontSize: '1.35rem', fontWeight: 800, color: abuseData.abuse_confidence_score > 25 ? 'var(--danger-color)' : (abuseData.abuse_confidence_score > 0 ? 'var(--warning-color)' : 'var(--accent-color)') }}>
                            {abuseData.abuse_confidence_score}%
                          </span>
                          <div style={{ flex: 1, height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '3px', overflow: 'hidden' }}>
                            <div style={{ 
                              width: `${Math.max(4, abuseData.abuse_confidence_score)}%`, 
                              height: '100%', 
                              background: abuseData.abuse_confidence_score > 25 ? 'var(--danger-color)' : (abuseData.abuse_confidence_score > 0 ? 'var(--warning-color)' : 'var(--accent-color)') 
                            }} />
                          </div>
                        </div>
                      </div>

                      <div style={{ background: 'rgba(0,0,0,0.03)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)' }}>
                        <div className="text-muted" style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>Total Abuse Reports</div>
                        <div style={{ fontSize: '1.35rem', fontWeight: 800 }}>
                          {abuseData.total_reports} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-muted)' }}>({abuseData.distinct_users || 0} distinct users)</span>
                        </div>
                      </div>

                      <div style={{ background: 'rgba(0,0,0,0.03)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)' }}>
                        <div className="text-muted" style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>Infrastructure Usage</div>
                        <div style={{ fontSize: '0.9rem', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={abuseData.usage_type}>
                          {abuseData.usage_type}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ISP: {abuseData.isp}</div>
                      </div>

                      <div style={{ background: 'rgba(0,0,0,0.03)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)' }}>
                        <div className="text-muted" style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>Tor & Whitelist Status</div>
                        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                          <span className={`badge ${abuseData.is_tor ? 'badge-malware' : 'badge-benign'}`} style={{ fontSize: '0.7rem' }}>
                            {abuseData.is_tor ? 'Tor Exit: Yes' : 'Tor Exit: No'}
                          </span>
                          <span className="badge" style={{ fontSize: '0.7rem', background: abuseData.is_whitelisted ? 'rgba(16, 185, 129, 0.15)' : 'rgba(0,0,0,0.05)' }}>
                            {abuseData.is_whitelisted ? 'Whitelisted' : 'Standard'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {abuseData.reports && abuseData.reports.length > 0 ? (
                      <div style={{ marginTop: '0.75rem' }}>
                        <div style={{ fontSize: '0.8rem', fontWeight: 700, marginBottom: '0.5rem', color: 'var(--danger-color)' }}>
                          Recent Incident Reports ({abuseData.reports.length} logged):
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '180px', overflowY: 'auto' }}>
                          {abuseData.reports.map((rep: any, rIdx: number) => (
                            <div key={rIdx} style={{ fontSize: '0.78rem', padding: '0.5rem 0.75rem', background: 'rgba(239, 68, 68, 0.04)', borderRadius: 'var(--radius-sm)', borderLeft: '3px solid var(--danger-color)' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                                <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                                  {rep.categories?.map((cat: string, cIdx: number) => (
                                    <span key={cIdx} style={{ fontSize: '0.68rem', padding: '1px 5px', borderRadius: '3px', background: 'rgba(239, 68, 68, 0.15)', color: 'var(--danger-color)', fontWeight: 600 }}>
                                      {cat}
                                    </span>
                                  ))}
                                </div>
                                <span className="text-muted" style={{ fontSize: '0.7rem' }}>{rep.reported_at ? new Date(rep.reported_at).toLocaleDateString() : ''}</span>
                              </div>
                              <div style={{ color: 'var(--text-main)' }}>{rep.comment}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.8125rem', color: 'var(--accent-color)', display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.5rem' }}>
                        <CheckCircle2 size={16} color="var(--accent-color)" />
                        <span>Clean threat profile — No incident reports filed against this IP in the past 90 days.</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-muted" style={{ fontSize: '0.8125rem' }}>
                    No source IP available for AbuseIPDB intelligence query.
                  </div>
                )}
              </div>

              {/* Domain Breakdown */}
              <h3 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>Extracted Domains & Threat Indicators</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {suspiciousDomainsList.map((item, idx) => {
                  const vt = item.virustotal;
                  const isThreat = vt?.is_threat || item.reasons?.some((r: string) => r.toLowerCase().includes("threat") || r.toLowerCase().includes("malicious"));
                  return (
                    <div key={idx} className="glass-card" style={{ padding: '1.25rem', borderLeft: `4px solid ${isThreat ? 'var(--danger-color)' : 'var(--accent-color)'}` }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontWeight: 700, fontSize: '1rem' }}>{item.domain}</span>
                        </div>
                        <span className={`badge ${isThreat ? 'badge-malware' : 'badge-benign'}`}>
                          {isThreat ? 'Threat Flagged' : 'Clean'}
                        </span>
                      </div>

                      {/* Reasons */}
                      {item.reasons && item.reasons.length > 0 && (
                        <div style={{ marginBottom: '0.5rem' }}>
                          {item.reasons.map((r: string, rIdx: number) => {
                            const cleanReason = r
                              .replace(/VirusTotal\s*(threat intel detected:)?/gi, 'Threat intelligence flagged:')
                              .replace(/VirusTotal/gi, 'Threat Intelligence');
                            return (
                              <div key={rIdx} style={{ fontSize: '0.8125rem', color: isThreat ? 'var(--danger-color)' : 'var(--text-main)', marginBottom: '0.2rem' }}>
                                • {cleanReason}
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {/* Engine Vendor Details */}
                      {vt && vt.status === 'scanned' && (
                        <div style={{ 
                          display: 'flex', gap: '1.5rem', marginTop: '0.75rem', paddingTop: '0.75rem', 
                          borderTop: '1px solid var(--panel-border)', fontSize: '0.8125rem', color: 'var(--text-muted)', flexWrap: 'wrap' 
                        }}>
                          <div><strong>Malicious Engines:</strong> <span style={{ color: vt.malicious > 0 ? 'var(--danger-color)' : 'inherit' }}>{vt.malicious}</span></div>
                          <div><strong>Suspicious:</strong> <span style={{ color: vt.suspicious > 0 ? 'var(--warning-color)' : 'inherit' }}>{vt.suspicious}</span></div>
                          <div><strong>Harmless:</strong> {vt.harmless}</div>
                          <div><strong>Reputation Score:</strong> {vt.reputation}</div>
                        </div>
                      )}
                    </div>
                  );
                })}

                {suspiciousDomainsList.length === 0 && (
                  <div className="glass-card" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No suspicious domains identified. Threat intelligence engines found no active malicious indicators.
                  </div>
                )}
              </div>

              {/* Extracted URLs */}
              {extractedUrlsList.length > 0 && (
                <div style={{ marginTop: '1.5rem' }}>
                  <h3 style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>Extracted Hyperlinks ({extractedUrlsList.length})</h3>
                  <div className="glass-card font-mono" style={{ fontSize: '0.75rem', maxHeight: '180px', overflowY: 'auto' }}>
                    {extractedUrlsList.map((url, uIdx) => (
                      <div key={uIdx} style={{ padding: '0.25rem 0', wordBreak: 'break-all', borderBottom: '1px solid rgba(0,0,0,0.04)' }}>
                        {url}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 5: STEGANOGRAPHY & ATTACHMENTS */}
          {activeTab === 'steganography' && (
            <SteganographySection caseData={caseData} caseId={caseData.id} />
          )}

          {/* TAB 6: AI ANALYSIS */}
          {activeTab === 'ai_analysis' && (() => {
            const ClassificationIcon = classificationMeta.icon;
            const confidencePercent = ((caseData.confidence_score || 0) * 100).toFixed(1);
            return (
              <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-4 pb-3" style={{ borderBottom: '1px solid var(--panel-border)' }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: '1.5rem' }}>AI Classification Engine</h2>
                    <p className="text-muted" style={{ margin: '0.25rem 0 0 0', fontSize: '0.875rem' }}>
                      Multi-modal classification combining machine learning NLP and threat intelligence telemetry
                    </p>
                  </div>
                  <span className={`badge ${classificationMeta.badgeClass}`} style={{ fontSize: '0.875rem', padding: '0.35rem 0.85rem' }}>
                    {caseData.ai_classification}
                  </span>
                </div>

                <div className={`classification-card ${classificationMeta.cardClass} mb-6`}>
                  <div className="flex items-center justify-between gap-4" style={{ flexWrap: 'wrap' }}>
                    <div className="flex items-center gap-4" style={{ minWidth: '280px', flex: 1 }}>
                      <div style={{
                        width: '56px',
                        height: '56px',
                        borderRadius: 'var(--radius-md)',
                        background: classificationMeta.accentBg,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        border: `1px solid ${classificationMeta.borderColor}`,
                        flexShrink: 0
                      }}>
                        <ClassificationIcon size={32} color={classificationMeta.color} />
                      </div>
                      <div>
                        <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 600 }}>
                          Classification Verdict
                        </div>
                        <div style={{ fontSize: '1.75rem', fontWeight: 700, color: classificationMeta.color, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                          <span>{caseData.ai_classification}</span>
                          <span className={`badge ${classificationMeta.badgeClass}`}>
                            {classificationMeta.key === 'benign' ? 'Clean / Safe' : 'Threat Detected'}
                          </span>
                        </div>
                        <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                          {classificationMeta.description}
                        </p>
                      </div>
                    </div>

                    <div style={{ textAlign: 'right', minWidth: '150px' }}>
                      <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 600 }}>
                        Model Confidence
                      </div>
                      <div style={{ fontSize: '2rem', fontWeight: 800, color: classificationMeta.color }}>
                        {confidencePercent}%
                      </div>
                    </div>
                  </div>

                  <div className="confidence-progress-bg">
                    <div 
                      className="confidence-progress-fill" 
                      style={{ 
                        width: `${confidencePercent}%`,
                        backgroundColor: classificationMeta.color 
                      }}
                    />
                  </div>
                </div>
              </div>
            );
          })()}

          {/* TAB 6: RAW HEADERS */}
          {activeTab === 'raw_headers' && (
            <div className="glass-panel p-6">
              <h2 style={{ marginBottom: '1.5rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.75rem' }}>Raw SMTP Headers</h2>
              <pre className="font-mono" style={{ whiteSpace: 'pre-wrap', fontSize: '0.75rem', color: 'var(--text-main)', background: 'rgba(0,0,0,0.03)', padding: '1rem', borderRadius: 'var(--radius-md)', overflowX: 'auto', maxHeight: '500px', overflowY: 'auto' }}>
                {caseData.raw_headers ? JSON.stringify(JSON.parse(caseData.raw_headers), null, 2) : 'No headers available.'}
              </pre>
            </div>
          )}

          {/* TAB 7: REPORT */}
          {activeTab === 'report' && (
            <div className="glass-panel p-6">
              <div className="mb-4 pb-4" style={{ borderBottom: '1px solid var(--panel-border)' }}>
                <h2 style={{ margin: 0 }}>Generated Forensic Report</h2>
                <p className="text-muted" style={{ margin: '0.25rem 0 0 0', fontSize: '0.8125rem' }}>
                  Comprehensive report integrating geolocation and threat intelligence findings
                </p>
              </div>
              {reportText ? (
                <div>
                  <pre className="font-mono" style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', color: 'var(--text-main)', background: 'rgba(0,0,0,0.03)', padding: '1rem', borderRadius: 'var(--radius-md)', overflowX: 'auto', marginBottom: '1rem' }}>
                    {reportText}
                  </pre>
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button 
                      type="button" 
                      className="btn btn-primary" 
                      onClick={() => setDownloadModalOpen(true)}
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.875rem' }}
                    >
                      <Download size={16} /> Download Options
                    </button>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '3rem 2rem', color: 'var(--text-muted)' }}>
                  <p style={{ marginBottom: '1rem', fontSize: '1rem', fontWeight: 500, color: 'var(--text-main)' }}>
                    No forensic report generated in view yet.
                  </p>
                  <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
                    <button className="btn btn-primary" onClick={generateReport}>
                      <FileText size={16} /> Generate Report
                    </button>
                    <button className="btn btn-secondary" onClick={() => setDownloadModalOpen(true)}>
                      <Download size={16} /> Download Options
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Report Download Options Modal */}
      <ReportDownloadModal
        isOpen={downloadModalOpen}
        onClose={() => setDownloadModalOpen(false)}
        caseData={caseData}
        customReportText={reportText}
      />
    </div>
  );
}
