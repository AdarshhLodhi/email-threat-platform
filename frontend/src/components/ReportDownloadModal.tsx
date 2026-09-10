import { useState } from 'react';
import { X, FileText, FileCode, FileSpreadsheet, File, CheckCircle2 } from 'lucide-react';
import { exportJSON, exportCSV, exportPDF, downloadReportTxt } from '../utils/reportExport';

interface ReportDownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseData: any;
  isCompletedAction?: boolean;
  customReportText?: string;
}

export default function ReportDownloadModal({
  isOpen,
  onClose,
  caseData,
  isCompletedAction = false,
  customReportText
}: ReportDownloadModalProps) {
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);

  if (!isOpen || !caseData) return null;

  const handleDownload = async (format: 'pdf' | 'json' | 'csv' | 'txt') => {
    setDownloadingFormat(format);
    try {
      if (format === 'pdf') {
        await exportPDF(caseData);
      } else if (format === 'json') {
        await exportJSON(caseData);
      } else if (format === 'csv') {
        await exportCSV(caseData);
      } else if (format === 'txt') {
        await downloadReportTxt(caseData.id, customReportText);
      }
      onClose();
    } catch (error) {
      console.error(`Error generating ${format} report:`, error);
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div 
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(15, 23, 42, 0.65)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '1rem'
      }}
      onClick={onClose}
    >
      <div 
        className="glass-panel"
        style={{
          maxWidth: '560px',
          width: '100%',
          padding: '1.75rem',
          borderRadius: 'var(--radius-lg)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
          background: '#ffffff',
          border: '1px solid var(--panel-border)'
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.25rem' }}>
          <div>
            {isCompletedAction ? (
              <div style={{ 
                display: 'inline-flex', alignItems: 'center', gap: '0.4rem', 
                color: '#059669', background: 'rgba(16, 185, 129, 0.12)', 
                padding: '0.25rem 0.65rem', borderRadius: 'var(--radius-full)', 
                fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.5rem' 
              }}>
                <CheckCircle2 size={14} /> Case #{caseData.id} Marked as Closed
              </div>
            ) : (
              <div style={{ 
                display: 'inline-flex', alignItems: 'center', gap: '0.4rem', 
                color: 'var(--primary-color)', background: 'rgba(37, 99, 235, 0.1)', 
                padding: '0.25rem 0.65rem', borderRadius: 'var(--radius-full)', 
                fontSize: '0.75rem', fontWeight: 600, marginBottom: '0.5rem' 
              }}>
                Case #{caseData.id} • {caseData.status || 'Active'}
              </div>
            )}
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, color: 'var(--text-main)' }}>
              {isCompletedAction ? 'Download Forensic Report?' : 'Download Forensic Report'}
            </h2>
            <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              Which format do you want to download? Choose an option below:
            </p>
          </div>
          <button 
            type="button"
            onClick={onClose}
            style={{ 
              background: 'transparent', 
              border: 'none', 
              cursor: 'pointer', 
              padding: '0.25rem', 
              color: 'var(--text-muted)',
              borderRadius: 'var(--radius-md)'
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Options Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.875rem', marginBottom: '1.5rem' }}>
          {/* PDF Option */}
          <button
            type="button"
            onClick={() => handleDownload('pdf')}
            disabled={downloadingFormat !== null}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.875rem',
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--panel-border)',
              background: '#ffffff',
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'all var(--transition-fast)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = '#dc2626';
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 6px 14px rgba(220, 38, 38, 0.12)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--panel-border)';
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.05)';
            }}
          >
            <div style={{ 
              width: '42px', height: '42px', borderRadius: '8px', 
              background: 'rgba(239, 68, 68, 0.12)', color: '#dc2626',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
            }}>
              <FileText size={22} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.9375rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                PDF <span style={{ fontSize: '0.7rem', color: '#dc2626', fontWeight: 700, background: 'rgba(239,68,68,0.1)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>.PDF</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', lineHeight: 1.35 }}>
                Printable investigation report with headers & IOCs
              </div>
            </div>
          </button>

          {/* JSON Option */}
          <button
            type="button"
            onClick={() => handleDownload('json')}
            disabled={downloadingFormat !== null}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.875rem',
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--panel-border)',
              background: '#ffffff',
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'all var(--transition-fast)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = '#2563eb';
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 6px 14px rgba(37, 99, 235, 0.12)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--panel-border)';
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.05)';
            }}
          >
            <div style={{ 
              width: '42px', height: '42px', borderRadius: '8px', 
              background: 'rgba(37, 99, 235, 0.12)', color: '#2563eb',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
            }}>
              <FileCode size={22} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.9375rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                JSON <span style={{ fontSize: '0.7rem', color: '#2563eb', fontWeight: 700, background: 'rgba(37,99,235,0.1)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>.JSON</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', lineHeight: 1.35 }}>
                Full raw telemetry, headers & intelligence metadata
              </div>
            </div>
          </button>

          {/* CSV Option */}
          <button
            type="button"
            onClick={() => handleDownload('csv')}
            disabled={downloadingFormat !== null}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.875rem',
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--panel-border)',
              background: '#ffffff',
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'all var(--transition-fast)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = '#059669';
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 6px 14px rgba(5, 150, 105, 0.12)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--panel-border)';
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.05)';
            }}
          >
            <div style={{ 
              width: '42px', height: '42px', borderRadius: '8px', 
              background: 'rgba(16, 185, 129, 0.12)', color: '#059669',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
            }}>
              <FileSpreadsheet size={22} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.9375rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                CSV <span style={{ fontSize: '0.7rem', color: '#059669', fontWeight: 700, background: 'rgba(16,185,129,0.1)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>.CSV</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', lineHeight: 1.35 }}>
                Tabular format ideal for Excel, SIEM & analytics
              </div>
            </div>
          </button>

          {/* Text Option */}
          <button
            type="button"
            onClick={() => handleDownload('txt')}
            disabled={downloadingFormat !== null}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.875rem',
              padding: '1rem',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--panel-border)',
              background: '#ffffff',
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'all var(--transition-fast)',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = '#475569';
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = '0 6px 14px rgba(71, 85, 105, 0.12)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--panel-border)';
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.05)';
            }}
          >
            <div style={{ 
              width: '42px', height: '42px', borderRadius: '8px', 
              background: 'rgba(100, 116, 139, 0.12)', color: '#475569',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
            }}>
              <File size={22} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.9375rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                Plain Text <span style={{ fontSize: '0.7rem', color: '#475569', fontWeight: 700, background: 'rgba(100,116,139,0.1)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>.TXT</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', lineHeight: 1.35 }}>
                Standard structured text report log
              </div>
            </div>
          </button>
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--panel-border)', paddingTop: '1rem' }}>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
            {downloadingFormat ? `Generating ${downloadingFormat.toUpperCase()} report...` : 'Select your desired format to download.'}
          </div>
          <button 
            type="button"
            className="btn btn-secondary" 
            onClick={onClose}
            style={{ fontSize: '0.875rem' }}
          >
            {isCompletedAction ? "Don't Download / Skip" : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
}
