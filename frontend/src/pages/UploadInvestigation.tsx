import { useState } from 'react';
import axios from 'axios';
import { UploadCloud, File, AlertCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function UploadInvestigation() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const navigate = useNavigate();

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    
    setLoading(true);
    setError(null);
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
      const response = await axios.post(`${API_URL}/email/process`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      // Navigate to case details
      navigate(`/cases/${response.data.id}`);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'An error occurred during processing.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div className="mb-6">
        <h1 style={{ fontSize: '2rem', marginBottom: '0.25rem' }}>Start New Investigation</h1>
        <p className="text-muted">Upload a raw .eml file to initiate automated forensic analysis.</p>
      </div>

      <div className="glass-panel p-6">
        <div 
          className="upload-area"
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          style={{
            border: `2px dashed ${dragActive ? 'var(--primary-color)' : 'var(--panel-border)'}`,
            borderRadius: 'var(--radius-lg)',
            padding: '4rem 2rem',
            textAlign: 'center',
            backgroundColor: dragActive ? 'rgba(59, 130, 246, 0.05)' : 'transparent',
            transition: 'all var(--transition-fast)',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '1rem',
            marginBottom: '1.5rem'
          }}
        >
          <div style={{ 
            width: '80px', height: '80px', 
            borderRadius: '50%', 
            background: 'rgba(59, 130, 246, 0.1)', 
            display: 'flex', alignItems: 'center', justifyContent: 'center' 
          }}>
            <UploadCloud size={40} color="var(--primary-color)" />
          </div>
          
          <div>
            <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>Drag & drop raw email file here</h3>
            <p className="text-muted">Supports .eml or .txt formats containing raw SMTP headers and payload.</p>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', margin: '1rem 0' }}>
            <div style={{ height: '1px', background: 'var(--panel-border)', width: '100px' }}></div>
            <span className="text-muted" style={{ fontSize: '0.875rem' }}>OR</span>
            <div style={{ height: '1px', background: 'var(--panel-border)', width: '100px' }}></div>
          </div>
          
          <input 
            type="file" 
            id="file-upload" 
            style={{ display: 'none' }} 
            onChange={handleChange}
            accept=".eml,.txt"
          />
          <label htmlFor="file-upload" className="btn btn-secondary">
            Browse Files
          </label>
        </div>

        {file && (
          <div className="glass-card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <File size={24} className="text-primary-color" style={{ color: 'var(--primary-color)' }} />
              <div>
                <div style={{ fontWeight: 600 }}>{file.name}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{(file.size / 1024).toFixed(2)} KB</div>
              </div>
            </div>
            <button 
              className="btn btn-secondary" 
              style={{ padding: '0.25rem 0.5rem' }}
              onClick={() => setFile(null)}
            >
              Remove
            </button>
          </div>
        )}

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(239, 68, 68, 0.1)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(239, 68, 68, 0.2)', marginBottom: '1.5rem' }}>
            <AlertCircle size={20} color="var(--danger-color)" />
            <span style={{ color: 'var(--danger-color)' }}>{error}</span>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button 
            className="btn btn-primary" 
            onClick={handleUpload}
            disabled={!file || loading}
            style={{ padding: '0.75rem 2rem' }}
          >
            {loading ? (
              <>
                <span className="spinner" style={{ 
                  width: '16px', height: '16px', 
                  border: '2px solid rgba(255,255,255,0.3)', 
                  borderTop: '2px solid white', 
                  borderRadius: '50%', 
                  animation: 'spin 1s linear infinite' 
                }}></span>
                Analyzing Threat...
              </>
            ) : (
              'Start Investigation'
            )}
          </button>
        </div>
      </div>
      
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
