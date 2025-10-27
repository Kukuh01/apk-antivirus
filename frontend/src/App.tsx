import React, { useState, useEffect } from 'react';
import { Shield, Search, Database, Plus, Trash2, AlertTriangle, CheckCircle, Clock, FileText, Folder, X } from 'lucide-react';
import './App.css';

const API_URL = 'http://localhost:8080/api';

const AntivirusApp = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState({ total_signatures: 0, total_scans: 0, threats_detected: 0 });
  const [signatures, setSignatures] = useState([]);
  const [scanResults, setScanResults] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [selectedFile, setSelectedFile] = useState('');
  const [selectedFolder, setSelectedFolder] = useState('');
  
  // Form states
  const [newSignature, setNewSignature] = useState({
    name: '',
    md5_hash: '',
    binary_pattern: '',
    severity: 'Medium',
    description: ''
  });
  
  const [newSample, setNewSample] = useState({
    file_path: '',
    virus_name: '',
    severity: 'Medium',
    description: ''
  });

  useEffect(() => {
    fetchStats();
    fetchSignatures();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch(`${API_URL}/stats`);
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  const fetchSignatures = async () => {
    try {
      const response = await fetch(`${API_URL}/signatures`);
      const data = await response.json();
      setSignatures(data || []);
    } catch (error) {
      console.error('Failed to fetch signatures:', error);
    }
  };

  const scanFile = async () => {
    if (!selectedFile) {
      alert('Please enter a file path');
      return;
    }

    setScanning(true);
    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: selectedFile })
      });
      
      const result = await response.json();
      setScanResults([result, ...scanResults]);
      fetchStats();
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed: ' + error.message);
    } finally {
      setScanning(false);
    }
  };

  const scanFolder = async () => {
    if (!selectedFolder) {
      alert('Please enter a folder path');
      return;
    }

    setScanning(true);
    try {
      const response = await fetch(`${API_URL}/scan-folder`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder_path: selectedFolder })
      });
      
      const results = await response.json();
      setScanResults([...results, ...scanResults]);
      fetchStats();
    } catch (error) {
      console.error('Folder scan failed:', error);
      alert('Folder scan failed: ' + error.message);
    } finally {
      setScanning(false);
    }
  };

  const addSignature = async (e) => {
    e.preventDefault();
    
    if (!newSignature.name || (!newSignature.md5_hash && !newSignature.binary_pattern)) {
      alert('Please fill in required fields');
      return;
    }

    try {
      await fetch(`${API_URL}/signatures`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newSignature)
      });
      
      fetchSignatures();
      fetchStats();
      setNewSignature({ name: '', md5_hash: '', binary_pattern: '', severity: 'Medium', description: '' });
      alert('Signature added successfully!');
    } catch (error) {
      console.error('Failed to add signature:', error);
      alert('Failed to add signature');
    }
  };

  // const addSample = async (e) => {
  //   e.preventDefault();
    
  //   if (!newSample.file_path || !newSample.virus_name) {
  //     alert('Please fill in required fields');
  //     return;
  //   }

  //   try {
  //     const response = await fetch(`${API_URL}/add-sample`, {
  //       method: 'POST',
  //       headers: { 'Content-Type': 'application/json' },
  //       body: JSON.stringify(newSample)
  //     });
      
  //     const data = await response.json();
  //     fetchSignatures();
  //     fetchStats();
  //     setNewSample({ file_path: '', virus_name: '', severity: 'Medium', description: '' });
  //     alert(`Sample added successfully! MD5: ${data.md5}`);
  //   } catch (error) {
  //     console.error('Failed to add sample:', error);
  //     alert('Failed to add sample');
  //   }
  // };

// bagian dalam AntivirusApp atau komponen AddSample
const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  const f = e.target.files?.[0];
  if (f) setFileToUpload(f);
};

const [fileToUpload, setFileToUpload] = useState<File | null>(null);

const addSample = async (e: React.FormEvent) => {
  e.preventDefault();
  if (!fileToUpload) return alert('Pilih file sample terlebih dahulu');
  if (!newSample.virus_name) return alert('Isi nama virus');

  try {
    const form = new FormData();
    form.append('file', fileToUpload);
    form.append('name', newSample.virus_name);
    form.append('severity', newSample.severity);
    form.append('description', newSample.description || '');

    const res = await fetch(`${API_URL}/add-sample`, {
      method: 'POST',
      body: form,
    });

    if (!res.ok) {
      const t = await res.text();
      throw new Error(t || `HTTP ${res.status}`);
    }

    const data = await res.json(); // { md5: '', binary_pattern: '' }
    // update UI state, fetchSignatures, dsb.
    await fetchSignatures();
    await fetchStats();
    setNewSample({ file_path: '', virus_name: '', severity: 'Medium', description: '' });
    setFileToUpload(null);
    alert(`Sample added. MD5: ${data.md5}`);
  } catch (err: any) {
    console.error(err);
    alert('Failed to upload sample: ' + (err.message ?? err));
  }
};

  const deleteSignature = async (id) => {
    if (!confirm('Are you sure you want to delete this signature?')) return;

    try {
      await fetch(`${API_URL}/signatures/${id}`, { method: 'DELETE' });
      fetchSignatures();
      fetchStats();
    } catch (error) {
      console.error('Failed to delete signature:', error);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      Low: 'bg-blue-100 text-blue-800',
      Medium: 'bg-yellow-100 text-yellow-800',
      High: 'bg-orange-100 text-orange-800',
      Critical: 'bg-red-100 text-red-800'
    };
    return colors[severity] || colors.Medium;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-blue-600 shadow-lg">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-10 h-10 text-white" />
              <div>
                <h1 className="text-2xl font-bold text-white">SecureShield Antivirus</h1>
                <p className="text-purple-100 text-sm">Real-time Protection System</p>
              </div>
            </div>
            <div className="flex items-center space-x-2 bg-white/10 px-4 py-2 rounded-lg backdrop-blur-sm">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-white text-sm font-medium">System Protected</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="bg-slate-800 border-b border-slate-700 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6">
          <nav className="flex space-x-1">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: Shield },
              { id: 'scanner', label: 'Scanner', icon: Search },
              { id: 'database', label: 'Virus Database', icon: Database },
              { id: 'update', label: 'Add Sample', icon: Plus }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-6 py-3 font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-purple-600 text-white border-b-2 border-purple-400'
                    : 'text-slate-300 hover:bg-slate-700 hover:text-white'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-bold text-white mb-6">Security Dashboard</h2>
            
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl shadow-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-blue-100 text-sm font-medium">Total Signatures</p>
                    <p className="text-4xl font-bold text-white mt-2">{stats.total_signatures}</p>
                  </div>
                  <Database className="w-12 h-12 text-blue-200" />
                </div>
              </div>

              <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-xl shadow-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-green-100 text-sm font-medium">Total Scans</p>
                    <p className="text-4xl font-bold text-white mt-2">{stats.total_scans}</p>
                  </div>
                  <Search className="w-12 h-12 text-green-200" />
                </div>
              </div>

              <div className="bg-gradient-to-br from-red-500 to-red-600 rounded-xl shadow-lg p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-red-100 text-sm font-medium">Threats Detected</p>
                    <p className="text-4xl font-bold text-white mt-2">{stats.threats_detected}</p>
                  </div>
                  <AlertTriangle className="w-12 h-12 text-red-200" />
                </div>
              </div>
            </div>

            {/* Recent Scans */}
            <div className="bg-slate-800 rounded-xl shadow-lg p-6">
              <h3 className="text-xl font-bold text-white mb-4">Recent Scan Results</h3>
              <div className="space-y-3">
                {scanResults.length === 0 ? (
                  <p className="text-slate-400 text-center py-8">No scans performed yet</p>
                ) : (
                  scanResults.slice(0, 5).map((result, idx) => (
                    <div key={idx} className="bg-slate-700 rounded-lg p-4 flex items-center justify-between">
                      <div className="flex items-center space-x-4 flex-1">
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                          result.is_infected ? 'bg-red-500' : 'bg-green-500'
                        }`}>
                          {result.is_infected ? <X className="w-6 h-6 text-white" /> : <CheckCircle className="w-6 h-6 text-white" />}
                        </div>
                        <div className="flex-1">
                          <p className="text-white font-medium truncate">{result.file_path}</p>
                          <p className="text-slate-400 text-sm">
                            {result.is_infected ? `🦠 ${result.virus_name} (${result.detection_type})` : '✓ Clean'}
                          </p>
                        </div>
                      </div>
                      <div className="text-slate-400 text-sm">
                        {new Date(result.scan_time).toLocaleTimeString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* Scanner Tab */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-bold text-white mb-6">Malware Scanner</h2>
            
            {/* File Scanner */}
            <div className="bg-slate-800 rounded-xl shadow-lg p-6">
              <div className="flex items-center space-x-3 mb-4">
                <FileText className="w-6 h-6 text-purple-400" />
                <h3 className="text-xl font-bold text-white">Scan Single File</h3>
              </div>
              <div className="flex space-x-3">
                <input
                  type="text"
                  value={selectedFile}
                  onChange={(e) => setSelectedFile(e.target.value)}
                  placeholder="Enter file path (e.g., C:\path\to\file.exe)"
                  className="flex-1 bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
                <button
                  onClick={scanFile}
                  disabled={scanning}
                  className="bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center space-x-2"
                >
                  <Search className="w-5 h-5" />
                  <span>{scanning ? 'Scanning...' : 'Scan File'}</span>
                </button>
              </div>
            </div>

            {/* Folder Scanner */}
            <div className="bg-slate-800 rounded-xl shadow-lg p-6">
              <div className="flex items-center space-x-3 mb-4">
                <Folder className="w-6 h-6 text-blue-400" />
                <h3 className="text-xl font-bold text-white">Scan Folder</h3>
              </div>
              <div className="flex space-x-3">
                <input
                  type="text"
                  value={selectedFolder}
                  onChange={(e) => setSelectedFolder(e.target.value)}
                  placeholder="Enter folder path (e.g., C:\Users\Downloads)"
                  className="flex-1 bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  onClick={scanFolder}
                  disabled={scanning}
                  className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white px-6 py-3 rounded-lg font-medium transition-colors flex items-center space-x-2"
                >
                  <Search className="w-5 h-5" />
                  <span>{scanning ? 'Scanning...' : 'Scan Folder'}</span>
                </button>
              </div>
            </div>

            {/* Scan Results */}
            {scanResults.length > 0 && (
              <div className="bg-slate-800 rounded-xl shadow-lg p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-bold text-white">Scan Results</h3>
                  <button
                    onClick={() => setScanResults([])}
                    className="text-slate-400 hover:text-white text-sm"
                  >
                    Clear All
                  </button>
                </div>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {scanResults.map((result, idx) => (
                    <div key={idx} className={`rounded-lg p-4 ${
                      result.is_infected ? 'bg-red-900/30 border border-red-500' : 'bg-green-900/30 border border-green-500'
                    }`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            {result.is_infected ? (
                              <AlertTriangle className="w-5 h-5 text-red-400" />
                            ) : (
                              <CheckCircle className="w-5 h-5 text-green-400" />
                            )}
                            <span className={`font-bold ${result.is_infected ? 'text-red-400' : 'text-green-400'}`}>
                              {result.is_infected ? 'THREAT DETECTED' : 'CLEAN'}
                            </span>
                          </div>
                          <p className="text-white mt-2 font-mono text-sm break-all">{result.file_path}</p>
                          {result.is_infected && (
                            <div className="mt-2 space-y-1">
                              <p className="text-red-300 text-sm">Virus: {result.virus_name}</p>
                              <p className="text-red-300 text-sm">Detection: {result.detection_type}</p>
                            </div>
                          )}
                          <div className="flex items-center space-x-4 mt-2 text-slate-400 text-xs">
                            <span>Size: {(result.file_size / 1024).toFixed(2)} KB</span>
                            <span>Time: {new Date(result.scan_time).toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Virus Database Tab */}
        {activeTab === 'database' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-3xl font-bold text-white">Virus Signature Database</h2>
              <div className="text-slate-300">
                Total: <span className="text-white font-bold">{signatures.length}</span> signatures
              </div>
            </div>

            {/* Add Manual Signature Form */}
            <div className="bg-slate-800 rounded-xl shadow-lg p-6">
              <h3 className="text-xl font-bold text-white mb-4">Add Manual Signature</h3>
              <form onSubmit={addSignature} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <input
                    type="text"
                    placeholder="Virus Name *"
                    value={newSignature.name}
                    onChange={(e) => setNewSignature({...newSignature, name: e.target.value})}
                    className="bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
                    required
                  />
                  <select
                    value={newSignature.severity}
                    onChange={(e) => setNewSignature({...newSignature, severity: e.target.value})}
                    className="bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
                
                <input
                  type="text"
                  placeholder="MD5 Hash (32 characters)"
                  value={newSignature.md5_hash}
                  onChange={(e) => setNewSignature({...newSignature, md5_hash: e.target.value})}
                  className="w-full bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono"
                  maxLength={32}
                />
                
                <input
                  type="text"
                  placeholder="Binary Pattern (Hex, e.g., 4D5A90000300)"
                  value={newSignature.binary_pattern}
                  onChange={(e) => setNewSignature({...newSignature, binary_pattern: e.target.value})}
                  className="w-full bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono"
                />
                
                <textarea
                  placeholder="Description"
                  value={newSignature.description}
                  onChange={(e) => setNewSignature({...newSignature, description: e.target.value})}
                  className="w-full bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 h-24 resize-none"
                />
                
                <button
                  type="submit"
                  className="w-full bg-purple-600 hover:bg-purple-700 text-white py-3 rounded-lg font-medium transition-colors"
                >
                  Add Signature
                </button>
              </form>
            </div>

            {/* Signatures Table */}
            <div className="bg-slate-800 rounded-xl shadow-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-700">
                    <tr>
                      <th className="px-6 py-4 text-left text-white font-semibold">Name</th>
                      <th className="px-6 py-4 text-left text-white font-semibold">MD5 Hash</th>
                      <th className="px-6 py-4 text-left text-white font-semibold">Binary Pattern</th>
                      <th className="px-6 py-4 text-left text-white font-semibold">Severity</th>
                      <th className="px-6 py-4 text-left text-white font-semibold">Date Added</th>
                      <th className="px-6 py-4 text-center text-white font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {signatures.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="px-6 py-8 text-center text-slate-400">
                          No virus signatures found. Add your first signature above.
                        </td>
                      </tr>
                    ) : (
                      signatures.map((sig) => (
                        <tr key={sig.id} className="hover:bg-slate-700 transition-colors">
                          <td className="px-6 py-4">
                            <div>
                              <p className="text-white font-medium">{sig.name}</p>
                              {sig.description && (
                                <p className="text-slate-400 text-sm mt-1">{sig.description}</p>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <code className="text-purple-400 text-xs font-mono">
                              {sig.md5_hash || '-'}
                            </code>
                          </td>
                          <td className="px-6 py-4">
                            <code className="text-blue-400 text-xs font-mono">
                              {sig.binary_pattern ? sig.binary_pattern.substring(0, 20) + '...' : '-'}
                            </code>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`inline-flex px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(sig.severity)}`}>
                              {sig.severity}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-slate-300 text-sm">
                            {new Date(sig.created_at).toLocaleDateString()}
                          </td>
                          <td className="px-6 py-4 text-center">
                            <button
                              onClick={() => deleteSignature(sig.id)}
                              className="text-red-400 hover:text-red-300 transition-colors"
                            >
                              <Trash2 className="w-5 h-5" />
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

        {/* Add Sample Tab */}
        {activeTab === 'update' && (
          <div className="space-y-6">
            <h2 className="text-3xl font-bold text-white mb-6">Add Virus Sample</h2>
            
            <div className="bg-slate-800 rounded-xl shadow-lg p-6">
              <div className="bg-yellow-900/30 border border-yellow-600 rounded-lg p-4 mb-6">
                <div className="flex items-start space-x-3">
                  <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <h4 className="text-yellow-400 font-bold mb-1">Warning</h4>
                    <p className="text-yellow-200 text-sm">
                      Only upload known malware samples in a secure environment. The system will automatically calculate the MD5 hash and add it to the database.
                    </p>
                  </div>
                </div>
              </div>

              <form onSubmit={addSample} className="space-y-4">
                <div>
                  <label className="block text-slate-300 mb-2 font-medium">Sample File *</label>
                  <input
                    type="file"
                    accept="*/*"
                    onChange={handleFileChange}
                    className="w-full bg-slate-700 text-white px-4 py-2 rounded-lg"
                  />
                  <p className="text-slate-400 text-sm mt-2">Pilih file sample (malware) — file akan di-hash & disimpan hanya hash/pattern di DB.</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-slate-300 mb-2 font-medium">Virus Name *</label>
                    <input
                      type="text"
                      placeholder="e.g., Trojan.Win32.Generic"
                      value={newSample.virus_name}
                      onChange={(e) => setNewSample({...newSample, virus_name: e.target.value})}
                      className="w-full bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-slate-300 mb-2 font-medium">Severity *</label>
                    <select
                      value={newSample.severity}
                      onChange={(e) => setNewSample({...newSample, severity: e.target.value})}
                      className="w-full bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500"
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-slate-300 mb-2 font-medium">Description</label>
                  <textarea
                    placeholder="Describe the malware behavior, origin, or characteristics..."
                    value={newSample.description}
                    onChange={(e) => setNewSample({...newSample, description: e.target.value})}
                    className="w-full bg-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 h-32 resize-none"
                  />
                </div>

                <button
                  type="submit"
                  className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium transition-colors flex items-center justify-center space-x-2"
                >
                  <Plus className="w-5 h-5" />
                  <span>Add Sample to Database</span>
                </button>
              </form>
            </div>

            {/* Info Box */}
            <div className="bg-blue-900/30 border border-blue-600 rounded-lg p-6">
              <h3 className="text-blue-400 font-bold mb-3 flex items-center space-x-2">
                <Clock className="w-5 h-5" />
                <span>How It Works</span>
              </h3>
              <ul className="text-blue-200 space-y-2 text-sm">
                <li className="flex items-start space-x-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>The system reads the file and calculates its MD5 hash automatically</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>The hash is stored in the database for future file comparisons</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>Any file with a matching MD5 will be flagged as malware during scans</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-blue-400 mt-1">•</span>
                  <span>Make sure to only use this feature with confirmed malware samples</span>
                </li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AntivirusApp;