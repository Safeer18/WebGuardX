// app/page.tsx
'use client';
import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const faqs = [
  { question: "What vulnerabilities does the URL Scanner detect?", answer: "Our active scanner checks for insecure HTTP protocols, missing security headers, server information leaks, phishing heuristics (like typosquatting), and performs active TCP Port Reconnaissance." },
  { question: "How does the File Scanner identify malware?", answer: "WebGuardX uses a Multi-Layered Heuristic Engine. It checks cryptographic file hashes, analyzes extensions for spoofing, and scans the raw code for dangerous execution commands." },
  { question: "What is Steganography Detection?", answer: "Hackers often hide malicious code inside normal-looking images by injecting data past the file's End of File (EOF) marker. WebGuardX analyzes raw hexadecimal byte buffers to extract this covert data." },
  { question: "How does the Digital Forensics Footprint work?", answer: "Browsers naturally strip forensic metadata for privacy. WebGuardX uses custom scripts to extract local timestamps and exact byte sizes before transmission, while the backend captures the incoming packet's Network IP address to track the origin." },
  { question: "How does the Password Entropy Simulator work?", answer: "It calculates the exact mathematical randomness of your password based on the character set size and length. It then estimates how long a hacker's offline GPU array (capable of 100 Billion guesses a second) would take to brute-force it." }
];

const threatDatabase = [
  { id: 't1', category: 'Malware', name: 'Ransomware', icon: '🔒', riskLevel: 'Critical', description: 'Malicious software that encrypts a victim\'s files or locks them out of their system, demanding a ransom payment to restore access.', example: 'WannaCry, CryptoLocker', mitigation: 'Maintain offline backups, use advanced endpoint detection (EDR), and never pay the ransom.' },
  { id: 't2', category: 'Vulnerability', name: 'Cross-Site Scripting (XSS)', icon: '📝', riskLevel: 'High', description: 'A flaw where an application includes untrusted data in a web page without proper validation. Hackers use this to execute malicious scripts in a victim\'s browser.', example: 'Stealing session cookies via a malicious script hidden in a blog comment.', mitigation: 'Implement a strong Content-Security-Policy (CSP) and sanitize all user input.' },
  { id: 't3', category: 'Network Attack', name: 'TCP Port Exposure', icon: '🚪', riskLevel: 'Critical', description: 'Leaving administrative ports (like SSH 22 or MySQL 3306) open to the public internet, allowing hackers to attempt direct logins to the server.', example: 'Brute-forcing an open database port.', mitigation: 'Configure strict firewall rules to block non-essential ports.' },
  { id: 't4', category: 'Malware', name: 'Trojan Horse', icon: '🐴', riskLevel: 'High', description: 'A destructive program that masquerades as a benign application. Unlike viruses, Trojans do not replicate themselves but require the user to actively download and execute them.', example: 'A fake PDF invoice that secretly installs a keylogger.', mitigation: 'Verify file extensions (watch out for .pdf.exe), and avoid downloading software from untrusted sources.' },
  { id: 't5', category: 'Vulnerability', name: 'Steganography Injection', icon: '🖼️', riskLevel: 'Critical', description: 'Hiding malicious scripts or payloads inside benign files like JPEGs or PNGs by appending data past the End of File (EOF) marker.', example: 'Executing PowerShell commands hidden inside a website logo.', mitigation: 'Use deep file inspection and buffer analysis to strip abnormal EOF data.' },
  { id: 't6', category: 'Network Attack', name: 'Man-in-the-Middle', icon: '🕵️', riskLevel: 'Critical', description: 'An attacker secretly intercepts and alters communications between two parties who believe they are directly communicating with each other.', example: 'A hacker setting up a fake "Free Airport WiFi" to steal passwords.', mitigation: 'Always enforce HTTPS, use Virtual Private Networks (VPNs), and implement HSTS headers.' }
];

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<'url' | 'file' | 'library' | 'password'>('url');
  const [selectedThreat, setSelectedThreat] = useState<any>(null);
  
  const [file, setFile] = useState<File | null>(null);
  const [urlResult, setUrlResult] = useState<any>(null);
  const [fileResult, setFileResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [history, setHistory] = useState<any[]>([]); 
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const router = useRouter();

  const [pwdInput, setPwdInput] = useState('');
  const [entropyData, setEntropyData] = useState({ entropy: 0, timeString: 'Instant', pool: 0, length: 0 });

  useEffect(() => {
    if (!pwdInput) { setEntropyData({ entropy: 0, timeString: 'Instant', pool: 0, length: 0 }); return; }
    let pool = 0;
    if (/[a-z]/.test(pwdInput)) pool += 26;
    if (/[A-Z]/.test(pwdInput)) pool += 26;
    if (/[0-9]/.test(pwdInput)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwdInput)) pool += 32;

    const entropy = pool === 0 ? 0 : pwdInput.length * Math.log2(pool);
    const combinations = Math.pow(pool, pwdInput.length);
    const secondsToCrack = combinations / 100000000000; 

    let timeString = "";
    if (secondsToCrack < 1) timeString = "Instant";
    else if (secondsToCrack < 60) timeString = `${Math.round(secondsToCrack)} Seconds`;
    else if (secondsToCrack < 3600) timeString = `${Math.round(secondsToCrack/60)} Minutes`;
    else if (secondsToCrack < 86400) timeString = `${Math.round(secondsToCrack/3600)} Hours`;
    else if (secondsToCrack < 31536000) timeString = `${Math.round(secondsToCrack/86400)} Days`;
    else if (secondsToCrack < 3153600000) timeString = `${Math.round(secondsToCrack/31536000)} Years`;
    else timeString = "Centuries+";

    setEntropyData({ entropy: Math.round(entropy), timeString, pool, length: pwdInput.length });
  }, [pwdInput]);

  const fetchHistory = async (token: string) => {
    try {
      const res = await fetch('http://localhost:5000/api/history', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await res.json();
        setHistory(Array.isArray(data) ? data : []);
      }
    } catch (err) { console.error("Failed to fetch history"); }
  };

  useEffect(() => {
    const token = localStorage.getItem('webguardx_token');
    if (!token) router.push('/login');
    else { setIsAuthenticated(true); fetchHistory(token); }
  }, [router]);

  const handleLogout = () => { localStorage.removeItem('webguardx_token'); router.push('/login'); };

  const handleUrlScan = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setLoading(true); setUrlResult(null);
    const token = localStorage.getItem('webguardx_token');
    const submittedUrl = new FormData(e.currentTarget).get('urlInput') as string;

    try {
      const res = await fetch('http://localhost:5000/api/scan-url', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }, body: JSON.stringify({ url: submittedUrl }),
      });
      const data = await res.json();
      if (!res.ok) setUrlResult({ error: data.error || "Failed to scan website.", target: submittedUrl });
      else { setUrlResult(data); if (token) fetchHistory(token); }
    } catch (err) { console.error(err); }
    setLoading(false);
  };

  const handleFileScan = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault(); if (!file) return;
    setLoading(true); setFileResult(null);
    const token = localStorage.getItem('webguardx_token');
    const formData = new FormData();
    formData.append('file', file); 
    formData.append('lastModified', file.lastModified.toString()); 
    formData.append('size', file.size.toString());

    try {
      const res = await fetch('http://localhost:5000/api/scan-file', {
        method: 'POST', headers: { 'Authorization': `Bearer ${token}` }, body: formData,
      });
      const data = await res.json();
      if (!res.ok) setFileResult({ error: "Failed to scan file", ...data });
      else { setFileResult(data); if (token) fetchHistory(token); }
    } catch (err) { console.error(err); }
    setLoading(false);
  };

  const chartData = useMemo(() => {
    if (!history || history.length === 0) return [];
    return [...history].reverse().map((item, index) => ({ 
      name: `Scan ${index + 1}`, 
      risk: item.riskScore || 0, 
      target: item.target ? item.target.substring(0, 15) : 'Unknown' 
    }));
  }, [history]);

  const totalScans = history.length;
  const threatsBlocked = history.filter(item => item.isMalicious || item.riskScore >= 70).length;
  const avgRisk = totalScans > 0 ? Math.round(history.reduce((sum, item) => sum + (item.riskScore || 0), 0) / totalScans) : 0;

  if (!isAuthenticated) return null;

  return (
    <div className="min-h-screen bg-zinc-50 font-sans text-zinc-900 relative">
      
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-zinc-950/80 backdrop-blur-sm animate-fade-in-up">
          <div className="bg-white w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden border-2 border-zinc-200">
            <div className={`px-8 py-6 flex justify-between items-center border-b-4 ${selectedThreat.riskLevel === 'Critical' ? 'border-red-600 bg-red-50' : 'border-amber-500 bg-amber-50'}`}>
              <div className="flex items-center gap-4">
                <span className="text-4xl">{selectedThreat.icon}</span>
                <div>
                  <h2 className="text-2xl font-black text-zinc-900 uppercase tracking-wide">{selectedThreat.name}</h2>
                  <span className={`text-xs font-bold uppercase tracking-widest px-2 py-1 rounded ${selectedThreat.riskLevel === 'Critical' ? 'bg-red-200 text-red-800' : 'bg-amber-200 text-amber-800'}`}>
                    {selectedThreat.riskLevel} RISK • {selectedThreat.category}
                  </span>
                </div>
              </div>
              <button onClick={() => setSelectedThreat(null)} className="text-zinc-400 hover:text-zinc-900 text-2xl font-bold transition">✕</button>
            </div>
            <div className="p-8 space-y-6">
              <div><h3 className="text-sm font-black text-zinc-500 uppercase tracking-widest mb-2">How it works</h3><p className="text-zinc-800 font-medium leading-relaxed">{selectedThreat.description}</p></div>
              <div className="bg-zinc-100 p-4 rounded-lg border border-zinc-200"><h3 className="text-sm font-black text-zinc-500 uppercase tracking-widest mb-1">Real-World Example</h3><p className="font-mono text-sm text-zinc-700">{selectedThreat.example}</p></div>
              <div><h3 className="text-sm font-black text-zinc-500 uppercase tracking-widest mb-2 text-emerald-600">Defense & Mitigation</h3><p className="text-zinc-800 font-medium leading-relaxed border-l-4 border-emerald-500 pl-4">{selectedThreat.mitigation}</p></div>
            </div>
          </div>
        </div>
      )}

      <nav className="bg-zinc-950 text-white px-8 py-4 flex justify-between items-center border-b-4 border-red-600 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 bg-red-600 rounded flex items-center justify-center font-black text-2xl shadow-lg">W</div>
          <span className="text-2xl font-bold tracking-tight">WebGuard<span className="text-red-500">X</span></span>
        </div>
        <button onClick={handleLogout} className="text-sm font-semibold text-zinc-400 hover:text-white transition">Secure Logout →</button>
      </nav>

      <div className="bg-zinc-950 py-24 px-4 text-center relative overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-4xl bg-red-900/10 blur-3xl pointer-events-none rounded-full"></div>
        <div className="relative z-10">
          <h1 className="text-4xl md:text-6xl font-extrabold text-white mb-6 tracking-tight">Enterprise Security & Threat Recon</h1>
          <p className="text-zinc-400 text-lg md:text-xl max-w-3xl mx-auto mb-12">Instantly run TCP port reconnaissance, heuristic malware analysis, and cryptographic password audits.</p>
        </div>

        <div className="relative z-10 max-w-5xl mx-auto bg-white rounded-xl shadow-2xl overflow-hidden text-left border border-zinc-200">
          <div className="flex border-b border-zinc-200 bg-zinc-50 flex-col md:flex-row">
            <button onClick={() => setActiveTab('url')} className={`flex-1 py-4 font-bold text-center transition tracking-wide text-sm md:text-base ${activeTab === 'url' ? 'text-red-700 border-b-4 border-red-600 bg-white' : 'text-zinc-500 hover:bg-zinc-100'}`}>SCAN WEBSITE</button>
            <button onClick={() => setActiveTab('file')} className={`flex-1 py-4 font-bold text-center transition tracking-wide text-sm md:text-base ${activeTab === 'file' ? 'text-red-700 border-b-4 border-red-600 bg-white' : 'text-zinc-500 hover:bg-zinc-100'}`}>ANALYZE FILE</button>
            <button onClick={() => setActiveTab('password')} className={`flex-1 py-4 font-bold text-center transition tracking-wide text-sm md:text-base ${activeTab === 'password' ? 'text-red-700 border-b-4 border-red-600 bg-white' : 'text-zinc-500 hover:bg-zinc-100'}`}>ENTROPY CRACKER</button>
            <button onClick={() => setActiveTab('library')} className={`flex-1 py-4 font-bold text-center transition tracking-wide text-sm md:text-base ${activeTab === 'library' ? 'text-red-700 border-b-4 border-red-600 bg-white' : 'text-zinc-500 hover:bg-zinc-100'}`}>THREAT LIBRARY</button>
          </div>

          <div className="p-10 min-h-[180px]">
            {activeTab === 'url' && (
              <form onSubmit={handleUrlScan} className="flex flex-col md:flex-row gap-4 animate-fade-in-up">
                <input type="url" name="urlInput" placeholder="Enter target (e.g., https://example.com)" className="flex-1 px-6 py-4 bg-zinc-50 border-2 border-zinc-200 rounded-lg focus:outline-none focus:border-red-600 focus:bg-white transition text-lg" required />
                <button type="submit" disabled={loading} className="px-10 py-4 bg-red-600 hover:bg-red-700 text-white font-bold rounded-lg transition disabled:opacity-70 text-lg shadow-lg shadow-red-600/20 whitespace-nowrap uppercase tracking-wider">{loading ? 'Scanning...' : 'Run Recon'}</button>
              </form>
            )}

            {activeTab === 'file' && (
              <form onSubmit={handleFileScan} className="flex flex-col md:flex-row gap-4 animate-fade-in-up">
                <input type="file" className="flex-1 px-6 py-3 bg-zinc-50 border-2 border-zinc-200 rounded-lg focus:outline-none focus:border-red-600 focus:bg-white transition text-zinc-600 file:mr-4 file:py-2.5 file:px-5 file:rounded-md file:border-0 file:text-sm file:font-bold file:bg-red-50 file:text-red-700 hover:file:bg-red-100 cursor-pointer" onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)} required />
                <button type="submit" disabled={loading} className="px-10 py-4 bg-zinc-900 hover:bg-zinc-800 text-white font-bold rounded-lg transition disabled:opacity-70 text-lg whitespace-nowrap uppercase tracking-wider">{loading ? 'Analyzing...' : 'Analyze Hash'}</button>
              </form>
            )}

            {activeTab === 'password' && (
              <div className="animate-fade-in-up space-y-8">
                <div>
                  <input type="text" value={pwdInput} onChange={(e) => setPwdInput(e.target.value)} placeholder="Type a password to test brute-force resistance..." className="w-full px-6 py-4 bg-zinc-50 border-2 border-zinc-200 rounded-lg focus:outline-none focus:border-red-600 focus:bg-white transition text-xl font-mono text-center tracking-widest shadow-inner" />
                </div>
                
                {pwdInput && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-zinc-900 text-white p-6 rounded-xl text-center border-b-4 border-red-600">
                      <p className="text-zinc-400 text-xs font-black uppercase tracking-widest mb-2">Math Entropy</p>
                      <p className="text-5xl font-black">{entropyData.entropy} <span className="text-xl text-zinc-500">bits</span></p>
                    </div>
                    <div className="bg-zinc-900 text-white p-6 rounded-xl text-center border-b-4 border-zinc-500">
                      <p className="text-zinc-400 text-xs font-black uppercase tracking-widest mb-2">Character Pool</p>
                      <p className="text-5xl font-black">{entropyData.pool} <span className="text-xl text-zinc-500">chars</span></p>
                    </div>
                    <div className="bg-zinc-900 text-white p-6 rounded-xl text-center border-b-4 border-emerald-500 md:col-span-1">
                      <p className="text-zinc-400 text-xs font-black uppercase tracking-widest mb-2">GPU Crack Time</p>
                      <p className={`text-4xl font-black ${entropyData.entropy < 50 ? 'text-red-500' : 'text-emerald-500'}`}>{entropyData.timeString}</p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'library' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 animate-fade-in-up">
                {threatDatabase.map((threat) => (
                  <div key={threat.id} onClick={() => setSelectedThreat(threat)} className="bg-white border-2 border-zinc-200 rounded-xl p-5 cursor-pointer hover:border-red-600 hover:shadow-lg transition-all group">
                    <div className="flex items-center gap-3 mb-3"><span className="text-3xl group-hover:scale-110 transition-transform">{threat.icon}</span><h3 className="font-black text-zinc-900 uppercase tracking-tight leading-tight">{threat.name}</h3></div>
                    <p className="text-sm font-bold text-zinc-500 uppercase tracking-widest">{threat.category}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <main className="max-w-6xl mx-auto px-4 py-16 space-y-12">
        
        {history.length > 0 && (
          <section className="grid grid-cols-1 md:grid-cols-3 gap-8 animate-fade-in-up">
            <div className="bg-white border-l-4 border-l-zinc-800 border-y border-r border-zinc-200 rounded-r-xl p-6 shadow-sm flex items-center gap-5">
              <div className="w-14 h-14 rounded-full bg-zinc-100 flex items-center justify-center text-zinc-800 text-2xl">📡</div>
              <div><p className="text-zinc-500 text-sm font-bold uppercase tracking-wider">Total Scans</p><p className="text-4xl font-black text-zinc-900">{totalScans}</p></div>
            </div>
            
            <div className="bg-white border-l-4 border-l-red-600 border-y border-r border-zinc-200 rounded-r-xl p-6 shadow-sm flex items-center gap-5">
              <div className="w-14 h-14 rounded-full bg-red-50 flex items-center justify-center text-red-600 text-2xl">🛡️</div>
              <div><p className="text-zinc-500 text-sm font-bold uppercase tracking-wider">Threats Blocked</p><p className="text-4xl font-black text-zinc-900">{threatsBlocked}</p></div>
            </div>

            <div className="bg-white border-l-4 border-l-zinc-400 border-y border-r border-zinc-200 rounded-r-xl p-6 shadow-sm flex items-center gap-5">
              <div className="w-14 h-14 rounded-full bg-zinc-50 flex items-center justify-center text-zinc-500 text-2xl">📊</div>
              <div><p className="text-zinc-500 text-sm font-bold uppercase tracking-wider">Avg Network Risk</p><p className="text-4xl font-black text-zinc-900">{avgRisk} <span className="text-xl font-semibold text-zinc-400">/ 100</span></p></div>
            </div>
          </section>
        )}

        {urlResult && activeTab === 'url' && (
          <section className="animate-fade-in-up">
            <h2 className="text-2xl font-black text-zinc-900 mb-6 flex items-center gap-3 uppercase tracking-wide">
              <span className="w-3 h-8 bg-red-600 rounded-sm"></span> Reconnaissance Report
            </h2>
            
            {urlResult.error ? (
              <div className="bg-red-50 border-2 border-red-200 rounded-xl p-8 flex items-start gap-5">
                <div className="text-4xl">⚠️</div>
                <div><h3 className="text-xl font-bold text-red-900 uppercase tracking-wide">Connection Failed</h3><p className="text-red-700 mt-2 font-medium">{urlResult.error}</p></div>
              </div>
            ) : (
              <div className="flex flex-col gap-8">
                <div className="bg-white border border-zinc-200 rounded-xl shadow-md p-10 flex flex-col md:flex-row gap-10 items-start">
                  <div className={`flex flex-col items-center justify-center w-48 h-48 rounded-full border-[10px] ${urlResult.riskScore > 30 ? 'border-red-100' : 'border-emerald-100'} shrink-0`}>
                    <span className={`text-6xl font-black ${urlResult.riskScore > 30 ? 'text-red-600' : 'text-emerald-600'}`}>{urlResult.riskScore}</span>
                    <span className="text-zinc-500 font-bold uppercase tracking-widest text-xs mt-2">Risk Score</span>
                  </div>
                  <div className="flex-1 w-full">
                    <h3 className="text-xl font-bold text-zinc-900 mb-6 uppercase tracking-wide border-b border-zinc-100 pb-4">Security Headers & Phishing Heuristics</h3>
                    <ul className="space-y-4">
                      {(urlResult.issues ?? []).map((issue: string, idx: number) => {
                        const isPositive = issue.toLowerCase().includes("enabled") || issue.toLowerCase().includes("excellent") || issue.toLowerCase().includes("safe");
                        return (
                          <li key={idx} className="flex items-start gap-4 text-zinc-700 bg-zinc-50 p-4 rounded-lg border border-zinc-200 font-medium">
                            <span className={`text-lg mt-0.5 ${isPositive ? 'text-emerald-600' : 'text-red-600'}`}>{isPositive ? '✓' : '✖'}</span>{issue}
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                </div>

                {urlResult.openPorts && (
                  <div className="bg-white border border-zinc-200 rounded-xl shadow-md p-10">
                    <h3 className="text-xl font-bold text-zinc-900 mb-6 uppercase tracking-wide border-b border-zinc-100 pb-4 flex items-center gap-3">
                      <span>🚪</span> TCP Open Port Reconnaissance
                    </h3>
                    <div className="flex flex-wrap gap-4">
                      {[21, 22, 23, 80, 443, 3306].map(port => {
                        const isOpen = urlResult.openPorts.includes(port);
                        const isDangerous = isOpen && [21, 22, 23, 3306].includes(port);
                        let service = "HTTP";
                        if(port===21) service="FTP"; if(port===22) service="SSH"; if(port===23) service="TELNET"; if(port===443) service="HTTPS"; if(port===3306) service="MySQL";

                        return (
                          <div key={port} className={`flex-1 min-w-[120px] p-4 rounded-xl border-2 text-center ${!isOpen ? 'border-zinc-200 bg-zinc-50 opacity-50' : isDangerous ? 'border-red-500 bg-red-50' : 'border-emerald-500 bg-emerald-50'}`}>
                            <p className={`text-xs font-black uppercase tracking-widest ${!isOpen ? 'text-zinc-400' : isDangerous ? 'text-red-600' : 'text-emerald-600'}`}>{service}</p>
                            <p className={`text-2xl font-mono font-bold ${!isOpen ? 'text-zinc-500' : isDangerous ? 'text-red-700' : 'text-emerald-700'}`}>{port}</p>
                            <p className="text-xs font-bold text-zinc-500 mt-1 uppercase">{isOpen ? 'OPEN' : 'CLOSED'}</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>
        )}

        {fileResult && activeTab === 'file' && (
          <section className="animate-fade-in-up">
            <h2 className="text-2xl font-black text-zinc-900 mb-6 flex items-center gap-3 uppercase tracking-wide"><span className="w-3 h-8 bg-zinc-900 rounded-sm"></span> Threat Intelligence</h2>
            <div className={`bg-white border-2 rounded-xl shadow-md p-10 ${fileResult.isMalicious ? 'border-red-500' : 'border-emerald-500'}`}>
              <div className="flex items-center gap-6 mb-8">
                <div className={`w-16 h-16 rounded-full flex items-center justify-center text-3xl ${fileResult.isMalicious ? 'bg-red-100 text-red-600' : 'bg-emerald-100 text-emerald-600'}`}>{fileResult.isMalicious ? '✖' : '✓'}</div>
                <div>
                  <h3 className={`text-2xl font-black uppercase tracking-wide ${fileResult.isMalicious ? 'text-red-600' : 'text-emerald-600'}`}>{fileResult.message}</h3>
                  <p className="text-zinc-500 font-mono text-sm mt-2 truncate max-w-xl bg-zinc-100 px-3 py-1 rounded inline-block">Hash: {fileResult.hash}</p>
                </div>
              </div>
              
              {fileResult.issues && fileResult.issues.length > 0 && (
                <div className="mt-8 pt-8 border-t border-zinc-200">
                   <h3 className="text-sm font-black text-zinc-900 uppercase tracking-widest mb-4">Detection Engine Flags:</h3>
                   <ul className="space-y-3">
                     {fileResult.issues.map((issue: string, idx: number) => (
                       <li key={idx} className="flex items-start gap-3 text-red-700 bg-red-50 p-4 rounded-lg border border-red-100 font-bold"><span className="text-red-600">⚠</span> {issue}</li>
                     ))}
                   </ul>
                </div>
              )}

              {/* Steganography Extractor UI */}
              {fileResult.hiddenData && (
                <div className="mt-8 pt-8 border-t border-zinc-200 animate-fade-in-up">
                   <h3 className="text-sm font-black text-red-600 uppercase tracking-widest mb-4 flex items-center gap-2">
                     <span className="text-2xl">🕵️</span> Covert Steganography Payload Extracted
                   </h3>
                   <div className="bg-red-50 p-6 rounded-xl border-2 border-red-500 shadow-inner relative overflow-hidden">
                     <div className="absolute top-0 left-0 w-full h-2 bg-gradient-to-r from-red-600 via-red-500 to-red-600"></div>
                     <p className="text-xs font-bold text-red-800 uppercase tracking-wider mb-2 opacity-80">Raw Hex Dump Translation (Sanitized):</p>
                     <p className="font-mono text-red-900 font-bold whitespace-pre-wrap break-all bg-white/50 p-4 rounded border border-red-200">
                       {fileResult.hiddenData}
                     </p>
                   </div>
                </div>
              )}

              {fileResult.footprint && (
                <div className="mt-8 pt-8 border-t border-zinc-200">
                   <h3 className="text-sm font-black text-zinc-900 uppercase tracking-widest mb-4 flex items-center gap-2"><span className="text-xl">🔎</span> Digital Forensics Footprint</h3>
                   <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                     <div className="bg-zinc-50 p-4 rounded-lg border border-zinc-200"><p className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">Source IP Address</p><p className="font-mono text-zinc-900 font-bold">{fileResult.footprint.uploaderIp}</p></div>
                     <div className="bg-zinc-50 p-4 rounded-lg border border-zinc-200"><p className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">File Size</p><p className="font-mono text-zinc-900 font-bold">{(fileResult.footprint.size / 1024).toFixed(2)} KB</p></div>
                     <div className="bg-zinc-50 p-4 rounded-lg border border-zinc-200 md:col-span-2"><p className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-1">Last Modified (Local System)</p><p className="font-mono text-zinc-900 font-bold">{new Date(parseInt(fileResult.footprint.lastModified)).toLocaleString()}</p></div>
                   </div>
                </div>
              )}
            </div>
          </section>
        )}

        {history.length > 0 && (
          <section>
            <h2 className="text-xl font-black text-zinc-900 mb-6 uppercase tracking-wide">Risk Trend Analysis</h2>
            <div className="bg-white border border-zinc-200 rounded-xl shadow-md p-8 h-96">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#dc2626" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e4e4e7" />
                  <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#71717a', fontWeight: 600 }} dy={10} />
                  <YAxis axisLine={false} tickLine={false} tick={{ fill: '#71717a', fontWeight: 600 }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ borderRadius: '8px', border: '1px solid #e4e4e7', boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)' }} labelStyle={{ fontWeight: '900', color: '#18181b', textTransform: 'uppercase' }} />
                  <Area type="monotone" dataKey="risk" stroke="#dc2626" strokeWidth={4} fillOpacity={1} fill="url(#colorRisk)" activeDot={{ r: 8, fill: '#dc2626', stroke: '#fff', strokeWidth: 2 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>
        )}

        <section>
          <h2 className="text-xl font-black text-zinc-900 mb-6 uppercase tracking-wide">System Activity Log</h2>
          <div className="bg-white border border-zinc-200 rounded-xl shadow-md overflow-hidden">
            {history.length === 0 ? (
              <div className="p-12 text-center text-zinc-500 font-medium"><p>System log is empty. Initiate a scan to populate history.</p></div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-zinc-100 border-b-2 border-zinc-200 text-zinc-700 text-xs">
                      <th className="p-5 font-black uppercase tracking-widest">Date & Time</th>
                      <th className="p-5 font-black uppercase tracking-widest">Protocol Type</th>
                      <th className="p-5 font-black uppercase tracking-widest">Target Asset</th>
                      <th className="p-5 font-black uppercase tracking-widest">Diagnostic Result</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-100">
                    {history.map((item, index) => (
                      <tr key={index} className="hover:bg-zinc-50 transition">
                        <td className="p-5 text-sm text-zinc-600 font-medium">{new Date(item.date).toLocaleString()}</td>
                        <td className="p-5"><span className={`px-4 py-1.5 rounded text-xs font-black tracking-widest uppercase ${item.type === 'URL Scan' ? 'bg-zinc-800 text-white' : 'bg-zinc-200 text-zinc-800'}`}>{item.type}</span></td>
                        <td className="p-5 text-sm font-bold text-zinc-900 truncate max-w-[200px]">{item.target}</td>
                        <td className="p-5">
                          {item.type === 'URL Scan' ? (
                            <span className={`font-black uppercase tracking-wide ${item.riskScore > 30 ? 'text-red-600' : 'text-emerald-600'}`}>Risk: {item.riskScore}</span>
                          ) : (
                            <span className={`font-black uppercase tracking-wide ${item.isMalicious ? 'text-red-600' : 'text-emerald-600'}`}>{item.isMalicious ? 'Malware' : 'Clean'}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        <section className="pt-8">
          <h2 className="text-xl font-black text-zinc-900 mb-6 uppercase tracking-wide border-b border-zinc-200 pb-4">Platform Documentation & FAQs</h2>
          <div className="space-y-4">
            {faqs.map((faq, idx) => (
              <div key={idx} className="bg-white border border-zinc-200 rounded-xl shadow-sm overflow-hidden transition-all">
                <button onClick={() => setOpenFaq(openFaq === idx ? null : idx)} className="w-full px-6 py-5 flex justify-between items-center text-left focus:outline-none hover:bg-zinc-50 transition-colors">
                  <span className="font-bold text-zinc-800 uppercase tracking-wide text-sm">{faq.question}</span><span className={`text-red-600 font-black text-xl transition-transform duration-300 ${openFaq === idx ? 'rotate-180' : ''}`}>▼</span>
                </button>
                {openFaq === idx && (<div className="px-6 pb-6 pt-2 text-zinc-600 font-medium border-t border-zinc-100 bg-zinc-50 leading-relaxed text-sm">{faq.answer}</div>)}
              </div>
            ))}
          </div>
        </section>

      </main>
    </div>
  );
}