// server.js
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const net = require('net'); 
const { URL } = require('url'); 

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'webguardx_super_secret_key_2026';
const upload = multer({ storage: multer.memoryStorage() });
const dbPath = path.join(__dirname, 'users.json');

const readUsers = () => { try { return JSON.parse(fs.readFileSync(dbPath, 'utf8')); } catch (err) { return []; } };
const saveUsers = (users) => { fs.writeFileSync(dbPath, JSON.stringify(users, null, 2)); };

const MALICIOUS_HASHES = [
    '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', // password
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'  // EICAR
];

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access denied" });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid session" });
        req.user = user; next();
    });
};

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    if (users.find(u => u.email === email)) return res.status(400).json({ error: "Email already registered" });
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { id: Date.now(), email, password: hashedPassword, history: [] };
        users.push(newUser); saveUsers(users);
        res.status(201).json({ message: "Registration successful" });
    } catch (error) { res.status(500).json({ error: "Registration failed" }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Invalid credentials" });
    res.json({ token: jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' }) });
});

app.get('/api/history', authenticateToken, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.id === req.user.userId);
    res.json(user && user.history ? user.history : []);
});

const checkPort = (port, host) => {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(1500); 
        socket.on('connect', () => { socket.destroy(); resolve(port); });
        socket.on('timeout', () => { socket.destroy(); resolve(null); });
        socket.on('error', () => { socket.destroy(); resolve(null); });
        socket.connect(port, host);
    });
};

app.post('/api/scan-url', authenticateToken, async (req, res) => {
    let { url } = req.body;
    let riskScore = 0; let issues = [];
    if (!url.startsWith('http')) url = 'https://' + url;

    try {
        const parsedUrl = new URL(url);
        const host = parsedUrl.hostname;

        const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
        if (isIP) { issues.push("Phishing Risk: URL uses a direct IP address instead of a domain name."); riskScore += 30; }
        if (host.split('.').length > 3 && !host.includes('www')) { issues.push("Typosquatting Risk: Deep subdomain nesting detected."); riskScore += 20; }
        
        const hyphenCount = (host.match(/-/g) || []).length;
        if (hyphenCount > 2) { issues.push(`Suspicious: Excessive hyphens in domain (${hyphenCount}).`); riskScore += 15; }

        if (url.startsWith('http://')) { issues.push("Insecure Protocol: Using HTTP instead of HTTPS."); riskScore += 40; }

        const fetchOptions = { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36' }};
        const response = await Promise.race([ fetch(url, fetchOptions), new Promise((_, r) => setTimeout(() => r(new Error("Timeout")), 10000)) ]);
        
        const headers = response.headers;
        if (!headers.get('content-security-policy')) { issues.push("Missing Content-Security-Policy (CSP)"); riskScore += 20; }
        if (!headers.get('strict-transport-security')) { issues.push("Missing HSTS Header"); riskScore += 15; }
        if (headers.get('server')) { issues.push(`Info Leak: Server header exposed (${headers.get('server')})`); riskScore += 10; }

        const portsToScan = [21, 22, 23, 80, 443, 3306];
        const openPortsRaw = await Promise.all(portsToScan.map(p => checkPort(p, host)));
        const openPorts = openPortsRaw.filter(p => p !== null);

        if (openPorts.includes(21)) { issues.push("Critical: FTP Port 21 is open to the public."); riskScore += 30; }
        if (openPorts.includes(22)) { issues.push("Warning: SSH Port 22 is exposed to the internet."); riskScore += 15; }
        if (openPorts.includes(3306)) { issues.push("Critical: MySQL Database Port 3306 is exposed globally."); riskScore += 40; }

        riskScore = Math.min(riskScore, 100);
        if (issues.length === 0) issues.push("Excellent! Strict security headers and safe ports enabled.");

        const result = { type: 'URL Scan', target: url, riskScore, date: new Date().toISOString() };
        
        const users = readUsers();
        const userIndex = users.findIndex(u => u.id === req.user.userId);
        if (userIndex !== -1) { 
            users[userIndex].history = users[userIndex].history || []; 
            users[userIndex].history.unshift(result); 
            saveUsers(users); 
        }

        res.json({ ...result, issues, openPorts });
    } catch (e) { res.status(400).json({ error: "Website unreachable or timed out." }); }
});

app.post('/api/scan-file', [authenticateToken, upload.single('file')], (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file provided" });

    const fileHash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    const filename = req.file.originalname.toLowerCase();
    const buffer = req.file.buffer;
    
    let uploaderIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (uploaderIp === '::1') uploaderIp = '127.0.0.1 (Localhost)';

    let riskScore = MALICIOUS_HASHES.includes(fileHash) ? 100 : 0;
    let issues = [];
    let hiddenData = null;

    if (riskScore === 100) issues.push("Known malware signature matched");
    if (filename.split('.').length > 2) { issues.push("Double extension detected (Spoofing attempt)"); riskScore += 30; }
    if (['.exe', '.bat', '.vbs', '.ps1'].some(ext => filename.endsWith(ext))) { issues.push("Dangerous executable format"); riskScore += 40; }

    // STEGANOGRAPHY EOF BYTE ANALYSIS
    if (req.file.mimetype.startsWith('image/')) {
        if (filename.endsWith('.jpg') || filename.endsWith('.jpeg')) {
            const eofIndex = buffer.lastIndexOf(Buffer.from([0xFF, 0xD9]));
            if (eofIndex !== -1 && eofIndex < buffer.length - 2) {
                const extracted = buffer.slice(eofIndex + 2).toString('utf8').replace(/[^\x20-\x7E]/g, '').trim();
                if (extracted.length > 5) {
                    hiddenData = extracted;
                    issues.push(`Steganography Alert: ${buffer.length - (eofIndex + 2)} bytes of hidden payload found after JPEG EOF.`);
                    riskScore += 60;
                }
            }
        } else if (filename.endsWith('.png')) {
            const iend = Buffer.from([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
            const eofIndex = buffer.indexOf(iend);
            if (eofIndex !== -1 && eofIndex < buffer.length - iend.length) {
                const extracted = buffer.slice(eofIndex + iend.length).toString('utf8').replace(/[^\x20-\x7E]/g, '').trim();
                if (extracted.length > 5) {
                    hiddenData = extracted;
                    issues.push(`Steganography Alert: ${buffer.length - (eofIndex + iend.length)} bytes of hidden payload found after PNG EOF.`);
                    riskScore += 60;
                }
            }
        }
    }

    if (req.file.size < 1000000 && !hiddenData) {
        const content = buffer.toString('utf8');
        const triggers = ['eval(', 'WScript.Shell', 'cmd.exe', 'powershell'];
        const found = triggers.filter(t => content.includes(t));
        if (found.length > 0) { issues.push(`Suspicious patterns found: ${found.join(', ')}`); riskScore += 30; }
    }

    riskScore = Math.min(riskScore, 100);
    const isMalicious = riskScore >= 70;
    const result = { type: 'File Scan', target: req.file.originalname, riskScore, isMalicious, date: new Date().toISOString() };

    const users = readUsers();
    const userIndex = users.findIndex(u => u.id === req.user.userId);
    if (userIndex !== -1) { 
        users[userIndex].history = users[userIndex].history || [];
        users[userIndex].history.unshift(result); 
        saveUsers(users); 
    }

    res.json({ 
        ...result, 
        hash: fileHash, 
        issues, 
        hiddenData, 
        message: isMalicious ? "Threat Detected" : "Clean", 
        footprint: { size: req.body.size || req.file.size, lastModified: req.body.lastModified || Date.now(), uploaderIp }
    });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 WebGuardX Backend ready on port ${PORT}`));