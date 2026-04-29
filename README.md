# 🛡️ WebGuardX: Enterprise Security Scanner

A full-stack cybersecurity dashboard built with Next.js and Node.js to perform active network reconnaissance, digital forensics, and threat intelligence.

## 🚀 Features
* **Live Network Reconnaissance:** Actively scans target URLs for vulnerable security headers, phishing heuristics (typosquatting), and exposed TCP ports (21, 22, 3306).
* **Heuristic Malware Engine:** Inspects file hashes against threat databases and detects dangerous executable spoofing.
* **Steganography Extractor:** Performs raw hexadecimal buffer analysis to locate and extract covert hacker payloads hidden past the End of File (EOF) markers in images.
* **Cryptographic Entropy Simulator:** Calculates the exact mathematical randomness of passwords to estimate offline GPU brute-force crack times.
* **Digital Forensics Tracker:** Extracts local creation timestamps, byte sizes, and originating IP addresses from uploaded files.

## 🛠️ Tech Stack
* **Frontend:** Next.js (React), Tailwind CSS, Recharts
* **Backend:** Node.js, Express.js, JSON Web Tokens (JWT), native `net` and `crypto` modules.

## ⚙️ How to Run Locally
1. Clone the repository: `git clone https://github.com/YourUsername/WebGuardX.git`
2. Start the backend: `cd backend && node server.js`
3. Start the frontend: `cd frontend && npm run dev`
