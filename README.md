# 🛡️ WebGuardX: Enterprise Security Scanner

A full-stack cybersecurity platform built with **Next.js**, **Node.js**, and **Express.js** that performs active network reconnaissance, malware analysis, digital forensics, and password security assessment through an intuitive web interface.

## 🌐 Live Demo

- **Frontend:** https://webguardx-frontend.vercel.app/

## 🚀 Features

- 🔍 **Live Network Reconnaissance**
  - Scans target websites for missing security headers.
  - Detects phishing indicators and typosquatting domains.
  - Checks commonly exposed TCP ports (21, 22, 3306).

- 🛡️ **Malware Detection Engine**
  - Analyzes uploaded file hashes.
  - Detects suspicious executable files and spoofed extensions.

- 🖼️ **Steganography Analysis**
  - Performs hexadecimal buffer inspection.
  - Extracts hidden payloads embedded after image EOF markers.

- 🔐 **Password Security Analyzer**
  - Calculates password entropy.
  - Estimates brute-force crack time based on password complexity.

- 📁 **Digital Forensics Toolkit**
  - Displays file metadata including size, timestamps, and originating IP information (where available).

## 🛠️ Tech Stack

### Frontend
- Next.js
- React.js
- Tailwind CSS
- Recharts

### Backend
- Node.js
- Express.js
- JSON Web Token (JWT)
- Native `crypto` and `net` modules

## 📂 Project Structure

```
WebGuardX/
├── webguardx-frontend/
└── webguardx-backend/
```

## ⚙️ Local Installation

### 1. Clone the repository

```bash
git clone https://github.com/Safeer18/WebGuardX.git
```

### 2. Install dependencies

#### Backend

```bash
cd webguardx-backend
npm install
node server.js
```

#### Frontend

```bash
cd webguardx-frontend
npm install
npm run dev
```

## 🚀 Deployment

| Service | Platform |
|---------|----------|
| Frontend | Vercel |
| Backend | Render |

## 👨‍💻 Author

**Safeer Husain Zaidi**

- GitHub: https://github.com/Safeer18

---

⭐ If you found this project useful, consider giving it a star.
