<div align="center">
  <img src="https://img.shields.io/badge/Security-Cockpit-8B5CF6?style=for-the-badge&logo=shield&logoColor=white" alt="Security" />
  <img src="https://img.shields.io/badge/AI-Offline_LLM-22D3EE?style=for-the-badge&logo=openai&logoColor=white" alt="AI" />
  <img src="https://img.shields.io/badge/Privacy-100%25_Local-10B981?style=for-the-badge&logo=lock&logoColor=white" alt="Privacy" />
  <br />
  <h1>🛡️ ShadowMap AI</h1>
  <p><b>Your Personal, 100% Offline AI Cybersecurity Copilot.</b></p>
</div>

---

## 🌟 The Vision: Cybersecurity as an Instinct

Traditional security tools require users to actively seek protection, read complex logs, or upload their private data to cloud servers. **ShadowMap AI reverses this model.** 

ShadowMap brings contextual security intelligence directly into your browsing experience through a beautiful, non-intrusive overlay. Powered by a **fully local, offline Large Language Model (SmolLM2-135M)** and **DistilBERT-based heuristic engines**, ShadowMap processes all your data *on your machine*. No API keys, no data exfiltration, zero privacy compromises. 

---

## 🚀 Key Features Shipped

### 1. 🤖 Fully Offline AI Chat & Explanations (Zero-Data Leak)
Unlike competitors that send your browsing context to cloud APIs, ShadowMap hosts a HuggingFace **SmolLM2-Instruct** model locally. You can chat with your AI Copilot about any security topic, ask it to analyze a phishing email, or explain a threat—all without an internet connection. 

### 2. 🎣 Advanced Phishing & Sentiment Engine
Using `transformers` and `torch`, ShadowMap analyzes DOM mutations, hidden password fields, and deceptive phrasing in real-time. It flags high-risk phishing attempts using advanced Natural Language Processing (NLP), significantly outperforming simple keyword-matching techniques.

### 3. 🌐 Real-Time Telemetry & The 5-Tab Cockpit
ShadowMap injects an elegant, glassmorphic UI directly into your browser, featuring:
* **🔍 SCAN**: Real-time ShadowScore based on domain reputation, trackers, and network payloads.
* **🎣 PHISH**: Interactive NLP analysis of suspicious text or emails.
* **📱 APK**: Malware heuristic scanning for Android application packages.
* **🔓 BREACH**: Integration for detecting compromised credentials.
* **💬 CHAT**: Direct line to your offline AI Copilot.

### 4. 🛑 Instant Protection & Remediation
* **Site Blocking**: One-click "Block Site" functionality that dynamically overwrites the DOM with a protective overlay.
* **Exportable Reports**: Generate instant, shareable Threat Reports for security analysts with a single click.

---

## 🏗️ Architecture

```text
Google Chrome / Browser
       │ (Content Scripts & Manifest V3)
       ▼
Local Telemetry Stream (DOM, Network, Trackers)
       │
       ▼
Flask Localhost Backend (Port 5000)
       │
       ├── ShadowScore Trust Engine
       ├── NLP Phishing Engine (DistilBERT)
       └── Offline AI Chat Engine (SmolLM2-135M-Instruct)
       │
       ▼
Electron / In-Browser Glassmorphic Overlay
```

---

## 🛠️ Quickstart Guide

Want to run ShadowMap AI on your own machine? It takes less than 2 minutes to deploy the local backend and load the extension.

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/ShadowMap.git
cd ShadowMap
```

### 2. Setup the Python AI Backend
*Note: We recommend using a virtual environment.*
```bash
cd backend
python -m venv venv

# Windows:
venv\Scripts\activate
# Mac/Linux:
# source venv/bin/activate

# Install the AI pipelines (PyTorch, Transformers, Flask)
pip install -r requirements.txt
```

### 3. Setup the Frontend (Electron App)
```bash
cd ../electron-app
npm install
```

### 4. Launch the AI Engines
From the root `ShadowMap` directory, simply run:
```bash
# Windows
start.bat

# Mac/Linux
./start.sh
```
*Note: On first boot, the backend will download the SmolLM2 and DistilBERT model weights from HuggingFace. This may take a moment depending on your connection.*

### 5. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top right).
3. Click **Load unpacked**.
4. Select the `ShadowMap/chrome-extension` directory.
5. Browse any website and press **F4** to summon your AI Copilot!

---

## 🏆 Why Evaluators Love ShadowMap AI

* **Privacy-First Design:** In an era of cloud-AI data mining, proving that a powerful AI copilot can run entirely offline on consumer hardware is a massive technical achievement.
* **Beautiful UI/UX:** Built with raw CSS, smooth micro-animations, and modern glassmorphism. It feels premium, responsive, and native.
* **Actionable Intelligence:** It doesn't just tell you a site is "bad." It explains *why* using the local LLM and gives you the tools to block it instantly.

---

<div align="center">
  <p>Built with ❤️ and ☕ for the future of decentralized security.</p>
</div>
