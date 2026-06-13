## 🚀 Key Features Shipped

| Feature                      | Description                                                                              | Tech                         |
| ---------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------- |
| **Live Telemetry**           | Overlay updates instantly as users navigate between websites.                            | Chrome Extension + Socket.IO |
| **ShadowScore Engine**       | Proprietary trust-scoring system that evaluates website legitimacy and security posture. | Python Risk Engine           |
| **F4 Security Analysis**     | Launches a deep security assessment of the active page.                                  | Browser Events + Flask API   |
| **Phishing Detection**       | Detects suspicious login flows, deceptive URLs, and credential harvesting patterns.      | Heuristic Analysis           |
| **Domain Spoof Detection**   | Identifies look-alike domains and impersonation attempts.                                | Domain Similarity Engine     |
| **Credential Risk Analysis** | Evaluates forms and authentication flows for theft risk.                                 | DOM Analysis                 |
| **Redirect Risk Analysis**   | Detects suspicious redirects and navigation chains.                                      | URL Intelligence             |
| **AI Explanations**          | Generates human-readable security reasoning and recommendations.                         | AI Explanation Engine        |
| **Protection Center**        | Interactive remediation dashboard providing actionable security guidance.                | Electron UI                  |
| **Copy Security Report**     | Generates shareable threat reports for users and analysts.                               | Dynamic Report Builder       |
| **Block Site**               | Allows users to immediately block suspicious domains from within the Protection Center.  | Local Protection Layer       |
| **Real-Time Overlay UI**     | Animated security dashboard with live threat visualization.                              | Electron + CSS Animations    |

---

## 🛡️ Understanding ShadowScore

ShadowScore is ShadowMap AI's proprietary trust metric designed to summarize website safety into a single intuitive score.

### Score Ranges

| Score  | Classification | Meaning                                |
| ------ | -------------- | -------------------------------------- |
| 95-100 | TRUSTED        | Verified, highly trustworthy website   |
| 80-94  | SAFE           | Generally safe with minor concerns     |
| 60-79  | WARNING        | Requires caution                       |
| 40-59  | DANGEROUS      | Significant security concerns          |
| 0-39   | CRITICAL       | High probability of malicious activity |

### Factors Considered

* Domain reputation
* Phishing probability
* Domain spoof probability
* Credential theft risk
* Redirect behavior
* HTTPS security
* Tracker analysis
* Trust signals
* Threat indicators

---

## 🎨 Protection Center

After analysis, ShadowMap opens the Protection Center, which presents:

### Security Metrics

* Phishing Risk
* Domain Spoof Risk
* Credential Risk
* Redirect Risk

### User Actions

* Continue Browsing
* Copy Security Report
* View Detailed Analysis
* Block Site
* Close Protection Center

### Visual Risk System

Green → Low Risk

Yellow → Moderate Risk

Orange → High Risk

Red → Critical Risk

All indicators dynamically update based on live scan results.

---

## 🏗️ Current Architecture

```text
Chrome Extension
       │
       ▼
Telemetry Stream
       │
       ▼
Flask Backend
       │
       ├── ShadowScore Engine
       ├── Phishing Engine
       ├── Risk Analyzer
       ├── AI Explanation Engine
       │
       ▼
Electron Overlay
       │
       ▼
Protection Center
```

---

## 📂 Project Structure

```text
ShadowMap/
│
├── backend/
│   ├── app.py
│   ├── engines/
│   │   ├── shadow_score_engine.py
│   │   ├── phishing_engine.py
│   │   ├── breach_checker.py
│   │   └── ai_explainer.py
│   │
│   └── database/
│
├── chrome-extension/
│   ├── background.js
│   ├── content.js
│   ├── manifest.json
│   └── assets/
│
├── electron-app/
│
├── README.md
└── LICENSE
```

---

## 🎯 Current Status

### Completed

✅ Real-Time Browser Telemetry

✅ ShadowScore Trust Engine

✅ Phishing Detection

✅ Domain Spoof Detection

✅ Credential Risk Analysis

✅ Redirect Risk Analysis

✅ AI Threat Explanations

✅ Electron Overlay UI

✅ Protection Center

✅ Copy Security Report

✅ Site Blocking

✅ GitHub Deployment

### In Progress

🚧 Advanced Threat Intelligence Feeds

🚧 Cloud Reputation Database

🚧 Enterprise Security Dashboard

🚧 Historical Risk Tracking

🚧 Cross-Browser Support

---

## 🏆 Why ShadowMap?

Traditional security tools require users to actively seek protection.

ShadowMap reverses this model.

Instead of asking users to visit a security dashboard, ShadowMap brings contextual security intelligence directly into their browsing experience through live telemetry, real-time analysis, AI-generated explanations, and actionable protection tools.

Cybersecurity becomes an instinct—not an interruption.
