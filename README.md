# ☁️ CloudShield — ML-Based Cloud Security Scanner

> **AI-powered cloud misconfiguration scanner with Indian compliance framework support (RBI, DPDP Act, CERT-In, IT Act)**

---

## 🚀 Features

- **ML-Based Risk Scoring** — Context-aware 0–100 risk scores using scikit-learn
- **Indian Compliance Frameworks** — RBI Guidelines, DPDP Act 2023, CERT-In Rules, IT Act 2000
- **Multi-Resource Support** — S3, EC2, RDS, IAM, Lambda, KMS, CloudTrail, Load Balancers, Security Groups
- **Auto-Remediation Engine** — Simulated one-click fixes for detected misconfigurations
- **Demo Mode** — Instant scan of 15 pre-configured sample AWS resources (no AWS account needed)
- **Upload Config Mode** — Upload your own JSON cloud config for scanning
- **PDF Report Export** — Detailed compliance reports with remediation steps
- **Mobile Responsive** — Works seamlessly on phones, tablets, and desktops

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask |
| ML | scikit-learn, numpy |
| Frontend | HTML5, CSS3, Vanilla JS |
| Charts | Chart.js |
| Cloud SDK | boto3 (AWS) |
| Deployment | Vercel (Python Serverless) |

---

## 📦 Local Setup

### Prerequisites
- Python 3.9+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cloud-security-scanner.git
cd cloud-security-scanner

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Visit **http://localhost:5000** in your browser.

---

## ☁️ Deploy to Vercel

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/cloud-security-scanner.git
git push -u origin main
```

### 2. Deploy on Vercel
1. Go to [vercel.com](https://vercel.com) and sign in with GitHub
2. Click **"Add New Project"**
3. Select your `cloud-security-scanner` repository
4. Set **Framework Preset** to `Other`
5. Add environment variable:
   - `SECRET_KEY` → any long random string
6. Click **Deploy** ✅

---

## 📁 Project Structure

```
cloud-security-scanner/
├── api/
│   └── index.py              # Vercel entry point
├── modules/
│   ├── cloud_connector.py    # AWS resource fetcher (demo mode)
│   ├── scanner_engine.py     # Security rule engine
│   ├── ml_predictor.py       # ML risk scorer
│   ├── compliance_mapper.py  # Indian compliance mapping
│   └── remediation_engine.py # Auto-remediation
├── static/
│   ├── css/style.css         # Main stylesheet (responsive)
│   └── js/main.js            # Frontend logic
├── templates/
│   ├── base.html             # Base template
│   ├── login.html            # Login / demo entry
│   ├── scan.html             # Scanning progress 
│   ├── dashboard.html        # Main security dashboard
│   └── report.html           # Compliance report
├── app.py                    # Flask application
├── config.py                 # App configuration
├── vercel.json               # Vercel deployment config
└── requirements.txt          # Python dependencies
```

---

## 🔐 Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| **RBI Guidelines** | Data localization, encryption, access controls |
| **DPDP Act 2023** | Personal data protection, consent, retention |
| **CERT-In Rules** | Incident reporting, log retention, vulnerability management |
| **IT Act 2000** | Sensitive personal data, electronic records |

---

## 📱 Supported Resource Types

`S3_Bucket` · `EC2_Instance` · `RDS_Instance` · `IAM_User` · `Security_Group` · `Lambda_Function` · `KMS_Key` · `CloudTrail` · `Load_Balancer`

---

## 📄 License

MIT License — free to use, modify, and distribute.
