# 🛡️ SecureWatch — Real-Time Linux Security Monitoring Dashboard

A lightweight SOC (Security Operations Center) dashboard for monitoring Linux authentication logs, detecting intrusion attempts, and visualizing threat activity in real time.

Built with Python, Flask, SQLite, Chart.js, and a custom dark cybersecurity UI.

---

## ✨ Features

- **Real-Time Log Monitoring** — Parse `/var/log/auth.log` and detect authentication events
- **Brute-Force Detection** — Automatically flag IPs with repeated failed login attempts
- **Threat Alert System** — Tiered severity (Low / Medium / High / Critical) with resolve workflow
- **Suspicious IP Tracker** — Score, monitor, and block malicious IP addresses
- **Security Analytics** — Interactive Chart.js charts (login trends, severity distribution, top IPs)
- **Report Export** — Download security events and alerts as CSV files
- **Role-Based Access** — Admin and Analyst roles with session management
- **Secure by Default** — PBKDF2 password hashing, CSRF protection, SQL injection prevention

---

## 🖥️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask 3 |
| Database | SQLite + SQLAlchemy |
| Frontend | HTML5, CSS3, JavaScript, Chart.js |
| Auth | Werkzeug PBKDF2, Flask-WTF CSRF |
| Parsing | Python regex (auth.log) |

---

## 🚀 Quick Start (macOS / Linux)

### 1. Clone / unzip the project

```bash
cd securewatch
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. (Optional) Set a secret key

```bash
cp .env.example .env
# Edit .env and set a strong SECRET_KEY
```

### 5. Run the application

```bash
python app.py
```

The app starts at **http://localhost:5000**

---

## 🔑 Demo Login Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@1234` |
| Analyst | `analyst` | `Analyst@1234` |

---

## 📁 Project Structure

```
securewatch/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── generate_sample_log.py    # Sample auth.log generator
├── .env.example              # Environment variable template
├── templates/
│   ├── base_public.html      # Public page layout
│   ├── base_dashboard.html   # Dashboard layout with sidebar
│   ├── index.html            # Landing page
│   ├── login.html            # Authentication page
│   ├── about.html            # About page
│   ├── contact.html          # Contact page
│   └── dashboard/
│       ├── main.html         # Main security overview
│       ├── threats.html      # Threat alert management
│       ├── login_activity.html  # Login event log
│       ├── suspicious_ips.html  # IP tracker
│       ├── reports.html      # Report exports
│       └── settings.html     # Settings & log parser
├── static/
│   ├── css/style.css         # Complete UI design system
│   └── js/dashboard.js       # Charts, live refresh, UI logic
├── logs/                     # Log files directory
└── reports/                  # Exported reports directory
```

---

## 🪵 Log Parsing

SecureWatch can parse real Linux auth logs:

```bash
# macOS (uses /var/log/system.log — adjust path)
# Linux:
sudo cp /var/log/auth.log logs/auth.log
```

Then in the Dashboard → **Settings** → **Parse Log File** → enter the path.

To generate a realistic sample log for testing:

```bash
python generate_sample_log.py
```

This creates `logs/sample_auth.log` with 500 simulated events. Import it via Settings.

---

## 🔐 Security Features

- Passwords hashed with **PBKDF2-SHA256** via Werkzeug
- **CSRF tokens** on all forms (Flask-WTF)
- **Session signing** with server-side secret key
- **SQL injection prevention** via SQLAlchemy parameterized queries
- Input validation on all endpoints
- Role-based route protection (admin vs analyst)

---

## 📊 Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| Overview | `/dashboard` | Stats, charts, recent events |
| Threats | `/dashboard/threats` | Alert list with resolve workflow |
| Login Activity | `/dashboard/login-activity` | Full authentication log |
| Suspicious IPs | `/dashboard/suspicious-ips` | IP scoring and blocking |
| Reports | `/dashboard/reports` | CSV export |
| Settings | `/dashboard/settings` | Log parser, password, data management |

---

## 🌐 Deployment

### Render / Railway

1. Add `gunicorn` to requirements.txt
2. Set `SECRET_KEY` as an environment variable
3. Start command: `gunicorn app:app`

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

---

## 🔮 Future Enhancements

- [ ] Email / Telegram alerts on new critical threats
- [ ] Live log streaming via WebSockets (Flask-SocketIO)
- [ ] GeoIP mapping of attacking IPs (ip-api.com)
- [ ] PDF report generation (ReportLab / WeasyPrint)
- [ ] JWT API authentication for REST endpoints
- [ ] AI anomaly detection (isolation forest)
- [ ] Multi-server log aggregation
- [ ] Log retention and archiving policies

---

## 📄 License

MIT License — free to use for personal projects, portfolios, and internship demonstrations.

---

*SecureWatch — Built for cybersecurity portfolios and SOC engineering demonstrations.*
