import os
import csv
import json
import random
import re
import io
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, redirect, url_for, request,
    session, flash, jsonify, Response, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securewatch-dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securewatch.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# ─────────────────────────── Models ───────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='analyst')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45))
    username = db.Column(db.String(80))
    hostname = db.Column(db.String(120))
    message = db.Column(db.Text)
    severity = db.Column(db.String(20), default='low')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    raw_log = db.Column(db.Text)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(80))
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    service = db.Column(db.String(50), default='ssh')
    hostname = db.Column(db.String(120))


class ThreatAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(80), nullable=False)
    source_ip = db.Column(db.String(45))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default='medium')
    is_resolved = db.Column(db.Boolean, default=False)
    triggered_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)


class SuspiciousIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked = db.Column(db.Boolean, default=False)
    country = db.Column(db.String(50), default='Unknown')
    threat_score = db.Column(db.Integer, default=0)


class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), default='info')
    message = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────── Auth helpers ─────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access the dashboard.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────── Log parser ───────────────────────

FAILED_PATTERNS = [
    re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+).*user=(\S+)'),
]
SUCCESS_PATTERN = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)')
TIMESTAMP_PATTERN = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)')

BRUTE_THRESHOLD = 5


def parse_log_line(line):
    m = TIMESTAMP_PATTERN.match(line)
    if not m:
        return None
    ts_str, hostname, rest = m.groups()
    year = datetime.utcnow().year
    try:
        ts = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        ts = datetime.utcnow()

    for pat in FAILED_PATTERNS:
        fm = pat.search(rest)
        if fm:
            groups = fm.groups()
            username = groups[0] if len(groups) >= 2 else 'unknown'
            ip = groups[1] if len(groups) >= 2 else groups[0]
            return {'type': 'failed', 'username': username, 'ip': ip,
                    'hostname': hostname, 'timestamp': ts, 'raw': line}

    sm = SUCCESS_PATTERN.search(rest)
    if sm:
        username, ip = sm.groups()
        return {'type': 'success', 'username': username, 'ip': ip,
                'hostname': hostname, 'timestamp': ts, 'raw': line}
    return None


def process_log_file(path):
    if not os.path.exists(path):
        return 0
    counts = 0
    ip_fails = defaultdict(int)
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                event = parse_log_line(line.strip())
                if not event:
                    continue
                attempt = LoginAttempt(
                    ip_address=event['ip'],
                    username=event['username'],
                    success=(event['type'] == 'success'),
                    timestamp=event['timestamp'],
                    hostname=event['hostname'],
                )
                db.session.add(attempt)
                if event['type'] == 'failed':
                    ip_fails[event['ip']] += 1
                    sev = 'medium'
                    ev = SecurityEvent(
                        event_type='failed_login',
                        source_ip=event['ip'],
                        username=event['username'],
                        hostname=event['hostname'],
                        message=f"Failed login for {event['username']}",
                        severity=sev,
                        timestamp=event['timestamp'],
                        raw_log=line.strip(),
                    )
                    db.session.add(ev)
                counts += 1
        db.session.commit()

        for ip, fails in ip_fails.items():
            sip = SuspiciousIP.query.filter_by(ip_address=ip).first()
            if sip:
                sip.failed_attempts += fails
                sip.last_seen = datetime.utcnow()
                sip.threat_score = min(100, sip.failed_attempts * 5)
            else:
                sip = SuspiciousIP(
                    ip_address=ip,
                    failed_attempts=fails,
                    threat_score=min(100, fails * 5),
                )
                db.session.add(sip)
            if fails >= BRUTE_THRESHOLD:
                alert = ThreatAlert(
                    alert_type='Brute Force Attack',
                    source_ip=ip,
                    description=f"{fails} failed login attempts from {ip}",
                    severity='critical' if fails > 20 else 'high' if fails > 10 else 'medium',
                )
                db.session.add(alert)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Log parse error: {e}")
    return counts


# ─────────────────────────── Routes: Public ───────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active:
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ─────────────────────────── Dashboard ────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    total_attempts = LoginAttempt.query.count()
    failed_attempts = LoginAttempt.query.filter_by(success=False).count()
    success_attempts = LoginAttempt.query.filter_by(success=True).count()
    active_alerts = ThreatAlert.query.filter_by(is_resolved=False).count()
    suspicious_ips = SuspiciousIP.query.count()
    critical_alerts = ThreatAlert.query.filter_by(severity='critical', is_resolved=False).count()
    recent_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(15).all()
    recent_alerts = ThreatAlert.query.filter_by(is_resolved=False).order_by(ThreatAlert.triggered_at.desc()).limit(5).all()
    top_ips = SuspiciousIP.query.order_by(SuspiciousIP.failed_attempts.desc()).limit(5).all()

    # Chart data — last 7 days
    labels, failed_data, success_data = [], [], []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        labels.append(day.strftime('%b %d'))
        failed_data.append(LoginAttempt.query.filter(
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= start,
            LoginAttempt.timestamp < end
        ).count())
        success_data.append(LoginAttempt.query.filter(
            LoginAttempt.success == True,
            LoginAttempt.timestamp >= start,
            LoginAttempt.timestamp < end
        ).count())

    severity_counts = {
        'critical': ThreatAlert.query.filter_by(severity='critical').count(),
        'high': ThreatAlert.query.filter_by(severity='high').count(),
        'medium': ThreatAlert.query.filter_by(severity='medium').count(),
        'low': ThreatAlert.query.filter_by(severity='low').count(),
    }

    return render_template('dashboard/main.html',
        total_attempts=total_attempts,
        failed_attempts=failed_attempts,
        success_attempts=success_attempts,
        active_alerts=active_alerts,
        suspicious_ips=suspicious_ips,
        critical_alerts=critical_alerts,
        recent_events=recent_events,
        recent_alerts=recent_alerts,
        top_ips=top_ips,
        chart_labels=json.dumps(labels),
        chart_failed=json.dumps(failed_data),
        chart_success=json.dumps(success_data),
        severity_counts=json.dumps(severity_counts),
    )


@app.route('/dashboard/threats')
@login_required
def threats():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    resolved = request.args.get('resolved', '')
    q = ThreatAlert.query
    if severity:
        q = q.filter_by(severity=severity)
    if resolved == '0':
        q = q.filter_by(is_resolved=False)
    elif resolved == '1':
        q = q.filter_by(is_resolved=True)
    alerts = q.order_by(ThreatAlert.triggered_at.desc()).paginate(page=page, per_page=20)
    return render_template('dashboard/threats.html', alerts=alerts, severity=severity, resolved=resolved)


@app.route('/dashboard/threats/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    alert = ThreatAlert.query.get_or_404(alert_id)
    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    flash('Alert resolved.', 'success')
    return redirect(url_for('threats'))


@app.route('/dashboard/login-activity')
@login_required
def login_activity():
    page = request.args.get('page', 1, type=int)
    search_ip = request.args.get('ip', '')
    search_user = request.args.get('username', '')
    success_filter = request.args.get('success', '')
    q = LoginAttempt.query
    if search_ip:
        q = q.filter(LoginAttempt.ip_address.contains(search_ip))
    if search_user:
        q = q.filter(LoginAttempt.username.contains(search_user))
    if success_filter == '1':
        q = q.filter_by(success=True)
    elif success_filter == '0':
        q = q.filter_by(success=False)
    attempts = q.order_by(LoginAttempt.timestamp.desc()).paginate(page=page, per_page=25)
    return render_template('dashboard/login_activity.html',
        attempts=attempts, search_ip=search_ip, search_user=search_user, success_filter=success_filter)


@app.route('/dashboard/suspicious-ips')
@login_required
def suspicious_ips():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '')
    q = SuspiciousIP.query
    if search:
        q = q.filter(SuspiciousIP.ip_address.contains(search))
    ips = q.order_by(SuspiciousIP.threat_score.desc()).paginate(page=page, per_page=20)
    return render_template('dashboard/suspicious_ips.html', ips=ips, search=search)


@app.route('/dashboard/suspicious-ips/<int:ip_id>/block', methods=['POST'])
@login_required
def block_ip(ip_id):
    sip = SuspiciousIP.query.get_or_404(ip_id)
    sip.is_blocked = not sip.is_blocked
    db.session.commit()
    state = 'blocked' if sip.is_blocked else 'unblocked'
    flash(f'IP {sip.ip_address} has been {state}.', 'success')
    return redirect(url_for('suspicious_ips'))


@app.route('/dashboard/reports')
@login_required
def reports():
    total_events = SecurityEvent.query.count()
    total_alerts = ThreatAlert.query.count()
    unresolved_alerts = ThreatAlert.query.filter_by(is_resolved=False).count()
    total_ips = SuspiciousIP.query.count()
    blocked_ips = SuspiciousIP.query.filter_by(is_blocked=True).count()
    return render_template('dashboard/reports.html',
        total_events=total_events,
        total_alerts=total_alerts,
        unresolved_alerts=unresolved_alerts,
        total_ips=total_ips,
        blocked_ips=blocked_ips,
    )


@app.route('/dashboard/reports/export/csv')
@login_required
def export_csv():
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Event Type', 'Source IP', 'Username', 'Severity', 'Timestamp', 'Message'])
    for e in events:
        writer.writerow([e.id, e.event_type, e.source_ip, e.username,
                         e.severity, e.timestamp.strftime('%Y-%m-%d %H:%M:%S'), e.message])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=securewatch_events_{datetime.utcnow().strftime("%Y%m%d")}.csv'}
    )


@app.route('/dashboard/reports/export/alerts-csv')
@login_required
def export_alerts_csv():
    alerts = ThreatAlert.query.order_by(ThreatAlert.triggered_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Alert Type', 'Source IP', 'Severity', 'Resolved', 'Triggered At', 'Description'])
    for a in alerts:
        writer.writerow([a.id, a.alert_type, a.source_ip, a.severity,
                         'Yes' if a.is_resolved else 'No',
                         a.triggered_at.strftime('%Y-%m-%d %H:%M:%S'), a.description])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=securewatch_alerts_{datetime.utcnow().strftime("%Y%m%d")}.csv'}
    )


@app.route('/dashboard/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            current = request.form.get('current_password')
            new_pw = request.form.get('new_password')
            confirm = request.form.get('confirm_password')
            if not user.check_password(current):
                flash('Current password is incorrect.', 'danger')
            elif new_pw != confirm:
                flash('New passwords do not match.', 'danger')
            elif len(new_pw) < 8:
                flash('Password must be at least 8 characters.', 'danger')
            else:
                user.set_password(new_pw)
                db.session.commit()
                flash('Password updated successfully.', 'success')
        elif action == 'parse_logs':
            log_path = request.form.get('log_path', '/var/log/auth.log')
            count = process_log_file(log_path)
            flash(f'Parsed {count} log entries from {log_path}.', 'success')
        elif action == 'generate_sample':
            generate_sample_data()
            flash('Sample security data generated successfully.', 'success')
        elif action == 'clear_data':
            if user.role == 'admin':
                LoginAttempt.query.delete()
                SecurityEvent.query.delete()
                ThreatAlert.query.delete()
                SuspiciousIP.query.delete()
                db.session.commit()
                flash('All security data cleared.', 'warning')
            else:
                flash('Admin privileges required.', 'danger')
    return render_template('dashboard/settings.html', user=user)


# ─────────────────────────── API endpoints ────────────────────

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify({
        'total_attempts': LoginAttempt.query.count(),
        'failed': LoginAttempt.query.filter_by(success=False).count(),
        'success': LoginAttempt.query.filter_by(success=True).count(),
        'active_alerts': ThreatAlert.query.filter_by(is_resolved=False).count(),
        'suspicious_ips': SuspiciousIP.query.count(),
        'timestamp': datetime.utcnow().isoformat(),
    })


@app.route('/api/chart/daily')
@login_required
def api_chart_daily():
    labels, failed_data, success_data = [], [], []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        labels.append(day.strftime('%b %d'))
        failed_data.append(LoginAttempt.query.filter(
            LoginAttempt.success == False,
            LoginAttempt.timestamp >= start,
            LoginAttempt.timestamp < end
        ).count())
        success_data.append(LoginAttempt.query.filter(
            LoginAttempt.success == True,
            LoginAttempt.timestamp >= start,
            LoginAttempt.timestamp < end
        ).count())
    return jsonify({'labels': labels, 'failed': failed_data, 'success': success_data})


@app.route('/api/recent-events')
@login_required
def api_recent_events():
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(10).all()
    return jsonify([{
        'id': e.id,
        'type': e.event_type,
        'ip': e.source_ip,
        'user': e.username,
        'severity': e.severity,
        'time': e.timestamp.strftime('%H:%M:%S'),
        'message': e.message,
    } for e in events])


# ─────────────────────────── Sample data ──────────────────────

SAMPLE_IPS = [
    ('185.220.101.42', 'Russia'), ('103.224.182.201', 'China'),
    ('45.142.212.100', 'Germany'), ('192.168.1.105', 'Local'),
    ('10.0.0.55', 'Local'), ('62.171.160.10', 'Netherlands'),
    ('89.248.167.131', 'Netherlands'), ('198.235.24.145', 'United States'),
    ('222.186.160.77', 'China'), ('91.240.118.172', 'Ukraine'),
    ('179.60.150.34', 'Brazil'), ('5.188.86.172', 'Russia'),
]
SAMPLE_USERS = ['root', 'admin', 'ubuntu', 'pi', 'user1', 'deploy', 'git', 'postgres', 'mysql', 'oracle']


def generate_sample_data():
    now = datetime.utcnow()
    ip_fail_counts = defaultdict(int)

    for i in range(300):
        ip, country = random.choice(SAMPLE_IPS)
        username = random.choice(SAMPLE_USERS)
        success = random.random() < 0.08
        ts = now - timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )
        attempt = LoginAttempt(
            ip_address=ip, username=username, success=success,
            timestamp=ts, service='ssh', hostname='web-server-01',
        )
        db.session.add(attempt)
        if not success:
            ip_fail_counts[(ip, country)] += 1
            ev = SecurityEvent(
                event_type='failed_login', source_ip=ip, username=username,
                hostname='web-server-01',
                message=f"Failed SSH login for '{username}' from {ip}",
                severity=random.choice(['low', 'medium', 'medium', 'high']),
                timestamp=ts,
                raw_log=f"{ts.strftime('%b %d %H:%M:%S')} web-server-01 sshd[1234]: Failed password for {username} from {ip} port 22 ssh2",
            )
            db.session.add(ev)

    db.session.commit()

    for (ip, country), fails in ip_fail_counts.items():
        sip = SuspiciousIP.query.filter_by(ip_address=ip).first()
        if sip:
            sip.failed_attempts += fails
            sip.threat_score = min(100, sip.failed_attempts * 4)
            sip.country = country
        else:
            sip = SuspiciousIP(
                ip_address=ip, failed_attempts=fails,
                threat_score=min(100, fails * 4), country=country,
            )
            db.session.add(sip)

        if fails >= BRUTE_THRESHOLD:
            existing = ThreatAlert.query.filter_by(source_ip=ip, is_resolved=False).first()
            if not existing:
                sev = 'critical' if fails > 30 else 'high' if fails > 15 else 'medium'
                alert = ThreatAlert(
                    alert_type='Brute Force Attack',
                    source_ip=ip,
                    description=f"Detected {fails} failed login attempts from {ip} ({country})",
                    severity=sev,
                )
                db.session.add(alert)

    for i in range(8):
        ip, country = random.choice(SAMPLE_IPS)
        t = random.choice(['Port Scan Detected', 'Privilege Escalation', 'Sudo Abuse', 'Account Lockout'])
        s = random.choice(['medium', 'high', 'critical'])
        alert = ThreatAlert(
            alert_type=t, source_ip=ip,
            description=f"{t} detected from {ip} ({country})",
            severity=s,
            is_resolved=random.random() < 0.3,
        )
        db.session.add(alert)

    db.session.commit()


# ─────────────────────────── Init ─────────────────────────────

def create_default_users():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@securewatch.local', role='admin')
        admin.set_password('Admin@1234')
        db.session.add(admin)
    if not User.query.filter_by(username='analyst').first():
        analyst = User(username='analyst', email='analyst@securewatch.local', role='analyst')
        analyst.set_password('Analyst@1234')
        db.session.add(analyst)
    db.session.commit()


with app.app_context():
    db.create_all()
    create_default_users()
    if LoginAttempt.query.count() == 0:
        generate_sample_data()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
