"""
Generate a realistic sample /var/log/auth.log file for testing SecureWatch.
Run: python generate_sample_log.py
Output: logs/sample_auth.log
"""
import random
import os
from datetime import datetime, timedelta

ATTACKING_IPS = [
    '185.220.101.42', '103.224.182.201', '45.142.212.100',
    '62.171.160.10', '89.248.167.131', '222.186.160.77',
    '91.240.118.172', '179.60.150.34', '5.188.86.172',
]
LEGIT_IPS = ['192.168.1.105', '10.0.0.55', '198.235.24.145']
USERNAMES = ['root', 'admin', 'ubuntu', 'pi', 'user1', 'deploy', 'git', 'postgres', 'oracle']
LEGIT_USERS = ['ubuntu', 'deploy']
HOSTNAME = 'web-server-01'
SERVICES = ['sshd', 'sudo', 'su']

def fmt_time(dt):
    return dt.strftime('%b %d %H:%M:%S').replace(' 0', '  ') if dt.day < 10 else dt.strftime('%b %d %H:%M:%S')

def generate_logs(n=500):
    lines = []
    now = datetime.now()

    for i in range(n):
        ts = now - timedelta(days=random.randint(0, 6),
                             hours=random.randint(0, 23),
                             minutes=random.randint(0, 59),
                             seconds=random.randint(0, 59))
        t = fmt_time(ts)
        pid = random.randint(10000, 65000)

        kind = random.choices(['brute', 'legit', 'invalid', 'misc'], weights=[55, 15, 20, 10])[0]

        if kind == 'brute':
            ip = random.choice(ATTACKING_IPS)
            user = random.choice(USERNAMES)
            lines.append(f"{t} {HOSTNAME} sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(1024,65000)} ssh2")

        elif kind == 'invalid':
            ip = random.choice(ATTACKING_IPS)
            user = f"user{random.randint(1,999)}"
            lines.append(f"{t} {HOSTNAME} sshd[{pid}]: Invalid user {user} from {ip} port {random.randint(1024,65000)}")

        elif kind == 'legit':
            ip = random.choice(LEGIT_IPS)
            user = random.choice(LEGIT_USERS)
            lines.append(f"{t} {HOSTNAME} sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(1024,65000)} ssh2")

        else:
            ip = random.choice(ATTACKING_IPS)
            lines.append(f"{t} {HOSTNAME} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user=root")

    lines.sort()
    return lines

if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    logs = generate_logs(500)
    path = os.path.join('logs', 'sample_auth.log')
    with open(path, 'w') as f:
        f.write('\n'.join(logs))
    print(f"Generated {len(logs)} log lines → {path}")
    print("To import into SecureWatch: go to Settings → Parse Log File → enter: logs/sample_auth.log")
