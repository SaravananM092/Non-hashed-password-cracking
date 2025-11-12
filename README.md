# bruteforce-login-demo

This repository intentionally contains an authentication exercise intended for controlled, local testing and defensive learning. All insecure configurations (for example disabled rate limits or permissive settings) exist solely to support instructor-led labs and CTF practice on a local machine or isolated VM. Do not deploy this code on public networks or use it against systems you do not own or have explicit permission to test. Before performing any tests, ensure your environment is isolated, obtain written authorization, and follow responsible disclosure practices. The project is provided for learning how authentication can fail and how to properly mitigate such failures.

# Development / runtime

Python 3 — runtime for the Flask app.
Flask — web framework used by the project.
SQLite — lightweight local database used for storing users and logs.
bcrypt — secure password hashing library used for credential storage.
pip / virtualenv — dependency management and isolated environments.

# Project tooling / debugging

sqlite3 / DB Browser for SQLite — inspect and manage the local DB during tests.
Git — version control for the project.
VS Code / Vim / nano — editors commonly used to view and edit files.

# Passive / analysis tools (safe for lab)

Burp Suite (Community or Professional) — proxy/interceptor for inspecting HTTP(S) traffic and learning about requests/responses. (Use only in local lab.)
OWASP ZAP — alternative proxy and security testing tool for learning.
Wireshark / tcpdump — packet capture and network analysis (useful when learning about session traffic).
Browser devtools (Chrome/Firefox) — inspect HTML, JS, cookies, and network activity.

# Educational / training platforms (safe alternatives)

OWASP Juice Shop / DVWA / WebGoat — intentionally vulnerable apps for practicing in a controlled environment (recommended instead of attacking production apps).

# (Optional, with strong caution) Offensive tools you may mention only for lab contexts

Hydra / Medusa / Burp Intruder — automated password-guessing tools. Only mention if explicitly stating “for authorized lab use only”; do not include usage instructions or parameters in public docs.

I strongly recommend preferring controlled training platforms (Juice Shop/DVWA) over raw brute-force tools.

#run this line by line

**1)**`sudo apt update
sudo apt install -y unzip python3 
python3-venv python3-pip sqlite3 build-essential libssl-dev libffi-dev python3-dev
`

**2)**# adjust path to your zip file`
unzip /path/to/secure_login.zip -d ~/projects
cd ~/projects/secure_login
ls -la
`

**3)**`python3 -m venv .venv
source .venv/bin/activate
`

**4)**`pip install --upgrade pip
pip install -r requirements.txt
`

**5)**`pip install bcrypt`

**6)**`sqlite3 app.db < schema.sql`

**7)**`python3 create_admin.py admin StrongPass123`

**8)**`python3 app.py`

**9)**` * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)`

**10)** # Open a browser on the Kali machine and go to:
`http://127.0.0.1:5000/login`

**10)** <ins> catch the login(GET) request and sent to intruder and brute force the username or password
       by your own common password list. </ins> 

















