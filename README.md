# 🕵️ DeepDecoy – Adaptive AI-Powered Honeypot

DeepDecoy is a safe, adaptive AI honeypot for SSH and Web. It simulates services using GPT or deterministic offline logic, logs attacker behavior, learns which personas work best, and includes a local dashboard for insights.

Key features:
- AI-driven SSH and Web responses (safe: no real commands)
- Multi-persona deception with adaptive switching
- Structured session logging + AI threat summaries
- Learning engine biases future persona choices
- Optional dashboard for metrics, sessions, and personas

[![CI](https://github.com/ibrahimkh99/DeepDecoy-Adaptive-AI-Powered-Honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/ibrahimkh99/DeepDecoy-Adaptive-AI-Powered-Honeypot/actions/workflows/ci.yml)

## Quick Start

```powershell
git clone https://github.com/ibrahimkh99/DeepDecoy-Adaptive-AI-Powered-Honeypot.git
cd DeepDecoy-Adaptive-AI-Powered-Honeypot
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# edit .env: set OPENAI_API_KEY, or set DEEPDECOY_DISABLE_OPENAI=true for offline
python main.py
```

Services:
- SSH: `localhost:2222` (change via `.env`)
- Web: `http://localhost:8080` (enable via `.env`)

## Offline Mode

Set `DEEPDECOY_DISABLE_OPENAI=true` in `.env` to use deterministic responses and heuristic persona switching. Ideal for local dev and CI.

## Learning & Dashboard

Populate metrics from logs:
```powershell
python learning_engine.py
# or
python main.py learn
```

Start the dashboard:
```powershell
python dashboard.py
# Open http://127.0.0.1:5000/ (or set DASHBOARD_PORT)
```

## Configuration

Edit `.env`:
- `OPENAI_API_KEY`: API key for GPT (omit if offline)
- `DEEPDECOY_DISABLE_OPENAI`: `true` for offline mode
- `SSH_PORT`, `SSH_HOST`, `HOSTNAME`, `USERNAME`: SSH settings
- `ENABLE_WEB`, `WEB_PORT`, `WEB_HOST`: Web settings
- `DECEPTION_EVAL_INTERVAL`, `INITIAL_PERSONA`: Deception engine
- `ENABLE_DASHBOARD`, `DASHBOARD_PORT`: Dashboard settings
- `USE_SQLITE`, `LEARNING_DB_PATH`: Learning storage

## Testing

Run tests in offline mode:
```powershell
$env:DEEPDECOY_DISABLE_OPENAI = "true"
pytest -q
```

Lint:
```powershell
flake8 . --max-line-length=120 --statistics
```

Focused tests (examples):
- `deception_engine.py`: heuristic triggers and weight bias
- `learning_engine.py`: log parsing and strategy updates
- `ai_shell.py` and `web_ai_responder.py`: deterministic outputs

## Troubleshooting

- Slow replies: switch model via `OPENAI_MODEL` or use offline
- Port conflicts: change `SSH_PORT`/`WEB_PORT` or free ports
- Windows SSH test: `ssh any@localhost -p 2222`
- Connectivity errors: verify firewall and that ports are free

## Project Structure

```
DeepDecoy/
├── main.py                    # Entry point (SSH + Web + Deception + CLI)
├── ai_shell.py                # SSH responses (AI/offline)
├── web_ai_responder.py        # Web responses (AI/offline)
├── web_server.py              # Flask web server
├── deception_engine.py        # Adaptive persona logic + learned bias
├── personas.py                # Persona definitions
├── session_logger.py          # JSON + text session logs
├── learning_engine.py         # Metrics + strategy weights (SQLite/JSON)
├── dashboard.py               # Overview, sessions, personas
├── analyzer.py                # Threat summaries
├── config.py                  # Config loader
├── .env.example               # Template for .env
├── requirements.txt           # Dependencies
├── logs/                      # SSH session logs
│   ├── session_*.json         # Structured logs (learning input)
│   ├── session_*.txt          # Human-readable logs
│   └── session_*.summary.txt  # AI threat reports
├── logs/web/                  # Web request logs
└── prompts/                   # Prompt templates
```

## Security & Safety

- No real commands executed; outputs are simulated
- Keep secrets only in local `.env`; never commit
- Do not expose services publicly without controls

## Contributing

PRs welcome for personas, prompts, tests, and docs. See `CONTRIBUTING.md` and `SECURITY.md`.

---

## 🔌 Connecting to the Honeypots

### SSH Honeypot

From another terminal or machine, connect using any SSH client:

```bash
ssh anyusername@localhost -p 2222
```

- **Username**: Any username (all accepted)
- **Password**: Any password (all accepted)

Once connected, you'll see a realistic Ubuntu terminal and can type commands like:
- `ls`, `cd`, `pwd`
- `cat /etc/passwd`
- `ps aux`
- `whoami`, `uname -a`
- `ifconfig`, `netstat`

Everything is simulated by AI!

### Web Honeypot

The web honeypot responds to HTTP requests on port 8080 (or configured port).

**Example requests:**

```bash
# Login page - returns AI-generated HTML
curl http://localhost:8080/login

# Admin panel - returns fake admin interface
curl http://localhost:8080/admin

# API endpoint - returns AI-generated JSON
curl http://localhost:8080/api/users

# Any path works - AI generates appropriate responses
curl http://localhost:8080/config.php
curl http://localhost:8080/.env
curl http://localhost:8080/phpmyadmin
```

**Example AI-generated web response:**
```html
<!DOCTYPE html>
<html>
<head><title>Login - DeepDecoy Corp</title></head>
<body>
  <h1>Employee Login Portal</h1>
  <form action="/auth" method="post">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
</body>
</html>
```

**Example AI-generated API response:**
```json
{
  "users": [
    {"id": 1, "username": "admin", "role": "administrator"},
    {"id": 2, "username": "john.doe", "role": "developer"},
    {"id": 3, "username": "jane.smith", "role": "analyst"}
  ],
  "total": 3,
  "page": 1
}
```

All web responses are dynamically generated by GPT-4 to appear realistic and enticing to attackers!

---

## 📋 Example Session Logs & Learning Metrics
### Persona Transition Snippet (SSH Session)
```json
{
  "session_id": "abc12345-6789-def0-1112-131415161718",
  "initial_persona": "Linux Dev Server",
  "persona_metadata": {"os": "Ubuntu 20.04", "services": ["ssh", "http"]},
  "deception_transitions": [
    {
      "timestamp": "2025-11-30T10:22:41Z",
      "previous": "Linux Dev Server",
      "new": "MySQL Backend",
      "reason": "Detected DB probing",
      "modules": ["ssh", "web", "db"]
    },
    {
      "timestamp": "2025-11-30T10:24:03Z",
      "previous": "MySQL Backend",
      "new": "IoT Hub",
      "reason": "Frequent access to /firmware and device-like paths",
      "modules": ["ssh", "web"]
    }
  ]
}
```

During the session, the deception engine evaluated behavior every 3 interactions and shifted personas when attacker intent indicators appeared (e.g., SQL-related commands, firmware route probes). Each shift updated shell response style and web content.

After multiple sessions, the **learning engine** aggregates:
- `engagement_score` = commands + HTTP requests (+ tiny duration factor)
- `threat_score` = suspicious_score + high-risk tag bonuses
- Persona effectiveness weights updated via: `new_weight = DECAY * old + ALPHA * metric`

SQLite tables:
```
sessions_metrics(session_id, engagement_score, threat_score, ...)
persona_effectiveness(session_id, persona_name, time_spent_seconds, command_count, http_count)
persona_strategy(persona_name, engagement_weight, threat_weight, usage_count)
```


When someone connects, DeepDecoy creates three log files:

### JSON Log (`session_20240327_143052_192_168_1_50_a1b2c3d4.json`)
```json
{
  "session_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "client_ip": "192.168.1.50",
  "username": "admin",
  "start_time": "2024-03-27T14:30:52",
  "end_time": "2024-03-27T14:35:18",
  "duration_seconds": 266,
  "total_commands": 8,
  "threat_tags": ["recon", "privilege_escalation", "file_access"],
  "suspicious_score": 5,
  "threat_level": "HIGH",
  "session_summary": "The attacker conducted systematic reconnaissance...",
  "commands": [
    {
      "timestamp": "2024-03-27T14:31:05",
      "command": "whoami",
      "output": "ubuntu",
      "category": "system_info",
      "command_length": 6,
      "output_length": 6
    },
    {
      "timestamp": "2024-03-27T14:31:12",
      "command": "ls -la",
      "output": "total 48\ndrwxr-xr-x 5 ubuntu ubuntu 4096 Mar 27 14:20 .\ndrwxr-xr-x 3 root   root   4096 Jan 15 10:30 ..\n-rw------- 1 ubuntu ubuntu  220 Jan 15 10:30 .bash_logout\n-rw------- 1 ubuntu ubuntu 3771 Jan 15 10:30 .bashrc\ndrwx------ 2 ubuntu ubuntu 4096 Mar 20 09:15 .cache\ndrwxr-xr-x 3 ubuntu ubuntu 4096 Feb 10 11:45 .local\n-rw------- 1 ubuntu ubuntu  807 Jan 15 10:30 .profile\ndrwxr-xr-x 2 ubuntu ubuntu 4096 Mar 27 13:50 Documents",
      "category": "file_access",
      "command_length": 6,
      "output_length": 387
    }
  ]
}
```

### Text Log (`session_20240327_143052_192_168_1_50_a1b2c3d4.txt`)
```
================================================================================
DEEPDECOY HONEYPOT SESSION LOG
================================================================================

Session ID:    a1b2c3d4-5678-90ab-cdef-1234567890ab
Client IP:     192.168.1.50
Username:      admin
Start Time:    2024-03-27 14:30:52
End Time:      2024-03-27 14:35:18
Duration:      266.0 seconds
Total Commands: 8

================================================================================
COMMAND HISTORY
================================================================================

[1] 14:31:05 [system_info]
>>> whoami
ubuntu

--------------------------------------------------------------------------------

[2] 14:31:12 [file_access]
>>> ls -la
total 48
drwxr-xr-x 5 ubuntu ubuntu 4096 Mar 27 14:20 .
drwxr-xr-x 3 root   root   4096 Jan 15 10:30 ..
-rw------- 1 ubuntu ubuntu  220 Jan 15 10:30 .bash_logout
...

================================================================================
SESSION STATISTICS
================================================================================

Commands by category:
  file_access: 4
  system_info: 2
  network_probe: 1
  privilege_escalation: 1

================================================================================
THREAT ANALYSIS (AI-POWERED)
================================================================================

Threat Level:      HIGH
Suspicious Score:  5
Threat Tags:       recon, privilege_escalation, file_access

AI Security Summary:
--------------------------------------------------------------------------------
The attacker conducted systematic reconnaissance followed by privilege 
escalation attempts. Commands indicate intermediate-level expertise with 
targeted file access to sensitive credentials. Recommend monitoring for 
similar patterns in production systems.
```

### AI Threat Report (`session_20240327_143052_192_168_1_50_a1b2c3d4.summary.txt`)
```
================================================================================
DEEPDECOY THREAT INTELLIGENCE REPORT
================================================================================

Session ID:        a1b2c3d4-5678-90ab-cdef-1234567890ab
Client IP:         192.168.1.50
Username:          admin
Threat Level:      HIGH
Suspicious Score:  5
Threat Tags:       recon, privilege_escalation, file_access
Flagged Commands:  4 of 8

================================================================================
AI SECURITY ASSESSMENT
================================================================================

The attacker demonstrated intermediate-level reconnaissance capabilities,
beginning with system enumeration (whoami, uname) before progressing to
targeted file access. The session exhibited clear indicators of credential
harvesting attempts through access to /etc/passwd and privilege escalation
via sudo commands.

The attack pattern suggests automated tooling or scripted reconnaissance
rather than manual exploration. The systematic progression from basic
enumeration to privilege escalation indicates prior knowledge of Linux
systems and common attack vectors.

Threat Level: HIGH - While the honeypot prevented actual compromise, this
session represents a credible threat that would require immediate response
in a production environment. Recommend monitoring for similar IP patterns
and updating detection signatures accordingly.
```

---

## 🔍 Threat Intelligence Features

DeepDecoy provides automated threat analysis:

### Automatic Threat Detection
- **7 Threat Categories**: recon, exploit, privilege_escalation, file_access, data_exfil, persistence, lateral_movement
- **Suspicious Scoring**: Numeric score based on high-risk commands
- **Threat Levels**: LOW, MEDIUM, HIGH, or CRITICAL ratings

### AI-Powered Summaries
After each session, GPT-4 generates:
- Attacker objectives and techniques
- Tools and methods identified
- Sophistication assessment
- Actionable security recommendations

### Pattern Recognition
Detects known attack tools and techniques:
- Scanning: nmap, netstat, ifconfig
- Exploitation: sqlmap, metasploit, hydra
- Privilege escalation: sudo, passwd, /etc/shadow
- Data exfiltration: wget, curl, nc, base64
- Persistence: cron, bashrc, systemctl

---

## ⚙️ Configuration Options

Edit `.env` to customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | *(required)* | Your OpenAI API key |
| `OPENAI_MODEL` | `gpt-4` | Model to use (gpt-4, gpt-3.5-turbo) |
| **SSH Settings** | | |
| `SSH_PORT` | `2222` | Port for SSH server |
| `SSH_HOST` | `0.0.0.0` | Host to bind (0.0.0.0 = all interfaces) |
| `HOSTNAME` | `deepdecoy` | Simulated hostname |
| `USERNAME` | `ubuntu` | Default username shown in prompt |
| **Web Settings** | | |
| `ENABLE_WEB` | `true` | Enable web honeypot service |
| `WEB_PORT` | `8080` | Port for web server |
| `WEB_HOST` | `0.0.0.0` | Host to bind web server |

---

## 🛡️ Security & Safety

### ⚠️ CRITICAL: This is a SIMULATION ONLY

- **NO REAL COMMANDS ARE EXECUTED** - Everything is generated by AI
- **COMPLETELY ISOLATED** - No access to your real system
- **SAFE TO RUN** - Cannot harm your computer or network
- **FOR RESEARCH/EDUCATION** - Study attacker behavior safely
 - **Never commit secrets** - Keep `OPENAI_API_KEY` only in local `.env`.

### Best Practices

1. **Run on an isolated network** or dedicated honeypot server
2. **Don't expose directly to the internet** without proper firewall rules
3. **Monitor your OpenAI API usage** - costs can add up with heavy use
4. **Review logs regularly** for interesting attack patterns
5. **Never use on production systems** - this is a research tool

### Legal Disclaimer

This tool is for **educational and research purposes only**. Ensure you have proper authorization before deploying any honeypot. Monitor local laws regarding honeypot deployment and data collection.

See `SECURITY.md` for operational guidance and disclosure process.

---

## 🎨 Customization

### Modify AI Behavior

**SSH Terminal:**
Edit `prompts/system_prompt.txt` to change how the AI simulates the terminal:
- Make it more or less realistic
- Add specific vulnerabilities (fake)
- Change the simulated OS version
- Adjust personality and verbosity

**Web Responses:**
Edit `prompts/http_web_prompt.txt` for HTML page generation:
- Change the fake organization name
- Adjust page styles and layouts
- Add specific fake services or products

Edit `prompts/http_api_prompt.txt` for JSON API responses:
- Modify data structures
- Change fake user/data schemas
- Adjust API error messages

### Change Welcome Message

Edit `prompts/motd.txt` to customize the login banner.

### Add Command Logging Tags

Edit `ai_shell.py` in the `categorize_command()` method to add more categories.

---

## 🔧 Troubleshooting

### "OPENAI_API_KEY not found"
Create a `.env` file with your API key (see Quick Start).

### "Permission denied" on port 22
Use a high port (like 2222) or run with elevated privileges.

### Slow responses
- Switch to `gpt-3.5-turbo` in `.env` for faster (but less realistic) responses
- Check your network connection to OpenAI

### Connection refused
- Check firewall settings
- Verify the port isn't already in use: `netstat -an | findstr :2222` (Windows)

---

## 📊 Command & Request Categories

DeepDecoy automatically categorizes attacker behavior:

**SSH Commands:**
- **file_access** - ls, cat, cd, find, grep, etc.
- **network_probe** - ping, netstat, ifconfig, nmap, curl, etc.
- **privilege_escalation** - sudo, su, passwd
- **system_info** - whoami, uname, hostname, df, etc.
- **process_management** - ps, kill, top, systemctl, etc.
- **other** - Everything else

**Web Requests:**
- **login_page** - Authentication interfaces
- **admin_panel** - Administrative dashboards
- **config_file** - Configuration file access attempts (.env, config.php, etc.)
- **api_endpoint** - REST API calls
- **exploit_attempt** - Known vulnerability paths (phpMyAdmin, wp-admin, etc.)
- **file_probe** - Sensitive file enumeration
- **other** - General requests

Use these categories to analyze attacker intent and techniques across both protocols.

---

## 📚 Use Cases

- **Cybersecurity Research** - Study attacker techniques safely
- **Education** - Teach honeypot concepts and AI integration
- **Threat Intelligence** - Collect data on attack patterns
- **Demo/Portfolio** - Showcase AI + security skills
- **Prompt Engineering** - Experiment with LLM behavior

---

## 🤝 Contributing

Contributions welcome (see `CONTRIBUTING.md` for full guidelines):
- Report bugs or issues
- Suggest new features
- Improve AI prompts & personas
- Add documentation & samples
- Share interesting sanitized logs
- Add support for new protocols
- Extend persona library / heuristics
- Improve test coverage / CI reliability

Community standards: `CODE_OF_CONDUCT.md`
Security policy: `SECURITY.md`
Architecture overview: `ARCHITECTURE.md`

## 📄 License

MIT License (see `LICENSE`). Provided as-is for educational & research use.

---

## 🙏 Acknowledgments

Built with:
- [Paramiko](https://www.paramiko.org/) - SSH protocol library
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [OpenAI API](https://openai.com/) - GPT-4 language model
- Python 3.10+

---

## 📧 Contact & Community

Questions? Suggestions? Share your DeepDecoy experiences!

**Remember:** This is a FAKE service simulator. No real commands are executed. Stay safe and ethical! 🛡️

---

**DeepDecoy** - Adaptive Multi-Protocol AI Honeypot 🕵️🤖
For licensing see `LICENSE`.
---

## ⚙️ Configuration Options

Additional adaptive deception variables (add to `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DECEPTION_EVAL_INTERVAL` | `3` | Interactions between persona evaluations |
| `INITIAL_PERSONA` | `Linux Dev Server` | Starting persona name (see `personas.py`) |
| `DEEPDECOY_DISABLE_OPENAI` | `false` | Set `true` for offline heuristic-only mode |
| `ENABLE_DASHBOARD` | `false` | Start local dashboard |
| `DASHBOARD_PORT` | `5000` | Dashboard port |
| `USE_SQLITE` | `true` | Use SQLite for learning storage |
| `LEARNING_DB_PATH` | `data/deepdecoy.db` | Learning database location |

Offline mode allows safe local / CI testing without API usage.

## 🎭 Adaptive Deception Personas

Personas are defined in `personas.py`:
- `name`: Identity label
- `prompts`: Overrides for SSH (`ssh`) and Web (`web`)
- `modules`: Informational service/module hints (e.g., `db`, `iot`)
- `metadata`: Descriptive attributes (OS, services, version strings)

Heuristic triggers (offline mode) in `deception_engine._heuristic_fallback()`:
- `sql`, `database` → MySQL Backend
- `firmware`, `device`, `sensor` → IoT Hub
- `admin`, `cms`, `wp-` → Vulnerable Web CMS

Add new persona:
1. Extend `PERSONAS` dict.
2. Provide realistic (fake) metadata & prompts.
3. Add optional heuristic keywords.
4. Test transitions with `DECEPTION_EVAL_INTERVAL=1`.

Decision JSON contract (GPT path):
```json
{"action":"stay"|"switch","new_persona":"NameIfSwitching","reason":"Short justification"}
```

## 🧪 Testing & Quality

Run tests (heuristic-only mode):
```bash
DEEPDECOY_DISABLE_OPENAI=true pytest -q
```

Lint (basic style & complexity):
```bash
flake8 . --max-line-length=120 --statistics
```

## 🤖 Continuous Integration

GitHub Actions workflow (`.github/workflows/ci.yml`) runs:
- Dependency install
- Flake8 (error + stats passes)
- Pytest in offline mode

## 🔧 Additional Troubleshooting

| Issue | Resolution |
|-------|------------|
| Persona never changes | Lower `DECEPTION_EVAL_INTERVAL`, use triggering keywords |
| Tests fail due to OpenAI | Export `DEEPDECOY_DISABLE_OPENAI=true` |
| High API usage | Increase interval or enable offline mode for dev |
| Slow GPT replies | Switch `OPENAI_MODEL` to faster model (e.g., gpt-4o-mini) |

## 🧩 Roadmap Additions (Adaptive)

-- Expand persona library (Cloud Node, Legacy Windows, ICS PLC)
- Behavioral clustering for multi-session intent
- Real-time web dashboard for transitions
- Learning weight visualization charts
- Session tagging improvements & anomaly detection

---
