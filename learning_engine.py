import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple

# Simple, explainable learning engine.
# - Reads session logs produced by SSH and Web components
# - Computes engagement and threat metrics per session and per persona
# - Updates a persistent strategy configuration with weights per persona
#
# Storage options:
# - SQLite (recommended): tables for sessions_metrics and persona_strategy
# - JSON fallback: strategy_config.json for weights
#
# Assumptions about log structure (backward-compatible):
# - Text logs in logs/sessions/*.log and JSON logs in logs/sessions/*.json
# - JSON log contains keys: session_id, start_time, end_time, commands, http_requests,
#   suspicious_score, threat_tags, persona_transitions, initial_persona, summary
# - If fields are missing, defaults are applied.

DEFAULT_DB_PATH = os.path.join("data", "deepdecoy.db")
DEFAULT_STRATEGY_JSON = os.path.join("data", "strategy_config.json")
LOGS_DIR = os.path.join("logs", "sessions")  # Preferred location
FALLBACK_LOGS_DIR = "logs"  # Backward compatibility (earlier versions stored session_*.json directly in logs/

# Weight update parameters (kept simple and transparent)
ENGAGEMENT_ALPHA = 0.2
THREAT_ALPHA = 0.2
DECAY = 0.98

PERSONA_KEY = "persona"


def ensure_dirs():
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)


def open_db(db_path: str) -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(conn: sqlite3.Connection):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions_metrics (
            session_id TEXT PRIMARY KEY,
            start_time TEXT,
            end_time TEXT,
            ip TEXT,
            initial_persona TEXT,
            engagement_score REAL,
            threat_score REAL,
            suspicious_score REAL,
            threat_tags TEXT
        );

        CREATE TABLE IF NOT EXISTS persona_effectiveness (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            persona_name TEXT,
            time_spent_seconds REAL,
            command_count INTEGER,
            http_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS persona_strategy (
            persona_name TEXT PRIMARY KEY,
            engagement_weight REAL,
            threat_weight REAL,
            usage_count INTEGER
        );
        """
    )
    conn.commit()


def load_json_logs() -> List[Dict[str, Any]]:
    """Load session JSON logs from preferred and fallback directories.
    Looks for files matching pattern 'session_*.json'.
    """
    ensure_dirs()
    sessions: List[Dict[str, Any]] = []

    # Gather candidate directories
    dirs = []
    if os.path.isdir(LOGS_DIR):
        dirs.append(LOGS_DIR)
    if os.path.isdir(FALLBACK_LOGS_DIR):
        dirs.append(FALLBACK_LOGS_DIR)

    seen_paths = set()
    for d in dirs:
        for name in os.listdir(d):
            if not name.endswith('.json'):
                continue
            if not name.startswith('session_'):
                continue
            path = os.path.join(d, name)
            if path in seen_paths:
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    sessions.append(data)
                    seen_paths.add(path)
            except Exception:
                continue
    return sessions


def parse_time(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.utcfromtimestamp(0)


def compute_session_metrics(sess: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    session_id = str(sess.get('session_id') or sess.get('id') or '')
    start = parse_time(sess.get('start_time') or '')
    end = parse_time(sess.get('end_time') or '')
    duration = max((end - start).total_seconds(), 0)

    cmds = sess.get('commands') or []
    http_reqs = sess.get('http_requests') or []
    suspicious_score = float(sess.get('suspicious_score') or 0.0)
    threat_tags = sess.get('threat_tags') or []
    ip = sess.get('ip') or sess.get('remote_ip') or ''
    initial_persona = sess.get('initial_persona') or 'Linux Dev Server'

    engagement_score = float(len(cmds) + len(http_reqs)) + 0.001 * duration
    # Basic threat score combining suspicious_score and tag severity
    tag_bonus = 0.0
    high_risk_markers = {'exfil', 'priv-esc', 'c2', 'ransomware', 'sql-injection', 'bruteforce'}
    for t in threat_tags:
        if isinstance(t, str) and t.lower() in high_risk_markers:
            tag_bonus += 1.0
    threat_score = suspicious_score + tag_bonus

    # Persona effectiveness per persona segment
    transitions = sess.get('persona_transitions') or []
    segments: List[Dict[str, Any]] = []
    # Build segments from transitions; assume transition entries: {persona, timestamp}
    last_time = start
    last_persona = initial_persona
    for tr in transitions:
        ts = parse_time(tr.get('timestamp') or '')
        persona = tr.get('persona') or tr.get('to') or last_persona
        if ts > last_time:
            segments.append({
                'persona_name': last_persona,
                'time_spent_seconds': (ts - last_time).total_seconds(),
                'command_count': 0,
                'http_count': 0,
            })
            last_time = ts
            last_persona = persona
        else:
            last_persona = persona
    # Final segment till end
    if end > last_time:
        segments.append({
            'persona_name': last_persona,
            'time_spent_seconds': (end - last_time).total_seconds(),
            'command_count': 0,
            'http_count': 0,
        })

    # Count commands/http per persona using timeline entries if present
    # Expected optional fields with entries like: {time, persona, type, command|route}
    timeline = sess.get('timeline') or []
    for entry in timeline:
        persona = entry.get('persona') or initial_persona
        etype = entry.get('type') or ''
        # find matching segment by persona (approx)
        for seg in segments:
            if seg['persona_name'] == persona:
                if etype.upper() == 'SSH':
                    seg['command_count'] += 1
                elif etype.upper() in ('HTTP', 'WEB'):
                    seg['http_count'] += 1
                break

    metrics_row = {
        'session_id': session_id,
        'start_time': start.isoformat() if start else '',
        'end_time': end.isoformat() if end else '',
        'ip': ip,
        'initial_persona': initial_persona,
        'engagement_score': engagement_score,
        'threat_score': threat_score,
        'suspicious_score': suspicious_score,
        'threat_tags': ','.join(threat_tags) if threat_tags else ''
    }

    return metrics_row, segments


def upsert_persona_strategy(conn: sqlite3.Connection, persona: str, engagement: float, threat: float):
    cur = conn.cursor()
    # Fetch existing
    cur.execute("SELECT engagement_weight, threat_weight, usage_count FROM persona_strategy WHERE persona_name=?", (persona,))
    row = cur.fetchone()
    if row:
        e_w, t_w, use = row
        e_w = DECAY * e_w + ENGAGEMENT_ALPHA * engagement
        t_w = DECAY * t_w + THREAT_ALPHA * threat
        use = int(use) + 1
        cur.execute("UPDATE persona_strategy SET engagement_weight=?, threat_weight=?, usage_count=? WHERE persona_name=?",
                    (e_w, t_w, use, persona))
    else:
        cur.execute("INSERT INTO persona_strategy (persona_name, engagement_weight, threat_weight, usage_count) VALUES (?,?,?,?)",
                    (persona, engagement, threat, 1))
    conn.commit()


def learn(db_path: str = DEFAULT_DB_PATH, strategy_json: str = DEFAULT_STRATEGY_JSON, use_sqlite: bool = True) -> Dict[str, Any]:
    """Run the learning job: parse logs, compute metrics, update strategy.
    Returns a summary dict.
    """
    ensure_dirs()
    sessions = load_json_logs()
    summary = {"sessions": len(sessions), "updated_personas": set()}

    if use_sqlite:
        conn = open_db(db_path)
        init_db(conn)
    else:
        conn = None
        # Ensure JSON exists
        if not os.path.isfile(strategy_json):
            with open(strategy_json, 'w', encoding='utf-8') as f:
                json.dump({}, f)

    for sess in sessions:
        metrics_row, segments = compute_session_metrics(sess)
        if use_sqlite:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO sessions_metrics (session_id, start_time, end_time, ip, initial_persona, engagement_score, threat_score, suspicious_score, threat_tags)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id) DO UPDATE SET
                    start_time=excluded.start_time,
                    end_time=excluded.end_time,
                    ip=excluded.ip,
                    initial_persona=excluded.initial_persona,
                    engagement_score=excluded.engagement_score,
                    threat_score=excluded.threat_score,
                    suspicious_score=excluded.suspicious_score,
                    threat_tags=excluded.threat_tags
                """,
                (
                    metrics_row['session_id'], metrics_row['start_time'], metrics_row['end_time'], metrics_row['ip'], metrics_row['initial_persona'],
                    metrics_row['engagement_score'], metrics_row['threat_score'], metrics_row['suspicious_score'], metrics_row['threat_tags']
                )
            )
            for seg in segments:
                cur.execute(
                    """
                    INSERT INTO persona_effectiveness (session_id, persona_name, time_spent_seconds, command_count, http_count)
                    VALUES (?,?,?,?,?)
                    """,
                    (
                        metrics_row['session_id'], seg['persona_name'], seg['time_spent_seconds'], seg['command_count'], seg['http_count']
                    )
                )
                upsert_persona_strategy(conn, seg['persona_name'], metrics_row['engagement_score'], metrics_row['threat_score'])
                summary["updated_personas"].add(seg['persona_name'])
            conn.commit()
        else:
            # JSON strategy upsert
            try:
                with open(strategy_json, 'r', encoding='utf-8') as f:
                    strat = json.load(f)
            except Exception:
                strat = {}
            for seg in segments:
                p = seg['persona_name']
                cur = strat.get(p, {"engagement_weight": 0.0, "threat_weight": 0.0, "usage_count": 0})
                cur['engagement_weight'] = DECAY * cur.get('engagement_weight', 0.0) + ENGAGEMENT_ALPHA * metrics_row['engagement_score']
                cur['threat_weight'] = DECAY * cur.get('threat_weight', 0.0) + THREAT_ALPHA * metrics_row['threat_score']
                cur['usage_count'] = int(cur.get('usage_count', 0)) + 1
                strat[p] = cur
                summary["updated_personas"].add(p)
            with open(strategy_json, 'w', encoding='utf-8') as f:
                json.dump(strat, f, indent=2)

    summary['updated_personas'] = sorted(list(summary['updated_personas']))
    return summary


if __name__ == "__main__":
    use_sqlite = os.environ.get('USE_SQLITE', 'true').lower() == 'true'
    db_path = os.environ.get('LEARNING_DB_PATH', DEFAULT_DB_PATH)
    strat_json = os.environ.get('STRATEGY_JSON_PATH', DEFAULT_STRATEGY_JSON)
    out = learn(db_path=db_path, strategy_json=strat_json, use_sqlite=use_sqlite)
    print(json.dumps(out, indent=2))
