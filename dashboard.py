import os
import sqlite3
from flask import Flask, render_template, jsonify, abort

DASHBOARD_PORT = int(os.environ.get('DASHBOARD_PORT', '5000'))
DB_PATH = os.environ.get('LEARNING_DB_PATH', os.path.join('data', 'deepdecoy.db'))
USE_SQLITE = os.environ.get('USE_SQLITE', 'true').lower() == 'true'

app = Flask(__name__, template_folder='templates', static_folder='static')


def open_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def overview():
    if not USE_SQLITE:
        return render_template('overview.html', stats={})
    conn = open_db()
    cur = conn.cursor()
    # Summary stats
    cur.execute('SELECT COUNT(*) AS c FROM sessions_metrics')
    row = cur.fetchone()
    total_sessions = row['c'] if row else 0

    cur.execute('SELECT AVG(engagement_score) AS avg_eng FROM sessions_metrics')
    row = cur.fetchone()
    avg_eng = row['avg_eng'] if row else 0

    cur.execute('SELECT AVG(threat_score) AS avg_thr FROM sessions_metrics')
    row = cur.fetchone()
    avg_thr = row['avg_thr'] if row else 0

    cur.execute('SELECT initial_persona AS persona, COUNT(*) AS cnt FROM sessions_metrics GROUP BY initial_persona')
    per_persona = cur.fetchall()
    stats = {
        'total_sessions': total_sessions,
        'avg_engagement': round(avg_eng or 0, 3),
        'avg_threat': round(avg_thr or 0, 3),
        'sessions_per_persona': [(row['persona'], row['cnt']) for row in per_persona]
    }
    return render_template('overview.html', stats=stats)


@app.route('/sessions')
def sessions_list():
    if not USE_SQLITE:
        return render_template('sessions_list.html', sessions=[])
    conn = open_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT session_id, start_time, ip, threat_tags, suspicious_score, threat_score, engagement_score, initial_persona
        FROM sessions_metrics
        ORDER BY start_time DESC
    ''')
    rows = cur.fetchall()
    return render_template('sessions_list.html', sessions=rows)


@app.route('/sessions/<session_id>')
def session_detail(session_id):
    if not USE_SQLITE:
        abort(404)
    conn = open_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM sessions_metrics WHERE session_id=?', (session_id,))
    meta = cur.fetchone()
    if not meta:
        abort(404)
    cur.execute('SELECT * FROM persona_effectiveness WHERE session_id=?', (session_id,))
    eff = cur.fetchall()
    # Load timeline from JSON log if available
    timeline = []
    log_path = os.path.join('logs', 'sessions', f'{session_id}.json')
    if os.path.isfile(log_path):
        import json
        with open(log_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            timeline = data.get('timeline') or []
            summary_text = data.get('summary') or ''
            persona_transitions = data.get('persona_transitions') or []
    else:
        summary_text = ''
        persona_transitions = []

    return render_template('session_detail.html', meta=meta, eff=eff, timeline=timeline, summary_text=summary_text, persona_transitions=persona_transitions)


@app.route('/personas')
def personas_view():
    if not USE_SQLITE:
        return render_template('personas.html', personas=[])
    conn = open_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM persona_strategy ORDER BY (engagement_weight + threat_weight) DESC')
    personas = cur.fetchall()
    return render_template('personas.html', personas=personas)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=DASHBOARD_PORT, debug=False)
