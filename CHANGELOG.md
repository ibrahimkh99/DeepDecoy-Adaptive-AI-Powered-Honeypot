# Changelog
All notable changes to this project will be documented in this file.

Semantic versioning is approximated by feature increments (v1.x, v2.x). This project is educational and experimental.

## [v2.1] - 2025-12-01
### Added
- Learning feedback loop (`learning_engine.py`) computes engagement, threat, and persona effectiveness metrics.
- Persona strategy weighting stored in SQLite (`persona_strategy` table) or JSON fallback.
- Dashboard (`dashboard.py` + templates) for overview, sessions list, session detail timeline, persona insights.
- Bias in `deception_engine.py` integrating learned weights for persona selection.
- Offline deterministic enhancements (shell commands: ls variants, cpuinfo, dmesg, find).
- README updates: Quick Start TL;DR, learning & dashboard docs, extended config.
- Fallback log directory support in learning engine (reads legacy `logs/` session_*.json).

### Changed
- Deception engine now prefers personas with higher (engagement_weight + threat_weight).
- Documentation promotes offline mode and dashboard usage.

### Fixed
- Dashboard overview query double-fetch bug causing 500 errors with empty database.
- Offline mode previously still attempted OpenAI calls; now properly guarded.

## [v2.0] - 2025-11-30
### Added
- Adaptive Deception Engine with personas (Linux Dev Server, MySQL Backend, IoT Hub, Internal API, C2 Panel, Vulnerable Web CMS).
- Persona transition logging with reasons and modules.
- Prompt overrides for SSH and Web via persona definitions.
- Architecture, Security, Contributing, Code of Conduct documentation.
- CI workflow (lint + tests) and offline test support.

## [v1.2] - 2025-11-28
### Added
- Flask-based web honeypot: dynamic HTML + JSON responses.
- Route-aware GPT prompts with fallback deterministic API outputs.
- Web interaction logging (HTTP requests + persona context when applicable).

## [v1.1] - 2025-11-27
### Added
- AI threat analysis after each SSH session with GPT summary.
- Suspicious score, threat tags, threat level assignment.
- Session summary report files.

## [v1.0] - 2025-11-26
### Added
- Initial SSH honeypot using Paramiko.
- GPT-driven simulated Linux shell responses.
- Session JSON and text logging.

---
Future versions may include richer dashboards, anomaly detection, and expanded protocol support.
