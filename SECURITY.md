# Security Policy

## Supported Versions
This project is an educational honeypot. Please use the latest commit.

## Reporting a Vulnerability
If you discover a security issue:
- Do not open a public issue describing exploit details.
- Email the maintainer or open a private security advisory on GitHub.
- Provide steps to reproduce, affected components, and potential impact.

## Operational Safety
- DeepDecoy is a simulated SSH honeypot—no real commands are executed.
- Deploy only on isolated networks. Do not expose production credentials.
- Keep secrets (e.g., `OPENAI_API_KEY`) in local `.env` and out of Git history.
- Monitor OpenAI usage and set spending limits.

## Data Collection Notice
DeepDecoy logs session metadata (IP, username, commands, AI output, timestamps).
Ensure compliance with local laws and obtain proper authorization before collecting traffic.
