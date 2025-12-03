# Contributing to DeepDecoy

Thanks for your interest in contributing!

## Getting Started
- Fork the repo and create a feature branch.
- Use Python 3.10+ and install deps via `pip install -r requirements.txt`.
- Create a `.env` with your `OPENAI_API_KEY` (do not commit it).

## Development
- Keep code modular: `main.py`, `ai_shell.py`, `session_logger.py`, `config.py`.
- Avoid running real system commands; all behavior must be simulated.
- Add/update prompt templates under `prompts/`.

## Testing
- Manually test via SSH on port 2222.
- Verify logs appear under `logs/` and outputs look realistic.

## Commit Guidelines
- Use clear messages, e.g., `feat(ai): improve sudo simulation`
- Do not include secrets or `.env` in commits.

## Pull Requests
- Explain the problem and solution.
- Include screenshots or log samples if applicable.
- Link to issues or discussions.
