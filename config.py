"""
DeepDecoy Configuration Module
Loads environment variables and provides configuration settings.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration class for DeepDecoy honeypot."""
    
    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
    
    # SSH Server Configuration
    SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
    SSH_HOST = os.getenv("SSH_HOST", "0.0.0.0")
    
    # Web Server Configuration
    ENABLE_WEB = os.getenv("ENABLE_WEB", "true").lower() == "true"
    WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
    WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")

    # Deception / Adaptive Engine
    DECEPTION_EVAL_INTERVAL = int(os.getenv("DECEPTION_EVAL_INTERVAL", "3"))
    INITIAL_PERSONA = os.getenv("INITIAL_PERSONA", "Linux Dev Server")
    
    # Dashboard & Learning
    ENABLE_DASHBOARD = os.getenv("ENABLE_DASHBOARD", "false").lower() == "true"
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))
    USE_SQLITE = os.getenv("USE_SQLITE", "true").lower() == "true"
    LEARNING_DB_PATH = os.getenv("LEARNING_DB_PATH", os.path.join("data", "deepdecoy.db"))
    STRATEGY_JSON_PATH = os.getenv("STRATEGY_JSON_PATH", os.path.join("data", "strategy_config.json"))
    DISABLE_OPENAI = os.getenv("DEEPDECOY_DISABLE_OPENAI", "false").lower() == "true"
    
    # Honeypot Identity
    HOSTNAME = os.getenv("HOSTNAME", "deepdecoy")
    USERNAME = os.getenv("USERNAME", "ubuntu")
    
    # Paths
    LOGS_DIR = "logs"
    WEB_LOGS_DIR = "logs/web"
    PROMPTS_DIR = "prompts"
    SSH_KEY_FILE = "honeypot_rsa.key"
    
    # Session Configuration
    MAX_COMMAND_LENGTH = 10000
    SESSION_TIMEOUT = 3600  # 1 hour in seconds
    
    @classmethod
    def validate(cls):
        """Validate that required configuration is present."""
        # Allow running without OpenAI for tests / offline demo
        if not cls.OPENAI_API_KEY and not cls.DISABLE_OPENAI:
            raise ValueError(
                "OPENAI_API_KEY not found. Set in .env or export, or set DEEPDECOY_DISABLE_OPENAI=true for offline mode."
            )
        
        # Create directories if they don't exist
        os.makedirs(cls.LOGS_DIR, exist_ok=True)
        os.makedirs(cls.WEB_LOGS_DIR, exist_ok=True)
        os.makedirs(cls.PROMPTS_DIR, exist_ok=True)
        
        return True
