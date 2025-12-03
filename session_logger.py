"""
DeepDecoy Session Logger
Handles structured logging of SSH honeypot sessions.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from config import Config


class SessionLogger:
    """Logs honeypot sessions with detailed command history."""
    
    def __init__(self, session_id: str, client_ip: str, username: str):
        """
        Initialize a session logger.
        
        Args:
            session_id: Unique identifier for this session
            client_ip: IP address of the connecting client
            username: Username used for login
        """
        self.session_id = session_id
        self.client_ip = client_ip
        self.username = username
        self.start_time = datetime.now()
        self.commands: List[Dict[str, Any]] = []
        
        # Threat intelligence fields
        self.threat_tags: List[str] = []
        self.suspicious_score: int = 0
        self.session_summary: str = ""
        self.threat_level: str = "UNKNOWN"

        # Deception engine fields
        self.initial_persona: str = "Linux Dev Server"
        self.persona_metadata: Dict[str, Any] = {}
        self.deception_transitions: List[Dict[str, Any]] = []
        
        # Generate log filename
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        safe_ip = client_ip.replace(".", "_").replace(":", "_")
        self.log_filename = f"session_{timestamp}_{safe_ip}_{session_id[:8]}.json"
        self.log_filepath = os.path.join(Config.LOGS_DIR, self.log_filename)
        
        # Create session log file immediately
        self._write_initial_log()
    
    def _write_initial_log(self):
        """Write initial session metadata to log file."""
        session_data = {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "username": self.username,
            "start_time": self.start_time.isoformat(),
            "end_time": None,
            "duration_seconds": None,
            "total_commands": 0,
            "commands": [],
            "threat_tags": [],
            "suspicious_score": 0,
            "threat_level": "UNKNOWN",
            "session_summary": "",
            "initial_persona": self.initial_persona,
            "persona_metadata": self.persona_metadata,
            "deception_transitions": self.deception_transitions
        }
        
        with open(self.log_filepath, "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2)
    
    def log_command(self, command: str, output: str, category: str = "other"):
        """
        Log a single command and its output.
        
        Args:
            command: The command entered by the attacker
            output: The AI-generated response
            category: Command category (file_access, network_probe, etc.)
        """
        command_entry = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "output": output,
            "category": category,
            "command_length": len(command),
            "output_length": len(output)
        }
        
        self.commands.append(command_entry)
        self._update_log_file()
    
    def _update_log_file(self):
        """Update the log file with current session data."""
        try:
            session_data = {
                "session_id": self.session_id,
                "client_ip": self.client_ip,
                "username": self.username,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "total_commands": len(self.commands),
                "commands": self.commands,
                "threat_tags": self.threat_tags,
                "suspicious_score": self.suspicious_score,
                "threat_level": self.threat_level,
                "session_summary": self.session_summary,
                "initial_persona": self.initial_persona,
                "persona_metadata": self.persona_metadata,
                "deception_transitions": self.deception_transitions
            }
            
            with open(self.log_filepath, "w", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            print(f"[!] Error writing log file: {e}")
    
    def set_threat_analysis(self, threat_tags: List[str], suspicious_score: int, 
                           threat_level: str, session_summary: str):
        """
        Set threat intelligence analysis results.
        
        Args:
            threat_tags: List of threat categories detected
            suspicious_score: Numeric suspicious activity score
            threat_level: LOW, MEDIUM, HIGH, or CRITICAL
            session_summary: AI-generated summary text
        """
        self.threat_tags = threat_tags
        self.suspicious_score = suspicious_score
        self.threat_level = threat_level
        self.session_summary = session_summary
        self._update_log_file()
        # Regenerate text summary with threat analysis
        self._write_text_summary()

    # Deception logging -------------------------------------------------
    def set_initial_persona(self, name: str, metadata: Dict[str, Any]):
        self.initial_persona = name
        self.persona_metadata = metadata
        self._update_log_file()

    def log_persona_transition(self, transition: Dict[str, Any]):
        """Record a persona change event from the deception engine."""
        self.deception_transitions.append(transition)
        self._update_log_file()
    
    def close_session(self):
        """Mark the session as closed and write final log."""
        self._update_log_file()
        
        # Also create a summary text log
        self._write_text_summary()
    
    def _write_text_summary(self):
        """Write a human-readable text summary of the session."""
        text_filename = self.log_filename.replace(".json", ".txt")
        text_filepath = os.path.join(Config.LOGS_DIR, text_filename)
        
        try:
            with open(text_filepath, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("DEEPDECOY HONEYPOT SESSION LOG\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Session ID:    {self.session_id}\n")
                f.write(f"Client IP:     {self.client_ip}\n")
                f.write(f"Username:      {self.username}\n")
                f.write(f"Start Time:    {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"End Time:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                duration = (datetime.now() - self.start_time).total_seconds()
                f.write(f"Duration:      {duration:.1f} seconds\n")
                f.write(f"Total Commands: {len(self.commands)}\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("COMMAND HISTORY\n")
                f.write("=" * 80 + "\n\n")
                
                for idx, cmd_entry in enumerate(self.commands, 1):
                    timestamp = datetime.fromisoformat(cmd_entry["timestamp"]).strftime("%H:%M:%S")
                    f.write(f"[{idx}] {timestamp} [{cmd_entry['category']}]\n")
                    f.write(f">>> {cmd_entry['command']}\n")
                    f.write(f"{cmd_entry['output']}\n\n")
                    f.write("-" * 80 + "\n\n")
                
                # Statistics
                f.write("=" * 80 + "\n")
                f.write("SESSION STATISTICS\n")
                f.write("=" * 80 + "\n\n")
                
                # Count categories
                categories = {}
                for cmd in self.commands:
                    cat = cmd["category"]
                    categories[cat] = categories.get(cat, 0) + 1
                
                f.write("Commands by category:\n")
                for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {cat}: {count}\n")
                
                # Deception transitions
                if self.deception_transitions:
                    f.write("\n" + "=" * 80 + "\n")
                    f.write("DECEPTION PERSONA TRANSITIONS\n")
                    f.write("=" * 80 + "\n\n")
                    for t in self.deception_transitions:
                        f.write(f"[{t.get('timestamp','')}] {t.get('previous')} -> {t.get('new')} | Reason: {t.get('reason','')} | Modules: {', '.join(t.get('modules', []))}\n")

                # Threat analysis
                if self.threat_tags or self.suspicious_score > 0:
                    f.write("\n" + "=" * 80 + "\n")
                    f.write("THREAT ANALYSIS (AI-POWERED)\n")
                    f.write("=" * 80 + "\n\n")
                    
                    f.write(f"Threat Level:      {self.threat_level}\n")
                    f.write(f"Suspicious Score:  {self.suspicious_score}\n")
                    f.write(f"Threat Tags:       {', '.join(self.threat_tags) if self.threat_tags else 'None'}\n\n")
                    
                    if self.session_summary:
                        f.write("AI Security Summary:\n")
                        f.write("-" * 80 + "\n")
                        f.write(self.session_summary + "\n")
        
        except Exception as e:
            print(f"[!] Error writing text summary: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current session.
        
        Returns:
            Dictionary with session summary statistics
        """
        categories = {}
        for cmd in self.commands:
            cat = cmd["category"]
            categories[cat] = categories.get(cat, 0) + 1
        
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "username": self.username,
            "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
            "total_commands": len(self.commands),
            "categories": categories
        }
