"""
DeepDecoy Session Analyzer Module
Provides AI-powered threat analysis and session summarization.
"""

import re
from typing import List, Dict, Any, Tuple
from openai import OpenAI
from config import Config
import os


class SessionAnalyzer:
    """Analyzes honeypot sessions for threat intelligence."""
    
    # Known suspicious command patterns
    THREAT_PATTERNS = {
        "recon": [
            r"\bnmap\b", r"\bnetstat\b", r"\bifconfig\b", r"\bip\s+addr\b",
            r"\bping\b", r"\bwhois\b", r"\bdig\b", r"\bnslookup\b",
            r"\barp\b", r"\broute\b", r"\btraceroute\b"
        ],
        "exploit": [
            r"\bsqlmap\b", r"\bmetasploit\b", r"\bmsfconsole\b",
            r"\bhydra\b", r"\bjohn\b", r"\bhashcat\b", r"\baircrack\b",
            r"\bexploit\b", r"\bpayload\b", r"\bshellcode\b"
        ],
        "privilege_escalation": [
            r"\bsudo\b", r"\bsu\b", r"\bpasswd\b", r"\/etc\/shadow",
            r"\/etc\/sudoers\b", r"\bchmod\s+[+]?s\b", r"\bsetuid\b",
            r"\bchown\s+root\b"
        ],
        "file_access": [
            r"\/etc\/passwd", r"\/var\/log\b", r"\/root\/", r"\/home\/.*\/\.ssh",
            r"\.bash_history\b", r"\.ssh\/id_rsa", r"\/proc\/",
            r"\.kdbx\b", r"\.conf\b"
        ],
        "data_exfil": [
            r"\bwget\b", r"\bcurl\b", r"\bscp\b", r"\brsync\b",
            r"\bnc\b", r"\bnetcat\b", r"\bbase64\b", r"\btar\s+.*\s+-z",
            r"\bgzip\b", r"\b7z\b"
        ],
        "persistence": [
            r"\bcrontab\b", r"\/etc\/cron", r"\.bashrc\b", r"\.profile\b",
            r"\bsystemctl\s+enable\b", r"\bchkconfig\b", r"\/etc\/init\.d",
            r"\brc\.local\b"
        ],
        "lateral_movement": [
            r"\bssh\s+.*@", r"\btelnet\b", r"\brdesktop\b",
            r"\bsmbclient\b", r"\bpsexec\b", r"\bwinrm\b"
        ]
    }
    
    def __init__(self):
        """Initialize the analyzer with OpenAI client."""
        self.client = OpenAI(api_key=Config.OPENAI_API_KEY)
        self.model = Config.OPENAI_MODEL
        self.summary_prompt = self._load_summary_prompt()
    
    def _load_summary_prompt(self) -> str:
        """Load the summarization prompt template."""
        prompt_file = os.path.join(Config.PROMPTS_DIR, "summary_prompt.txt")
        
        if os.path.exists(prompt_file):
            with open(prompt_file, "r", encoding="utf-8") as f:
                return f.read()
        
        # Default summary prompt
        return """You are an expert cybersecurity analyst specializing in threat intelligence and incident response.

Analyze the following SSH honeypot session log and provide a concise security assessment.

SESSION METADATA:
- Client IP: {client_ip}
- Username: {username}
- Duration: {duration} seconds
- Total Commands: {total_commands}

COMMAND HISTORY:
{command_history}

ANALYSIS REQUIREMENTS:
1. Identify the attacker's primary objectives (reconnaissance, exploitation, persistence, etc.)
2. List specific tools or techniques observed (e.g., nmap, sqlmap, privilege escalation attempts)
3. Assess the sophistication level (novice, intermediate, advanced)
4. Highlight any unusual or novel behavior
5. Rate the threat level: LOW, MEDIUM, HIGH, or CRITICAL

Provide a 3-5 paragraph summary suitable for an incident report. Be specific and actionable."""
    
    def analyze_command(self, command: str) -> Tuple[List[str], int]:
        """
        Analyze a single command for suspicious patterns.
        
        Args:
            command: The command string to analyze
            
        Returns:
            Tuple of (threat_tags, suspicious_score)
        """
        tags = set()
        score = 0
        
        command_lower = command.lower()
        
        for category, patterns in self.THREAT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command_lower, re.IGNORECASE):
                    tags.add(category)
                    score += 1
                    break  # Count each category once per command
        
        return list(tags), score
    
    def analyze_session(self, commands: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a full session's command history.
        
        Args:
            commands: List of command entries from session log
            
        Returns:
            Dictionary with threat_tags, suspicious_score, and analysis details
        """
        all_tags = set()
        total_score = 0
        command_analysis = []
        
        for cmd_entry in commands:
            command = cmd_entry.get("command", "")
            tags, score = self.analyze_command(command)
            
            all_tags.update(tags)
            total_score += score
            
            if tags:  # Only log commands with threats
                command_analysis.append({
                    "command": command,
                    "tags": tags,
                    "score": score
                })
        
        return {
            "threat_tags": sorted(list(all_tags)),
            "suspicious_score": total_score,
            "flagged_commands": command_analysis,
            "total_commands": len(commands),
            "flagged_count": len(command_analysis)
        }
    
    def generate_summary(
        self, 
        client_ip: str,
        username: str,
        duration: float,
        commands: List[Dict[str, Any]],
        analysis: Dict[str, Any]
    ) -> str:
        """
        Generate an AI-powered security summary of the session.
        
        Args:
            client_ip: Client IP address
            username: Username used
            duration: Session duration in seconds
            commands: Full command history
            analysis: Output from analyze_session()
            
        Returns:
            AI-generated summary text
        """
        # Format command history for GPT
        command_history = []
        for idx, cmd in enumerate(commands, 1):
            timestamp = cmd.get("timestamp", "")
            command = cmd.get("command", "")
            category = cmd.get("category", "other")
            
            command_history.append(
                f"[{idx}] {timestamp} [{category}]\n"
                f"Command: {command}\n"
            )
        
        command_history_text = "\n".join(command_history)
        
        # Build the prompt
        prompt = self.summary_prompt.format(
            client_ip=client_ip,
            username=username,
            duration=f"{duration:.1f}",
            total_commands=len(commands),
            command_history=command_history_text
        )
        
        # Add threat analysis context
        prompt += f"\n\nAUTOMATED THREAT DETECTION:\n"
        prompt += f"- Threat Tags: {', '.join(analysis['threat_tags']) if analysis['threat_tags'] else 'None'}\n"
        prompt += f"- Suspicious Score: {analysis['suspicious_score']}\n"
        prompt += f"- Flagged Commands: {analysis['flagged_count']} of {analysis['total_commands']}\n"
        
        try:
            # Call GPT for summarization
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert cybersecurity analyst. Provide clear, actionable threat analysis."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=1000
            )
            
            summary = response.choices[0].message.content.strip()
            return summary
        
        except Exception as e:
            return f"[Error generating summary: {e}]\n\nSession had {len(commands)} commands with threat tags: {analysis['threat_tags']}"
    
    def get_threat_level(self, suspicious_score: int, flagged_count: int) -> str:
        """
        Determine threat level based on score and flagged commands.
        
        Args:
            suspicious_score: Total suspicious score
            flagged_count: Number of flagged commands
            
        Returns:
            Threat level string: LOW, MEDIUM, HIGH, or CRITICAL
        """
        if suspicious_score == 0 and flagged_count == 0:
            return "LOW"
        elif suspicious_score <= 3 and flagged_count <= 2:
            return "MEDIUM"
        elif suspicious_score <= 8 and flagged_count <= 5:
            return "HIGH"
        else:
            return "CRITICAL"
