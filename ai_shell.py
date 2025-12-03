"""
DeepDecoy AI Shell Module
Handles GPT-powered command simulation for the fake Linux terminal.
"""

import os
from openai import OpenAI
from config import Config


class AIShell:
    """AI-powered shell simulator using GPT."""
    
    def __init__(self):
        """Initialize the AI shell with OpenAI client (disabled in offline mode)."""
        self.client = None
        self.model = Config.OPENAI_MODEL
        # Only initialize OpenAI when not disabled and API key is present
        if not Config.DISABLE_OPENAI and Config.OPENAI_API_KEY:
            try:
                self.client = OpenAI(api_key=Config.OPENAI_API_KEY)
            except Exception:
                self.client = None
        self.hostname = Config.HOSTNAME
        self.username = Config.USERNAME
        self.current_directory = "/home/" + self.username
        self.command_history = []
        
        # Base system prompt template
        self.system_prompt = self._load_system_prompt()
        # Dynamic persona override
        self.persona_prompt_override: str | None = None
    
    def _load_system_prompt(self):
        """Load the system prompt template."""
        prompt_file = os.path.join(Config.PROMPTS_DIR, "system_prompt.txt")
        
        if os.path.exists(prompt_file):
            with open(prompt_file, "r", encoding="utf-8") as f:
                return f.read()
        
        # Default system prompt if file doesn't exist
        return """You are simulating a realistic Linux terminal (Ubuntu 20.04 LTS).
You must respond EXACTLY as a real Linux shell would respond to commands.

CRITICAL RULES:
1. Generate realistic output with proper formatting
2. Use realistic filenames, directories, and system information
3. Maintain consistency across commands in the same session
4. Show appropriate errors for invalid commands
5. Never break character or mention you're an AI
6. Format output authentically (columns, spacing, colors codes are OK)
7. Remember the current directory context
8. Generate realistic file contents when cat/less/more are used
9. Show realistic process lists, network info, etc.

Current directory: {current_dir}
Hostname: {hostname}
Username: {username}

Respond ONLY with the command output. Do not add explanations or meta-commentary."""
    
    def get_prompt(self):
        """Get the shell prompt string."""
        return f"{self.username}@{self.hostname}:{self.current_directory}$ "
    
    def get_motd(self):
        """Get the Message of the Day displayed on login."""
        motd_file = os.path.join(Config.PROMPTS_DIR, "motd.txt")
        
        if os.path.exists(motd_file):
            with open(motd_file, "r", encoding="utf-8") as f:
                return f.read()
        
        # Default MOTD
        return """Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {timestamp}

  System load:  0.08              Processes:             123
  Usage of /:   45.2% of 29.84GB  Users logged in:       1
  Memory usage: 34%               IPv4 address for eth0: 192.168.1.100
  Swap usage:   0%

Last login: {last_login}
"""
    
    def execute_command(self, command: str) -> str:
        """
        Execute a command by sending it to GPT for simulation.
        
        Args:
            command: The command entered by the attacker
            
        Returns:
            The simulated command output
        """
        if not command.strip():
            return ""
        
        # Add to history
        self.command_history.append(command)
        
        # Handle directory changes (track state)
        if command.strip().startswith("cd "):
            self._handle_cd(command)
        
        # Offline mode: provide deterministic fallback outputs without OpenAI
        if Config.DISABLE_OPENAI or not self.client:
            return self._offline_execute(command)

        # Build the prompt for GPT
        user_prompt = f"""Command entered: {command}
Current directory: {self.current_directory}
Previous commands in session: {self.command_history[-5:] if len(self.command_history) > 1 else 'None'}

Provide the output this command would produce."""
        
        system_content = self._build_system_content()

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.7,
                max_tokens=1500,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"[!] AI Shell Error: {e}")
            return f"bash: {command.split()[0] if command.split() else 'command'}: command not found"

    def _offline_execute(self, command: str) -> str:
        """Heuristic, static outputs for common commands in offline mode."""
        cmd = command.strip()
        parts = cmd.split()
        if not parts:
            return ""

        head = parts[0]
        # Suppress output for cd (state already updated above)
        if head == "cd":
            return ""
        # Basic commands
        if head == "whoami":
            return self.username
        if head == "pwd":
            return self.current_directory
        if head == "uname":
            # support uname -a
            if len(parts) > 1 and parts[1] == "-a":
                return "Linux deepdecoy 5.4.0-150-generic x86_64 (simulated)"
            return "Linux"
        if head == "ls" and len(parts) > 1 and parts[1] == "-la":
            return (
                "total 48\n"
                "drwxr-xr-x 5 {u} {u} 4096 Nov 30 08:00 .\n"
                "drwxr-xr-x 3 root root 4096 Nov 30 07:00 ..\n"
                "-rw------- 1 {u} {u}  220 Nov 30 07:00 .bash_logout\n"
                "-rw------- 1 {u} {u} 3771 Nov 30 07:00 .bashrc\n"
                "drwx------ 2 {u} {u} 4096 Nov 30 07:30 .cache\n"
                "drwxr-xr-x 3 {u} {u} 4096 Nov 30 07:45 .local\n"
                "-rw------- 1 {u} {u}  807 Nov 30 07:00 .profile\n"
                "drwxr-xr-x 2 {u} {u} 4096 Nov 30 08:00 Documents".format(u=self.username)
            )
        if head == "ls":
            # simple listing, honor path argument
            path_arg = parts[1] if len(parts) > 1 and parts[1] != "-la" else None
            path = path_arg or self.current_directory
            fake_fs = {
                f"/home/{self.username}": ["Documents", "Downloads", "projects", "README.md"],
                "/var/www/html": ["index.php", "wp-content", "admin.php", "assets"],
                "/": ["bin", "etc", "var", "home", "usr"],
            }
            listing = fake_fs.get(path, fake_fs.get(self.current_directory, ["Documents", "Downloads", "projects", "README.md"]))
            return "\n".join(listing)
        if head == "cat":
            target = parts[1] if len(parts) > 1 else ""
            if target == "/etc/passwd":
                return (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    f"{self.username}:x:1000:1000:{self.username}:/home/{self.username}:/bin/bash\n"
                )
            if target == "/proc/cpuinfo":
                return (
                    "processor\t: 0\n"
                    "vendor_id\t: GenuineIntel\n"
                    "model name\t: Intel(R) Xeon(R) CPU E5-2673 v4 @ 2.30GHz\n"
                    "cpu MHz\t\t: 2300.000\n"
                    "cache size\t: 30720 KB\n"
                )
            return f"cat: {target}: No such file or directory" if target else ""
        if head == "ps":
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:01 init\n"
                "  123 ?        00:00:00 sshd\n"
                "  456 pts/0    00:00:00 bash\n"
                "  789 pts/0    00:00:00 ps"
            )
        if head in ("ifconfig", "ip"):
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n    inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255"
        if head == "dmesg":
            return (
                "[    0.000000] Linux version 5.4.0 (deepdecoy)\n"
                "[    0.100000] sensor: initializing mock i2c sensor bus\n"
                "[    1.000000] eth0: link up 1000Mbps\n"
            )
        if head == "find":
            target = parts[1] if len(parts) > 1 else self.current_directory
            name = None
            if "-name" in parts:
                idx = parts.index("-name")
                if idx + 1 < len(parts):
                    name = parts[idx + 1]
            fake_hits = {
                "/": ["/lib/firmware", "/usr/lib/firmware"],
                "/var/www/html": ["/var/www/html/wp-content"],
            }
            hits = fake_hits.get(target, [])
            if name:
                needle = name.strip("\"'")
                hits = [h for h in hits if needle in h]
            return "\n".join(hits) if hits else ""
        if head == "sudo":
            return f"{self.username} is not in the sudoers file.  This incident will be reported."
        # Default fallback
        return f"bash: {head}: command not found"

    # Persona support ---------------------------------------------------
    def update_persona(self, persona_prompt: str | None):
        """Set a dynamic persona-specific system prompt fragment."""
        self.persona_prompt_override = persona_prompt

    def _build_system_content(self) -> str:
        base = self.system_prompt.format(
            current_dir=self.current_directory,
            hostname=self.hostname,
            username=self.username,
        )
        if self.persona_prompt_override:
            return base + "\n\n" + "Persona context:\n" + self.persona_prompt_override
        return base
    
    def _handle_cd(self, command: str):
        """
        Update the current directory based on cd command.
        This is a simple simulation - just tracks the path string.
        """
        parts = command.strip().split(maxsplit=1)
        if len(parts) < 2:
            # cd with no argument goes to home
            self.current_directory = f"/home/{self.username}"
        else:
            target = parts[1].strip()
            
            if target == "~" or target == "":
                self.current_directory = f"/home/{self.username}"
            elif target == "/":
                self.current_directory = "/"
            elif target == "..":
                # Go up one directory
                if self.current_directory != "/":
                    self.current_directory = "/".join(
                        self.current_directory.rstrip("/").split("/")[:-1]
                    ) or "/"
            elif target.startswith("/"):
                # Absolute path
                self.current_directory = target
            else:
                # Relative path
                if self.current_directory == "/":
                    self.current_directory = f"/{target}"
                else:
                    self.current_directory = f"{self.current_directory}/{target}"
    
    def categorize_command(self, command: str) -> str:
        """
        Categorize the command for logging purposes.
        
        Returns:
            Category string: file_access, network_probe, privilege_escalation,
            system_info, process_management, or other
        """
        cmd_lower = command.lower().strip()
        first_word = cmd_lower.split()[0] if cmd_lower.split() else ""
        
        # File access commands
        file_commands = ["cat", "ls", "cd", "pwd", "find", "grep", "less", "more", 
                        "head", "tail", "vim", "nano", "rm", "cp", "mv", "mkdir", 
                        "touch", "chmod", "chown"]
        
        # Network probing
        network_commands = ["ping", "netstat", "ifconfig", "ip", "curl", "wget", 
                           "nmap", "nc", "netcat", "ssh", "scp", "ftp", "telnet"]
        
        # Privilege escalation
        priv_commands = ["sudo", "su", "passwd"]
        
        # System info
        system_commands = ["uname", "whoami", "id", "hostname", "uptime", "df", 
                          "du", "free", "top", "htop", "lsb_release"]
        
        # Process management
        process_commands = ["ps", "kill", "killall", "pkill", "systemctl", 
                           "service", "jobs", "bg", "fg"]
        
        if first_word in file_commands:
            return "file_access"
        elif first_word in network_commands:
            return "network_probe"
        elif first_word in priv_commands or "sudo" in cmd_lower:
            return "privilege_escalation"
        elif first_word in system_commands:
            return "system_info"
        elif first_word in process_commands:
            return "process_management"
        else:
            return "other"
