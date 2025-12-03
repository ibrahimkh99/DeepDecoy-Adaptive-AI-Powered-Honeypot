"""
DeepDecoy - AI-Powered Honeypot System
Main entry point for SSH, Web services, and adaptive deception engine.
"""

import socket
import threading
import paramiko
import os
import sys
import uuid
from datetime import datetime
from io import StringIO

from config import Config
from ai_shell import AIShell
from session_logger import SessionLogger
from analyzer import SessionAnalyzer
from deception_engine import DeceptionEngine

# Import web server if enabled
if Config.ENABLE_WEB:
    from web_server import start_web_honeypot


class HoneypotSSHServer(paramiko.ServerInterface):
    """SSH Server Interface for the honeypot."""
    
    def __init__(self):
        """Initialize the SSH server interface."""
        self.event = threading.Event()
    
    def check_auth_password(self, username: str, password: str) -> int:
        """
        Accept any username/password combination.
        
        Args:
            username: Username provided by client
            password: Password provided by client
            
        Returns:
            AUTH_SUCCESSFUL to allow login
        """
        # Log the authentication attempt
        print(f"[+] Login attempt - Username: {username}, Password: {password}")
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        """
        Handle channel requests.
        
        Args:
            kind: Type of channel request
            chanid: Channel ID
            
        Returns:
            OPEN_SUCCEEDED for session requests
        """
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel) -> bool:
        """
        Handle shell requests.
        
        Args:
            channel: The channel requesting a shell
            
        Returns:
            True to allow shell access
        """
        self.event.set()
        return True
    
    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        """
        Handle PTY requests.
        
        Returns:
            True to allow PTY allocation
        """
        return True


def generate_ssh_key():
    """Generate an RSA key for the SSH server if it doesn't exist."""
    key_file = Config.SSH_KEY_FILE
    
    if not os.path.exists(key_file):
        print(f"[*] Generating RSA key: {key_file}")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_file)
        print(f"[+] RSA key generated successfully")
    else:
        print(f"[*] Using existing RSA key: {key_file}")
    
    return paramiko.RSAKey.from_private_key_file(key_file)


def handle_client(client_socket, client_addr):
    """
    Handle an individual SSH client connection.
    
    Args:
        client_socket: Socket connection to the client
        client_addr: Client address tuple (ip, port)
    """
    session_id = str(uuid.uuid4())
    client_ip = client_addr[0]
    
    print(f"[+] New connection from {client_ip} (Session: {session_id[:8]})")
    
    try:
        # Create SSH transport
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(generate_ssh_key())
        
        # Create server interface
        server = HoneypotSSHServer()
        transport.start_server(server=server)
        
        # Wait for authentication
        channel = transport.accept(20)
        if channel is None:
            print(f"[!] No channel from {client_ip}")
            return
        
        # Get authenticated username
        username = transport.get_username() or "unknown"
        
        # Initialize AI shell, deception engine and logger
        ai_shell = AIShell()
        deception = DeceptionEngine()
        logger = SessionLogger(session_id, client_ip, username)
        # Record initial persona metadata
        logger.set_initial_persona(
            deception.current_persona.name,
            deception.persona_metadata()
        )
        
        print(f"[+] {client_ip} authenticated as '{username}'")
        
        # Send welcome message (MOTD)
        motd = ai_shell.get_motd()
        timestamp = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        last_login = (datetime.now()).strftime("%a %b %d %H:%M:%S %Y from 192.168.1.50")
        motd = motd.format(timestamp=timestamp, last_login=last_login)
        
        channel.send(motd + "\r\n")
        
        # Main command loop
        command_buffer = ""
        
        while True:
            # Send prompt
            prompt = ai_shell.get_prompt()
            channel.send(prompt)
            
            # Read command
            command_buffer = ""
            while True:
                try:
                    char = channel.recv(1).decode("utf-8", errors="ignore")
                    
                    if not char:
                        # Connection closed
                        raise ConnectionError("Connection closed by client")
                    
                    # Handle special characters
                    if char == "\r" or char == "\n":
                        # Command complete
                        channel.send("\r\n")
                        break
                    elif char == "\x03":  # Ctrl+C
                        channel.send("^C\r\n")
                        command_buffer = ""
                        break
                    elif char == "\x04":  # Ctrl+D (EOF/logout)
                        channel.send("logout\r\n")
                        raise ConnectionError("User logout (Ctrl+D)")
                    elif char == "\x7f" or char == "\x08":  # Backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            # Erase character on screen
                            channel.send("\x08 \x08")
                    else:
                        # Regular character
                        command_buffer += char
                        channel.send(char)  # Echo back
                
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    raise
            
            # Process command if not empty
            command = command_buffer.strip()
            
            if not command:
                continue
            
            # Handle exit commands
            if command.lower() in ["exit", "logout", "quit"]:
                channel.send("logout\r\n")
                break
            
            # Execute command with AI
            try:
                output = ai_shell.execute_command(command)
                category = ai_shell.categorize_command(command)
                logger.log_command(command, output, category)
                if output:
                    channel.send(output + "\r\n")
            except Exception as e:
                error_msg = f"bash: error processing command: {str(e)}"
                channel.send(error_msg + "\r\n")
                logger.log_command(command, error_msg, "error")

            # Deception engine evaluation after each command
            deception.record_interaction("ssh", command)
            if deception.should_evaluate():
                transition = deception.evaluate()
                if transition:
                    # Update shell persona prompt
                    persona_prompt = deception.get_persona_prompt("ssh")
                    ai_shell.update_persona(persona_prompt)
                    # Log transition
                    logger.log_persona_transition({
                        "timestamp": transition.timestamp,
                        "previous": transition.previous,
                        "new": transition.new,
                        "reason": transition.reason,
                        "modules": transition.modules
                    })
                    channel.send(f"[deception] System profile adapting to '{transition.new}' persona\r\n")
        
        # Close session
        logger.close_session()
        
        # Generate AI threat analysis
        print(f"[*] Analyzing session {session_id[:8]}...")
        try:
            analyzer = SessionAnalyzer()
            
            # Analyze the session
            analysis = analyzer.analyze_session(logger.commands)
            
            # Generate AI summary
            summary = analyzer.generate_summary(
                client_ip=client_ip,
                username=username,
                duration=logger.get_summary()['duration_seconds'],
                commands=logger.commands,
                analysis=analysis
            )
            
            # Determine threat level
            threat_level = analyzer.get_threat_level(
                analysis['suspicious_score'],
                analysis['flagged_count']
            )
            
            # Update logger with analysis
            logger.set_threat_analysis(
                threat_tags=analysis['threat_tags'],
                suspicious_score=analysis['suspicious_score'],
                threat_level=threat_level,
                session_summary=summary
            )
            
            # Write summary to separate file
            summary_filename = logger.log_filename.replace(".json", ".summary.txt")
            summary_filepath = os.path.join(Config.LOGS_DIR, summary_filename)
            with open(summary_filepath, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("DEEPDECOY THREAT INTELLIGENCE REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Session ID:        {session_id}\n")
                f.write(f"Client IP:         {client_ip}\n")
                f.write(f"Username:          {username}\n")
                f.write(f"Threat Level:      {threat_level}\n")
                f.write(f"Suspicious Score:  {analysis['suspicious_score']}\n")
                f.write(f"Threat Tags:       {', '.join(analysis['threat_tags']) if analysis['threat_tags'] else 'None'}\n")
                f.write(f"Flagged Commands:  {analysis['flagged_count']} of {analysis['total_commands']}\n\n")
                f.write("=" * 80 + "\n")
                f.write("AI SECURITY ASSESSMENT\n")
                f.write("=" * 80 + "\n\n")
                f.write(summary + "\n")
            
            print(f"[+] Session {session_id[:8]} analyzed - Threat Level: {threat_level}, Score: {analysis['suspicious_score']}")
        
        except Exception as e:
            print(f"[!] Error analyzing session: {e}")
        
        print(f"[+] Session {session_id[:8]} closed - {logger.get_summary()['total_commands']} commands executed")
        
    except Exception as e:
        print(f"[!] Error handling client {client_ip}: {e}")
    
    finally:
        try:
            transport.close()
        except:
            pass
        
        try:
            client_socket.close()
        except:
            pass


def start_ssh_honeypot():
    """Start the SSH honeypot server."""
    try:
        print(f"[*] Starting SSH server on {Config.SSH_HOST}:{Config.SSH_PORT}")
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((Config.SSH_HOST, Config.SSH_PORT))
        server_socket.listen(100)
        
        print(f"[+] SSH Honeypot listening on port {Config.SSH_PORT}")
        
        # Accept connections
        while True:
            client_socket, client_addr = server_socket.accept()
            
            # Handle each client in a separate thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_addr),
                daemon=True
            )
            client_thread.start()
    
    except Exception as e:
        print(f"[!] SSH honeypot error: {e}")


def start_all_services():
    """Start all enabled honeypot services."""
    try:
        # Validate configuration
        Config.validate()
        
        print("=" * 70)
        print("DeepDecoy - Adaptive Multi-Persona Honeypot")
        print("=" * 70)
        print(f"[*] OpenAI Model: {Config.OPENAI_MODEL}")
        print(f"[*] Hostname: {Config.HOSTNAME}")
        print(f"[*] Logs directory: {Config.LOGS_DIR}")
        print("=" * 70)
        print("[!] WARNING: This is a honeypot. No real commands are executed.")
        print("[!] All interactions are simulated by AI and logged.")
        print("=" * 70)
        
        services = []
        
        # Start SSH honeypot in a separate thread
        ssh_thread = threading.Thread(target=start_ssh_honeypot, daemon=True)
        ssh_thread.start()
        services.append("SSH")
        
        # Start Web honeypot if enabled
        if Config.ENABLE_WEB:
            web_thread = threading.Thread(target=start_web_honeypot, daemon=True)
            web_thread.start()
            services.append("Web")
        
        print(f"\n[+] Active services: {', '.join(services)}")
        # Display configured evaluation interval dynamically
        print(f"[+] Deception Engine: ENABLED (evaluation interval={Config.DECEPTION_EVAL_INTERVAL})")
        print("[*] Press Ctrl+C to stop all services\n")
        
        # Keep main thread alive
        while True:
            threading.Event().wait(1)
    
    except KeyboardInterrupt:
        print("\n[*] Shutting down all services...")
        sys.exit(0)
    
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)


def start_honeypot():
    """Legacy function - redirects to start_all_services."""
    start_all_services()


if __name__ == "__main__":
    import sys
    # Add simple CLI for learning and dashboard
    if len(sys.argv) > 1 and sys.argv[1].lower() == 'learn':
        from learning_engine import learn
        use_sqlite = os.environ.get('USE_SQLITE', 'true').lower() == 'true'
        db_path = os.environ.get('LEARNING_DB_PATH', os.path.join('data', 'deepdecoy.db'))
        strat_json = os.environ.get('STRATEGY_JSON_PATH', os.path.join('data', 'strategy_config.json'))
        result = learn(db_path=db_path, strategy_json=strat_json, use_sqlite=use_sqlite)
        print(result)
    else:
        start_honeypot()
        from config import Config
        if getattr(Config, 'ENABLE_DASHBOARD', False):
            # Start dashboard in-process (simple dev mode). For production, run separately.
            import threading
            def _start_dashboard():
                import dashboard
                dashboard.app.run(host='127.0.0.1', port=Config.DASHBOARD_PORT, debug=False)
            t = threading.Thread(target=_start_dashboard, daemon=True)
            t.start()
