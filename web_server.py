"""
DeepDecoy Web Server
Flask-based HTTP honeypot with AI-generated responses and adaptive persona support.
"""

from flask import Flask, request, Response
import json
import os
from datetime import datetime
from typing import Dict, Any
import uuid

from config import Config
from web_ai_responder import WebAIResponder
from deception_engine import DeceptionEngine


class WebHoneypot:
    """Flask web honeypot with AI-powered responses."""
    
    def __init__(self):
        """Initialize the web honeypot."""
        self.app = Flask(__name__)
        self.app.config['JSON_SORT_KEYS'] = False
        self.ai_responder = WebAIResponder()
        # Per-IP deception engines (multi-protocol persona coherence)
        self.deception_engines: Dict[str, DeceptionEngine] = {}
        
        # Disable Flask logging to reduce noise
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        # Set up routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Set up Flask routes with catch-all handler."""
        # Catch all routes with all methods
        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
        @self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
        def catch_all(path):
            return self.handle_request(path)
    
    def handle_request(self, path: str) -> Response:
        """
        Handle any HTTP request with AI-generated response.
        
        Args:
            path: The request path
            
        Returns:
            Flask Response object
        """
        try:
            # Extract request details
            method = request.method
            full_path = "/" + path if path else "/"
            query = request.query_string.decode('utf-8')
            headers = dict(request.headers)

            # Get request body
            try:
                if request.is_json:
                    body = json.dumps(request.get_json())
                elif request.form:
                    body = json.dumps(dict(request.form))
                else:
                    body = request.get_data(as_text=True)
            except:
                body = ""

            # Get client IP
            client_ip = request.remote_addr or "unknown"

            # Log the request
            request_id = str(uuid.uuid4())
            print(f"[WEB] {client_ip} - {method} {full_path} - ID: {request_id[:8]}")

            # Acquire deception engine for this client IP
            engine = self.deception_engines.get(client_ip)
            if engine is None:
                engine = DeceptionEngine()
                self.deception_engines[client_ip] = engine
            # Record interaction
            engine.record_interaction("web", f"{method} {full_path}")

            # Categorize the request
            category = self.ai_responder.categorize_request(method, full_path, body)

            # Evaluate persona switching if due
            transition = None
            if engine.should_evaluate():
                transition = engine.evaluate()
                if transition:
                    # Update web responder persona
                    persona_prompt = engine.get_persona_prompt("web")
                    self.ai_responder.update_persona(persona_prompt)
                    print(f"[WEB] Persona shift for {client_ip}: {transition.previous} -> {transition.new}")

            # Generate AI response (with current persona)
            response_body, content_type, status_code = self.ai_responder.generate_response(
                method=method,
                path=full_path,
                query=query,
                headers=headers,
                body=body
            )

            # Log the interaction
            self._log_request(
                request_id=request_id,
                client_ip=client_ip,
                method=method,
                path=full_path,
                query=query,
                headers=headers,
                body=body,
                response_body=response_body,
                status_code=status_code,
                category=category,
                persona=engine.current_persona.name,
                transition=transition
            )

            # Return Flask response
            return Response(
                response_body,
                status=status_code,
                content_type=content_type
            )
        except Exception as e:
            # Global safety net: never 500, always return a plausible response
            try:
                fallback_json = {
                    "status": "ok",
                    "note": "Simulated service",
                    "error": str(e)[:120]
                }
                return Response(
                    json.dumps(fallback_json),
                    status=200,
                    content_type="application/json"
                )
            except:
                html = "<!DOCTYPE html><html><body><h1>Service</h1><p>Simulated response.</p></body></html>"
                return Response(html, status=200, content_type="text/html")
    
    def _log_request(
        self,
        request_id: str,
        client_ip: str,
        method: str,
        path: str,
        query: str,
        headers: Dict[str, str],
        body: str,
        response_body: str,
        status_code: int,
        category: str,
        persona: str,
        transition: Any
    ):
        """Log a web request to JSON and text files."""
        timestamp = datetime.now()
        
        # Create log entry
        log_entry = {
            "request_id": request_id,
            "timestamp": timestamp.isoformat(),
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "query": query,
            "headers": headers,
            "body": body,
            "response_status": status_code,
            "response_body": response_body[:500] + "..." if len(response_body) > 500 else response_body,
            "response_length": len(response_body),
            "category": category,
            "persona": persona
        }
        if transition:
            log_entry["persona_transition"] = {
                "timestamp": transition.timestamp,
                "previous": transition.previous,
                "new": transition.new,
                "reason": transition.reason,
                "modules": transition.modules
            }
        
        # Generate log filenames
        date_str = timestamp.strftime("%Y%m%d")
        json_filename = f"web_requests_{date_str}.json"
        txt_filename = f"web_requests_{date_str}.txt"
        
        json_filepath = os.path.join(Config.WEB_LOGS_DIR, json_filename)
        txt_filepath = os.path.join(Config.WEB_LOGS_DIR, txt_filename)
        
        # Append to JSON log
        try:
            # Read existing log if it exists
            if os.path.exists(json_filepath):
                with open(json_filepath, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
            else:
                log_data = {"requests": [], "persona_transitions": []}

            # Store transition summary globally
            if transition:
                log_data["persona_transitions"].append(log_entry["persona_transition"])
            
            # Append new request
            log_data["requests"].append(log_entry)
            
            # Write back
            with open(json_filepath, "w", encoding="utf-8") as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            print(f"[!] Error writing JSON log: {e}")
        
        # Append to text log
        try:
            with open(txt_filepath, "a", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"Request ID: {request_id}\n")
                f.write(f"Timestamp:  {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Client IP:  {client_ip}\n")
                f.write(f"Method:     {method}\n")
                f.write(f"Path:       {path}\n")
                if query:
                    f.write(f"Query:      {query}\n")
                f.write(f"Category:   {category}\n")
                f.write(f"Status:     {status_code}\n")
                f.write("\nHeaders:\n")
                for key, value in headers.items():
                    f.write(f"  {key}: {value}\n")
                if body:
                    f.write(f"\nRequest Body:\n{body[:200]}{'...' if len(body) > 200 else ''}\n")
                f.write(f"\nResponse ({len(response_body)} bytes):\n")
                f.write(response_body[:300] + ("..." if len(response_body) > 300 else "") + "\n")
                f.write("=" * 80 + "\n\n")
        
        except Exception as e:
            print(f"[!] Error writing text log: {e}")
    
    def run(self):
        """Start the Flask web server."""
        print(f"[*] Starting web honeypot on {Config.WEB_HOST}:{Config.WEB_PORT}")
        self.app.run(
            host=Config.WEB_HOST,
            port=Config.WEB_PORT,
            debug=False,
            threaded=True
        )


def start_web_honeypot():
    """Entry point to start the web honeypot."""
    try:
        honeypot = WebHoneypot()
        honeypot.run()
    except Exception as e:
        print(f"[!] Web honeypot error: {e}")


if __name__ == "__main__":
    Config.validate()
    start_web_honeypot()
