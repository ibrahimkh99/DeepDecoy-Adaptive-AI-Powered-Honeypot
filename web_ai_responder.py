"""
DeepDecoy Web AI Responder
Generates realistic HTTP responses using GPT for web honeypot with persona overrides.
"""

import os
import json
from typing import Dict, Any, Tuple
from openai import OpenAI
from config import Config


class WebAIResponder:
    """AI-powered HTTP response generator for web honeypot."""
    
    def __init__(self):
        """Initialize the web AI responder with OpenAI client (disabled in offline mode)."""
        self.client = None
        self.model = Config.OPENAI_MODEL
        if not Config.DISABLE_OPENAI and Config.OPENAI_API_KEY:
            try:
                self.client = OpenAI(api_key=Config.OPENAI_API_KEY)
            except Exception:
                self.client = None
        
        # Load prompt templates
        self.web_prompt = self._load_prompt("http_web_prompt.txt")
        self.api_prompt = self._load_prompt("http_api_prompt.txt")
        # Persona override
        self.persona_prompt_override: str | None = None
    
    def _load_prompt(self, filename: str) -> str:
        """Load a prompt template from the prompts directory."""
        prompt_file = os.path.join(Config.PROMPTS_DIR, filename)
        
        if os.path.exists(prompt_file):
            with open(prompt_file, "r", encoding="utf-8") as f:
                return f.read()
        
        # Default prompts if files don't exist
        if "api" in filename:
            return self._get_default_api_prompt()
        else:
            return self._get_default_web_prompt()
    
    def _get_default_web_prompt(self) -> str:
        """Default prompt for HTML/web UI responses."""
        return """You are simulating a realistic but vulnerable web server.

Generate an authentic HTML page or web response for the following HTTP request.

REQUEST DETAILS:
- Method: {method}
- Path: {path}
- Query: {query}
- Headers: {headers}
- Body: {body}

REQUIREMENTS:
1. Return valid HTML5 with realistic structure
2. Include appropriate <head>, <body>, forms, links
3. Make it look like a real web application (login pages, dashboards, admin panels)
4. Include realistic but FAKE data (usernames, emails, tokens, logs)
5. Add subtle vulnerabilities if the path suggests exploitation (e.g., /admin, /debug)
6. Use realistic CSS classes, JavaScript references
7. Never break character or mention AI

If the path is common (/, /login, /admin, /dashboard), provide appropriate pages.
If the path is suspicious (/shell.php, /config.bak), return realistic error or debug output.

RESPOND ONLY with the HTML content. No explanations."""
    
    def _get_default_api_prompt(self) -> str:
        """Default prompt for JSON/API responses."""
        return """You are simulating a realistic REST API endpoint.

Generate an authentic JSON API response for the following HTTP request.

REQUEST DETAILS:
- Method: {method}
- Path: {path}
- Query: {query}
- Headers: {headers}
- Body: {body}

REQUIREMENTS:
1. Return valid JSON with realistic structure
2. Include appropriate status, data, metadata fields
3. Generate realistic but FAKE data (user objects, device lists, logs, tokens)
4. Match the API path semantics (e.g., /api/users returns user array, /api/devices returns device list)
5. For POST/PUT, acknowledge the operation with realistic response
6. Include subtle security issues if path suggests it (e.g., /api/admin/debug)
7. Use realistic field names: id, username, email, created_at, token, status
8. Never break character or mention AI

Common patterns:
- GET /api/user → {{"id": 1, "username": "admin", "email": "admin@example.com"}}
- GET /api/devices → {{"devices": [...]}}
- POST /api/login → {{"token": "abc123...", "user": {{...}}}}

RESPOND ONLY with the JSON content. No explanations."""
    
    def generate_response(
        self,
        method: str,
        path: str,
        query: str,
        headers: Dict[str, str],
        body: str
    ) -> Tuple[str, str, int]:
        """
        Generate an AI-powered HTTP response.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            query: Query string
            headers: Request headers dict
            body: Request body content
            
        Returns:
            Tuple of (response_body, content_type, status_code)
        """
        # Determine if this is an API or web UI request
        is_api = path.startswith("/api") or "application/json" in headers.get("Accept", "")
        
        # Select appropriate prompt template
        prompt_template = self.api_prompt if is_api else self.web_prompt
        
        # Format the prompt with request details
        prompt = prompt_template.format(
            method=method,
            path=path,
            query=query if query else "None",
            headers=str(headers),
            body=body if body else "None"
        )
        if self.persona_prompt_override:
            prompt += "\n\nPersona Context:\n" + self.persona_prompt_override
        
        # Deterministic fallbacks for common API endpoints (no AI required)
        if path.startswith("/api"):
            path_lower = path.lower()
            if path_lower.startswith("/api/users") and method == "GET":
                fallback = {
                    "users": [
                        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "administrator", "created_at": "2025-01-10T09:15:00Z"},
                        {"id": 2, "username": "john.doe", "email": "john.doe@example.com", "role": "developer", "created_at": "2025-02-18T12:02:00Z"},
                        {"id": 3, "username": "jane.smith", "email": "jane.smith@example.com", "role": "analyst", "created_at": "2025-03-05T18:42:00Z"}
                    ],
                    "total": 3,
                    "page": 1,
                    "status": "ok"
                }
                return json.dumps(fallback), "application/json", 200
            if path_lower.startswith("/api/status") and method == "GET":
                fallback = {
                    "service": "DeepDecoy Web Honeypot",
                    "version": "",
                    "status": "healthy",
                    "uptime_seconds": 42,
                    "endpoints": ["/", "/login", "/admin", "/api/users", "/api/status"],
                    "note": "This is a simulated service. Responses are generated for deception."
                }
                return json.dumps(fallback), "application/json", 200

        try:
            # If offline or client unavailable, return deterministic fallbacks
            if Config.DISABLE_OPENAI or not self.client:
                if is_api:
                    # Generic API fallback
                    return json.dumps({"status": "ok", "note": "simulated api (offline mode)"}), "application/json", self._determine_status_code(path, method)
                else:
                    html = (
                        "<!DOCTYPE html><html><head><title>DeepDecoy</title></head>"
                        "<body><h1>DeepDecoy Web Honeypot</h1><p>Simulated page (offline mode).</p></body></html>"
                    )
                    return html, "text/html", self._determine_status_code(path, method)

            # Call GPT API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a web server simulator. Generate realistic HTTP responses while maintaining deception persona consistency."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            response_body = response.choices[0].message.content.strip()
            
            # Determine content type
            if is_api or response_body.strip().startswith("{") or response_body.strip().startswith("["):
                content_type = "application/json"
            else:
                content_type = "text/html"
            
            # Determine status code based on path
            status_code = self._determine_status_code(path, method)
            
            return response_body, content_type, status_code
        
        except Exception as e:
            # Graceful fallback without 500 to avoid detection
            if path.startswith("/api"):
                error_body = {
                    "error": "temporary_unavailable",
                    "message": "Service temporarily unavailable",
                    "hint": "This is a simulated API endpoint",
                    "status": 503
                }
                return json.dumps(error_body), "application/json", 200
            # For web pages, return a simple HTML stub
            html = (
                "<!DOCTYPE html><html><head><title>Service Notice</title></head>"
                "<body><h1>Welcome</h1><p>This is a simulated web service."
                "</p><p>Status: Operational</p></body></html>"
            )
            return html, "text/html", 200
    
    def _determine_status_code(self, path: str, method: str) -> int:
        """Determine realistic HTTP status code based on path and method."""
        # Login/auth paths
        if "login" in path.lower() or "auth" in path.lower():
            return 200 if method == "POST" else 200
        
        # Admin/protected paths
        if "admin" in path.lower() or "dashboard" in path.lower():
            return 200  # Pretend they have access for deception
        
        # API endpoints
        if path.startswith("/api"):
            if method == "POST":
                return 201  # Created
            elif method == "PUT" or method == "PATCH":
                return 200  # Updated
            elif method == "DELETE":
                return 204  # No content
            else:
                return 200  # OK
        
        # Default
        return 200
    
    def categorize_request(self, method: str, path: str, body: str) -> str:
        """
        Categorize the HTTP request for logging purposes.
        
        Returns:
            Category string: recon, exploit, brute_force, injection, or normal
        """
        path_lower = path.lower()
        body_lower = body.lower() if body else ""
        
        # SQL Injection patterns
        sql_patterns = ["'", "union", "select", "drop", "insert", "delete", "--", ";--"]
        if any(pattern in path_lower or pattern in body_lower for pattern in sql_patterns):
            return "sql_injection"
        
        # XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror=", "onload="]
        if any(pattern in path_lower or pattern in body_lower for pattern in xss_patterns):
            return "xss_attempt"
        
        # Directory traversal
        if "../" in path or "..%2f" in path_lower:
            return "directory_traversal"
        
        # Brute force / credential testing
        if method == "POST" and ("login" in path_lower or "auth" in path_lower):
            return "brute_force"
        
        # Common scanner paths
        scanner_paths = [
            "/wp-admin", "/phpmyadmin", "/.git", "/.env", "/config",
            "/backup", "/.well-known", "/xmlrpc", "/shell", "/.ssh"
        ]
        if any(scanner in path_lower for scanner in scanner_paths):
            return "recon"
        
        # Admin/sensitive paths
        if "admin" in path_lower or "debug" in path_lower or "test" in path_lower:
            return "privilege_probe"
        
        # API endpoints
        if path.startswith("/api"):
            return "api_access"
        
        return "normal"

    # Persona support ---------------------------------------------------
    def update_persona(self, persona_prompt: str | None):
        self.persona_prompt_override = persona_prompt
