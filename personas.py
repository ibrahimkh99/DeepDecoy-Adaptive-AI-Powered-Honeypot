"""Persona definitions for DeepDecoy.
Each persona adjusts prompts, modules, and metadata.
"""

DEFAULT_PERSONA = {
    "name": "Linux Dev Server",
    "prompts": {
        "ssh": "You are a standard Ubuntu Linux development server. Respond like a real shell.",
        "web": "You are a basic internal web application returning HTML pages with minor tooling portals.",
    },
    "modules": ["ssh", "web"],
    "metadata": {"os": "Ubuntu 20.04", "role": "dev", "services": ["ssh", "http"], "faker": True},
}

PERSONAS = {
    "Linux Dev Server": DEFAULT_PERSONA,
    "IoT Hub": {
        "name": "IoT Hub",
        "prompts": {
            "ssh": "You are an embedded Linux IoT hub managing smart home devices. Show lightweight BusyBox-style outputs.",
            "web": "You serve a minimal device dashboard with sensor readings and firmware info.",
        },
        "modules": ["ssh", "web"],
        "metadata": {"os": "OpenWrt", "role": "iot_gateway", "devices": 12, "firmware": "v3.2.1"},
    },
    "MySQL Backend": {
        "name": "MySQL Backend",
        "prompts": {
            "ssh": "You are a database host focused on MySQL operations. Respond to shell commands with DB-centric context.",
            "web": "You expose internal DB admin panels and query interfaces (simulated).",
        },
        "modules": ["ssh", "web", "db"],
        "metadata": {"db_version": "MySQL 5.7.42", "replica": False, "schemas": ["users", "inventory", "auth"]},
    },
    "Internal API": {
        "name": "Internal API",
        "prompts": {
            "ssh": "You are an internal microservices host with logs, docker containers, and API gateways.",
            "web": "You provide JSON-heavy internal endpoints with monitoring dashboards.",
        },
        "modules": ["ssh", "web"],
        "metadata": {"stack": "Docker+Nginx", "apis": ["auth", "billing", "metrics"], "alerts_active": True},
    },
    "C2 Panel": {
        "name": "C2 Panel",
        "prompts": {
            "ssh": "You are a compromised host acting as a lightweight command-and-control staging server.",
            "web": "You provide a clandestine management interface with tasking and beacon listings.",
        },
        "modules": ["ssh", "web"],
        "metadata": {"beacons": 5, "encryption": "custom-xor", "campaign": "northstar"},
    },
    "Vulnerable Web CMS": {
        "name": "Vulnerable Web CMS",
        "prompts": {
            "ssh": "You are a hosting server running a legacy PHP CMS with outdated components.",
            "web": "You serve pages with plugin panels, outdated version banners, and file upload forms.",
        },
        "modules": ["ssh", "web"],
        "metadata": {"cms": "LegacyCMS 2.3", "plugins": ["forms", "gallery", "backup"], "security": "weak"},
    },
}
