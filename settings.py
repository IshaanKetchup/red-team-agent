import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

# Network configuration
TARGET_NETWORK = os.getenv("TARGET_NETWORK", "192.0.2.0/24")
KALI_IP = os.getenv("KALI_IP", "192.0.2.103")
DC_IP = os.getenv("DC_IP", "192.0.2.10")

# Active Directory configuration
DOMAIN_DN = os.getenv("DOMAIN_DN", "DC=example,DC=local")
LDAP_HOST = os.getenv("LDAP_HOST", "dc.example.local")
LDAP_PORT = int(os.getenv("LDAP_PORT", "636"))
LDAP_USER = os.getenv("LDAP_USER", "redteam.reader@example.local")
LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")

# TLS certificate authority bundle
CA_CERTS = os.getenv(
    "CA_CERTS",
    "/etc/ssl/certs/ca-certificates.crt",
)

DOMAIN_LABEL = ".".join(
    component.strip()[3:]
    for component in DOMAIN_DN.split(",")
    if component.strip().upper().startswith("DC=")
).upper()

# LLM providers
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

LLM_MAX_TURNS = int(os.getenv("LLM_MAX_TURNS", "8"))
LLM_REQUEST_TIMEOUT = int(os.getenv("LLM_REQUEST_TIMEOUT", "20"))

# MCP
MCP_SERVER_PATH = PROJECT_ROOT / "mcp_server.py"
