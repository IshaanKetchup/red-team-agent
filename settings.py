import os

from dotenv import load_dotenv

load_dotenv()

# Network configuration
TARGET_NETWORK = os.getenv("TARGET_NETWORK", "192.0.2.0/24")
KALI_IP = os.getenv("KALI_IP", "192.0.2.103")
DC_IP = os.getenv("DC_IP", "192.0.2.10")

# Active Directory configuration
DOMAIN_DN = os.getenv("DOMAIN_DN", "DC=example,DC=local")
LDAP_HOST = os.getenv("LDAP_HOST", "dc.example.local")
LDAP_PORT = int(os.getenv("LDAP_PORT", "636"))
LDAP_USER = os.getenv("LDAP_USER", "redteam.reader@example.local")

# TLS certificate authority bundle
CA_CERTS = os.getenv(
    "CA_CERTS",
    "/etc/ssl/certs/ca-certificates.crt"
)

# Domain name used to identify AD findings
DOMAIN_LABEL = ".".join(
    component.strip()[3:]
    for component in DOMAIN_DN.split(",")
    if component.strip().upper().startswith("DC=")
).upper()
