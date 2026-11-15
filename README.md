# Red Team Agent

A Python-based network and Active Directory reconnaissance and analysis tool for authorised security assessments in controlled environments.

Red Team Agent combines network discovery, service enumeration, LDAP-based Active Directory collection, deterministic detection rules, privilege relationship analysis, and persistent SQLite storage.

It includes a command-line interface and a Streamlit dashboard.

## Features

### Network reconnaissance
- Network host discovery using Nmap.
- TCP service enumeration across ports 1–1024.
- Service and version detection.
- Host and service inventory persistence.

### Active Directory enumeration
- Domain Controller identification.
- LDAP RootDSE discovery.
- LDAPS connectivity and certificate validation.
- Authenticated AD user enumeration.
- Domain, user, group, and group membership collection.
- Password policy collection.
- Primary group membership resolution.
- Nested group membership analysis.

### Security analysis
- Deterministic detection rules for:
  - Domain Controllers
  - SMB exposure
  - LDAP and LDAPS exposure
  - Active Directory users
  - Privilege-related group memberships
- Sensitive group identification using SIDs.
- Direct and nested privilege path analysis.
- Stable finding identities.
- Finding lifecycle tracking (`ACTIVE` / `RESOLVED`).

### Data management
- SQLite-based persistence.
- Scan run history.
- Host and service reconciliation.
- Stale AD object reconciliation.
- Transactional scan persistence and rollback on database failure.

### Dashboard
The Streamlit dashboard provides:
- Host and service inventory.
- Active Directory domain information.
- AD users and groups.
- Group membership relationships.
- Privilege analysis.
- Security findings with severity and status filters.
- Scan history and activity logs.
- Controls for full scans and individual collection operations.

## Architecture

```text
red-team-agent/
├── app.py
├── main.py
├── settings.py
├── requirements.txt
├── database/
│   ├── storage.py
│   └── ad_storage.py
├── engine/
│   ├── orchestrator.py
│   ├── rules.py
│   ├── ad_analysis.py
│   └── tool_registry.py
├── scanner/
│   ├── network.py
│   ├── nmap.py
│   ├── smb.py
│   ├── ldap.py
│   └── ad.py
└── tests/
```

**Component responsibilities**

- `scanner/` — network and Active Directory data collection.
- `engine/` — scan orchestration, detection rules, and AD analysis.
- `database/` — SQLite persistence and reconciliation.
- `app.py` — Streamlit dashboard.
- `main.py` — command-line entry point.
- `settings.py` — environment-based configuration.
- `tests/` — automated unit tests.

## Requirements

- Linux (Kali Linux recommended).
- Python 3.14 tested.
- Nmap installed and accessible through `PATH`.
- An Active Directory environment for AD collection.
- A read-only or appropriately restricted AD account.
- Network connectivity to the authorised assessment targets.

Install Nmap on Kali Linux:

```bash
sudo apt update
sudo apt install nmap
```

## Installation

Clone the repository:

```bash
git clone https://github.com/IshaanKetchup/red-team-agent.git
cd red-team-agent
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Create your local environment file:

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
# Network configuration
TARGET_NETWORK=192.0.2.0/24
KALI_IP=192.0.2.103
DC_IP=192.0.2.10

# Active Directory configuration
DOMAIN_DN=DC=example,DC=local
LDAP_HOST=dc.example.local
LDAP_PORT=636
LDAP_USER=redteam.reader@example.local

# TLS certificate authority bundle
CA_CERTS=/etc/ssl/certs/ca-certificates.crt
```

Replace the example values with the details of your authorised assessment environment.

Configuration variables:

| Variable | Description |
|---|---|
| `TARGET_NETWORK` | Network CIDR to discover |
| `KALI_IP` | Scanner IP, excluded from service enumeration |
| `DC_IP` | Domain Controller IP |
| `DOMAIN_DN` | Active Directory distinguished name |
| `LDAP_HOST` | Domain Controller hostname used for LDAP |
| `LDAP_PORT` | LDAP port; defaults to 636 |
| `LDAP_USER` | Account used for authenticated LDAP collection |
| `CA_CERTS` | Path to the trusted CA certificate or CA bundle |

The LDAP server certificate must be trusted by the configured CA certificate file or bundle.

**Do not commit `.env`, private certificates, databases, or credentials.**

## Usage

### Command-line scan

Activate the virtual environment and run:

```bash
python main.py
```

The application prompts for the LDAP password using a hidden password input.

### Streamlit dashboard

Run:

```bash
streamlit run app.py
```

Open the local URL printed by Streamlit.

The dashboard supports full scans and individual host discovery, service enumeration, and AD enumeration operations.

## Running tests

Run the automated test suite:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

The current test suite contains 52 tests covering detection rules, AD analysis, persistence, reconciliation, scan orchestration, and transaction rollback.

These are automated unit tests; they do not replace validation against a real assessment environment.

## Security and scope

This project is intended for authorised security assessments and isolated lab environments.

- Only scan networks and systems you have permission to assess.
- Use appropriately restricted AD credentials.
- Keep credentials and private CA material outside version control.
- Review the configured network scope before running scans.
- The detection and analysis engine uses deterministic rules; findings should be validated against the target environment.

## Current limitations

- Network service enumeration is limited to TCP ports 1–1024.
- AD collection requires a reachable LDAP/LDAPS service and valid credentials.
- Detection rules identify configured patterns and exposures; they do not establish that a system is exploitable.
- Results depend on the visibility and permissions available to the scanner account.

## Development status

The project currently implements network discovery, service enumeration, AD collection, deterministic analysis, SQLite persistence, and a Streamlit dashboard.

MCP tool integration and LLM-assisted analysis are planned extensions and are not currently implemented.

## License

No license has been specified yet. All rights reserved unless a license is added to this repository.
