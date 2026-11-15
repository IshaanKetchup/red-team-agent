from settings import DOMAIN_LABEL

def _normalise_identity(value):
    return " ".join(str(value or "").strip().casefold().split())


def _user_identity(user):
    sid = user.get("objectSid") or user.get("object_sid")
    sam = user.get("sAMAccountName") or user.get("sam_account_name")

    if sid:
        return f"user:{sid}"

    if sam:
        return f"user:sam:{_normalise_identity(sam)}"

    return None


def detect_domain_controllers(services):
    """Identify hosts exposing both Kerberos and LDAP."""

    host_ports = {}

    for service in services:
        if service["protocol"] == "tcp":
            host_ports.setdefault(service["host_ip"], set()).add(
                service["port"]
            )

    findings = []

    for ip, ports in host_ports.items():
        if 88 in ports and 389 in ports:
            findings.append({
                "rule": "DOMAIN_CONTROLLER",
                "severity": "INFO",
                "host": ip,
                "finding_key": "host",
                "evidence": "TCP ports 88 and 389 are open"
            })

    return findings


def detect_smb_exposure(services):
    """Identify hosts exposing SMB."""

    findings = []

    for service in services:
        if service["port"] == 445 and service["protocol"] == "tcp":
            findings.append({
                "rule": "SMB_EXPOSURE",
                "severity": "INFO",
                "host": service["host_ip"],
                "finding_key": "host",
                "evidence": "TCP port 445 is open"
            })

    return findings


def detect_ldap_exposure(services):
    """Identify LDAP and LDAPS exposure."""

    host_ports = {}

    for service in services:
        if service["protocol"] == "tcp":
            host_ports.setdefault(service["host_ip"], set()).add(
                service["port"]
            )

    findings = []

    for ip, ports in host_ports.items():
        if 389 in ports:
            findings.append({
                "rule": "LDAP_EXPOSURE",
                "severity": "INFO",
                "host": ip,
                "finding_key": "host",
                "evidence": (
                    "TCP port 389 is open; assess encryption "
                    "and LDAP signing requirements"
                )
            })

        if 636 in ports:
            findings.append({
                "rule": "LDAPS_EXPOSURE",
                "severity": "INFO",
                "host": ip,
                "finding_key": "host",
                "evidence": "TCP port 636 is open"
            })

    return findings


def detect_ad_users(users):
    """Report domain accounts discovered during the current run."""

    findings = []

    for user in users:
        sam = user.get("sAMAccountName") or user.get("sam_account_name")
        identity = _user_identity(user)

        if not sam or not identity:
            continue

        legacy_key = f"legacy:user:{_normalise_identity(sam)}"

        findings.append({
            "rule": "AD_USER_DISCOVERED",
            "severity": "INFO",
            "host": DOMAIN_LABEL,
            "finding_key": identity,
            "legacy_key": legacy_key,
            "evidence": f"Account discovered: {sam}"
        })

    return findings


def detect_ad_privilege_paths(analysis):
    """
    Report users with direct or nested paths to sensitive groups.

    Membership is an observation, not proof of misconfiguration.
    """

    findings = []

    if not analysis:
        return findings

    for item in analysis.get("paths", []):
        sam = item.get("sam_account_name") or "UNKNOWN"
        group_name = item.get("target_group") or "Unknown group"
        category = item.get("category") or "UNKNOWN"
        relationship = item.get("relationship") or "UNKNOWN"
        path = item.get("path") or []

        source_sid = item.get("source_sid")
        target_sid = item.get("target_group_sid")

        if source_sid and target_sid:
            finding_key = (
                f"user:{source_sid}"
                f"|group:{target_sid}"
                f"|relationship:{relationship}"
            )
        else:
            finding_key = (
                f"privilege:user:{_normalise_identity(sam)}"
                f"|group:{_normalise_identity(group_name)}"
                f"|relationship:{relationship}"
            )

        legacy_key = (
            f"legacy:priv:{_normalise_identity(sam)}"
            f":{_normalise_identity(group_name)}"
            f":{relationship.casefold()}"
        )

        path_text = " -> ".join(str(part) for part in path)

        evidence = (
            f"Account {sam} has {relationship.lower()} membership path "
            f"to {group_name} ({category}). Path: {path_text}. "
            "Review whether this access is required and authorised."
        )

        findings.append({
            "rule": "AD_PRIVILEGED_MEMBERSHIP",
            "severity": "INFO",
            "host": DOMAIN_LABEL,
            "finding_key": finding_key,
            "legacy_key": legacy_key,
            "evidence": evidence
        })

    return findings


def run_all_rules(services, users=None, ad_analysis=None):
    """Run detection rules against current-run observations."""

    findings = []

    findings.extend(detect_domain_controllers(services))
    findings.extend(detect_smb_exposure(services))
    findings.extend(detect_ldap_exposure(services))

    if users is not None:
        findings.extend(detect_ad_users(users))

    if ad_analysis is not None:
        findings.extend(detect_ad_privilege_paths(ad_analysis))

    return findings
