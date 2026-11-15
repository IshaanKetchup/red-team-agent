
import sqlite3
from contextlib import closing

from scanner.network import discover_hosts
from scanner.nmap import scan_services
from scanner.ad import enumerate_ad_data

from database.storage import (
    DB_PATH,
    initialize_database,
    initialize_services_table,
    initialize_users_table,
    initialize_findings_table,
    save_hosts,
    save_services,
    save_users,
    save_findings,
    get_hosts,
    start_scan_run,
    complete_scan_run,
    abort_scan_run
)

from database.ad_storage import (
    initialize_ad_tables,
    save_ad_data
)

from engine.ad_analysis import analyze_ad_data
from engine.rules import run_all_rules
from settings import TARGET_NETWORK, KALI_IP, DC_IP, DOMAIN_DN




def initialize():
    """Initialize all application database tables."""

    initialize_database()
    initialize_services_table()
    initialize_users_table()
    initialize_findings_table()
    initialize_ad_tables()


def run_discovery(log=print):
    """Discover hosts and update the host inventory."""

    initialize()

    log(f"Discovering hosts on {TARGET_NETWORK}...")

    hosts = discover_hosts(TARGET_NETWORK)

    if not hosts:
        raise RuntimeError("Network discovery returned no hosts.")

    save_hosts(hosts)

    log(f"Discovered {len(hosts)} hosts.")

    for host in hosts:
        log(f"Host: {host['ip']} ({host['status']})")

    return hosts


def run_service_enumeration(log=print):
    """Enumerate services on hosts in the existing inventory."""

    initialize()

    hosts = get_hosts()

    if not hosts:
        raise RuntimeError("No hosts in inventory. Run discovery first.")

    all_services = []

    for host in hosts:
        ip = host[0]

        if ip == KALI_IP:
            continue

        log(f"Enumerating services on {ip}...")

        services = scan_services(ip)
        save_services(services)
        all_services.extend(services)

        log(f"Found {len(services)} services on {ip}.")

    log(f"Service enumeration complete: {len(all_services)} services.")

    return all_services


def run_ad_enumeration(password: str, log=print):
    """Collect and persist Active Directory data."""

    initialize()

    if not password:
        raise ValueError("LDAP password is required.")

    log(f"Connecting to {DC_IP} using LDAPS...")

    ad_data = enumerate_ad_data(
        domain_dn=DOMAIN_DN,
        password=password
    )

    if ad_data is None:
        raise RuntimeError("Active Directory enumeration failed.")

    save_ad_data(ad_data)

    users = ad_data["users"]
    save_users(users)

    log("Saved AD domain information.")
    log(f"Saved {len(users)} AD users.")
    log(f"Saved {len(ad_data['groups'])} AD groups.")
    log(f"Saved {len(ad_data['memberships'])} AD memberships.")

    return ad_data


def run_ldap_enumeration(password: str, log=print):
    """
    Compatibility wrapper for callers that only need the user list.

    Full AD data is collected and persisted.
    """

    ad_data = run_ad_enumeration(password, log)
    return ad_data["users"]


def run_full_scan(password: str, log=print):
    """
    Run a complete scan.

    Collection and analysis happen in memory.
    All inventory and finding updates are committed in one transaction.
    """

    initialize()

    if not password:
        raise ValueError("LDAP password is required.")

    run_id = start_scan_run()

    log(f"Started scan run {run_id}.")

    try:
        # 1. Network discovery
        log(f"Discovering hosts on {TARGET_NETWORK}...")

        hosts = discover_hosts(TARGET_NETWORK)

        if not hosts:
            raise RuntimeError("Network discovery returned no hosts.")

        log(f"Discovered {len(hosts)} hosts.")

        for host in hosts:
            log(f"Host: {host['ip']} ({host['status']})")

        # 2. Service enumeration
        all_services = []
        checked_hosts = []

        for host in hosts:
            ip = host["ip"]

            if ip == KALI_IP:
                continue

            log(f"Enumerating services on {ip}...")

            services = scan_services(ip)

            # Only mark a host checked after enumeration succeeds.
            checked_hosts.append(ip)
            all_services.extend(services)

            log(f"Found {len(services)} services on {ip}.")

        log(
            f"Service enumeration complete: "
            f"{len(all_services)} services."
        )

        # 3. Domain controller identification
        dc_ports = {}

        for service in all_services:
            if service["protocol"] == "tcp":
                dc_ports.setdefault(
                    service["host_ip"], set()
                ).add(service["port"])

        domain_controllers = [
            ip for ip, ports in dc_ports.items()
            if 88 in ports and 389 in ports
        ]

        if DC_IP not in domain_controllers:
            raise RuntimeError(
                "Expected domain controller was not identified."
            )

        log(f"Domain controller identified: {DC_IP}")

        # 4. Active Directory collection (no persistence yet)
        log(f"Connecting to {DC_IP} using LDAPS...")

        ad_data = enumerate_ad_data(
            domain_dn=DOMAIN_DN,
            password=password
        )

        if ad_data is None:
            raise RuntimeError(
                "Active Directory enumeration failed."
            )

        users = ad_data["users"]

        log(f"Collected {len(users)} AD users.")
        log(f"Collected {len(ad_data['groups'])} AD groups.")
        log(
            f"Collected {len(ad_data['memberships'])} AD memberships."
        )

        # 5. Privilege analysis against in-memory AD data
        log("Analyzing AD privileged group memberships...")

        ad_analysis = analyze_ad_data(ad_data)

        sensitive_group_count = len(
            ad_analysis.get("sensitive_groups", [])
        )
        privilege_path_count = len(
            ad_analysis.get("paths", [])
        )

        log(f"Recognised sensitive groups: {sensitive_group_count}")
        log(f"User privilege paths found: {privilege_path_count}")

        # 6. Detection rules
        log("Running detection rules...")

        findings = run_all_rules(
            all_services,
            users,
            ad_analysis=ad_analysis
        )

        log(f"Generated {len(findings)} findings.")

        # 7. Atomic persistence
        #
        # Any exception inside this transaction rolls back every
        # inventory, AD, finding, and scan-completion update.
        with closing(sqlite3.connect(DB_PATH)) as conn:
            with conn:
                save_hosts(hosts, conn=conn)

                save_services(
                    all_services,
                    conn=conn,
                    checked_hosts=checked_hosts
                )

                save_ad_data(ad_data, conn=conn)
                save_users(users, conn=conn)
                save_findings(findings, run_id, conn=conn)

                complete_scan_run(
                    run_id,
                    checked_hosts,
                    ldap_checked=True,
                    conn=conn
                )

        log(f"Scan run {run_id} completed successfully.")

        return {
            "run_id": run_id,
            "hosts": hosts,
            "services": all_services,
            "users": users,
            "ad_data": ad_data,
            "ad_analysis": ad_analysis,
            "findings": findings
        }

    except Exception as error:
        # This uses a separate connection because the main transaction
        # has already rolled back or was never opened.
        try:
            abort_scan_run(run_id, str(error))
        except Exception as abort_error:
            log(
                f"Could not mark scan run {run_id} as failed: "
                f"{abort_error}"
            )

        log(f"Scan run {run_id} failed: {error}")
        raise
