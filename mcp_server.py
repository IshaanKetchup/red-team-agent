
import logging
import sys

from mcp.server.fastmcp import FastMCP

from engine.orchestrator import (
    initialize,
    run_discovery,
    run_service_enumeration,
    run_ad_enumeration,
    run_full_scan,
)

from database.storage import (
    get_findings_summary as storage_findings_summary,
    get_finding_details as storage_finding_details,
    compare_scan_runs as storage_compare_scan_runs,
    query_findings,
    query_host_inventory,
    query_service_inventory,
    query_scan_history,
)

from database.ad_queries import (
    query_ad_users,
    query_ad_groups,
    query_ad_group_members,
    query_ad_user_groups,
    query_ad_membership_paths,
)

from settings import LDAP_PASSWORD


logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("red-team-agent")

mcp = FastMCP("red-team-agent")


def log_message(message: str):
    logger.info(message)


def get_ldap_password() -> str:
    if not LDAP_PASSWORD:
        raise RuntimeError(
            "LDAP_PASSWORD is not configured in the server environment."
        )

    return LDAP_PASSWORD


@mcp.tool()
def discover_network() -> dict:
    """Actively discover live hosts on the configured target network.
    Performs network probing. Use only when fresh host discovery is requested."""
    logger.info("MCP tool invoked: discover_network")

    hosts = run_discovery(log=log_message)

    return {
        "host_count": len(hosts),
        "hosts": hosts,
    }


@mcp.tool()
def enumerate_services() -> dict:
    """Actively enumerate TCP services on hosts in the existing inventory.
    Performs network scanning. Use only when fresh service enumeration is requested."""
    logger.info("MCP tool invoked: enumerate_services")

    services = run_service_enumeration(log=log_message)

    return {
        "service_count": len(services),
        "services": services,
    }


@mcp.tool()
def enumerate_active_directory() -> dict:
    """Collect Active Directory data using the configured read-only LDAP account.
    Performs authenticated LDAP queries. Use only when fresh AD collection is requested."""
    logger.info("MCP tool invoked: enumerate_active_directory")

    password = get_ldap_password()

    ad_data = run_ad_enumeration(
        password=password,
        log=log_message,
    )

    return {
        "domain": ad_data.get("domain"),
        "user_count": len(ad_data.get("users", [])),
        "group_count": len(ad_data.get("groups", [])),
        "membership_count": len(ad_data.get("memberships", [])),
        "data": ad_data,
    }


@mcp.tool()
def run_complete_scan() -> dict:
    """Run a full assessment: network discovery, service enumeration,
    Active Directory collection, and analysis. This performs active
    network operations. Do not use for read-only analysis of existing data."""
    logger.info("MCP tool invoked: run_complete_scan")

    password = get_ldap_password()

    results = run_full_scan(
        password=password,
        log=log_message,
    )

    return {
        "run_id": results["run_id"],
        "host_count": len(results["hosts"]),
        "service_count": len(results["services"]),
        "user_count": len(results["users"]),
        "finding_count": len(results["findings"]),
        "findings": results["findings"],
    }


@mcp.tool()
def get_findings_summary(recent_limit: int = 10) -> dict:
    """Return finding analytics by severity, status, rule, host and lifecycle."""
    logger.info("MCP tool invoked: get_findings_summary")

    return storage_findings_summary(
        recent_limit=recent_limit,
    )


@mcp.tool()
def get_finding_details(finding_id: int) -> dict:
    """Retrieve a finding and its history across completed scan snapshots."""
    logger.info("MCP tool invoked: get_finding_details")

    return storage_finding_details(finding_id)


@mcp.tool()
def compare_scan_runs(
    older_run_id: int,
    newer_run_id: int,
    limit: int = 50,
) -> dict:
    """Compare findings between two completed scan runs."""
    logger.info("MCP tool invoked: compare_scan_runs")

    return storage_compare_scan_runs(
        older_run_id=older_run_id,
        newer_run_id=newer_run_id,
        limit=limit,
    )


@mcp.tool()
def get_findings(
    status: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    rule_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Query stored findings with optional filters and pagination."""
    logger.info("MCP tool invoked: get_findings")

    return query_findings(
        status=status,
        severity=severity,
        host=host,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )


@mcp.tool()
def get_scan_history(limit: int = 20) -> dict:
    """Retrieve recent scan run history."""
    logger.info("MCP tool invoked: get_scan_history")

    return query_scan_history(limit=limit)


@mcp.tool()
def get_host_inventory(limit: int = 200) -> dict:
    """Retrieve known hosts from the stored inventory."""
    logger.info("MCP tool invoked: get_host_inventory")

    return query_host_inventory(limit=limit)


@mcp.tool()
def get_service_inventory(
    host_ip: str | None = None,
    limit: int = 200,
) -> dict:
    """Retrieve stored services, optionally for one host."""
    logger.info("MCP tool invoked: get_service_inventory")

    return query_service_inventory(
        host_ip=host_ip,
        limit=limit,
    )


@mcp.tool()
def get_ad_users(
    search: str | None = None,
    enabled: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Read stored Active Directory users from SQLite.

    This is a read-only inventory query. It does not contact LDAP or
    initiate a fresh enumeration.

    Supports searching usernames, display names, UPNs, email addresses
    and descriptions. Supports enabled-state filtering and pagination.
    Use this tool when asked to list, find, search or inspect existing
    Active Directory users. Do not use enumerate_active_directory
    unless fresh AD collection is explicitly requested.
    """
    logger.info("MCP tool invoked: get_ad_users")

    return query_ad_users(
        search=search,
        enabled=enabled,
        limit=limit,
        offset=offset,
    )


@mcp.tool()
def get_ad_groups(
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Search stored Active Directory groups by name or description.

    Read-only SQLite query. Does not contact LDAP or start enumeration.
    """
    logger.info("MCP tool invoked: get_ad_groups")
    return query_ad_groups(
        search=search,
        limit=limit,
        offset=offset,
    )


@mcp.tool()
def get_ad_group_members(
    group: str,
    include_nested: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Retrieve members of an Active Directory group.

    Returns direct members and, by default, users with stored nested
    membership paths to the group. Results identify direct versus nested
    membership and include the available path evidence.
    Read-only query; does not contact LDAP.
    """
    logger.info("MCP tool invoked: get_ad_group_members")
    return query_ad_group_members(
        group=group,
        include_nested=include_nested,
        limit=limit,
        offset=offset,
    )


@mcp.tool()
def get_ad_user_groups(
    user: str,
    include_nested: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Retrieve the groups an Active Directory user belongs to.

    Returns direct groups and, by default, groups reached through stored
    nested membership paths. Each result identifies its membership type
    and includes path evidence where available.
    Read-only query; does not contact LDAP.
    """
    logger.info("MCP tool invoked: get_ad_user_groups")
    return query_ad_user_groups(
        user=user,
        include_nested=include_nested,
        limit=limit,
        offset=offset,
    )


@mcp.tool()
def get_ad_membership_paths(
    user: str | None = None,
    group: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Retrieve stored nested Active Directory membership paths.

    Filter by source username/DN, target group name/DN, or both.
    Returns the ordered distinguished-name path and its depth.
    Only paths with at least two membership edges are stored.
    Read-only query; does not contact LDAP.
    """
    logger.info("MCP tool invoked: get_ad_membership_paths")
    return query_ad_membership_paths(
        user=user,
        group=group,
        limit=limit,
        offset=offset,
    )


if __name__ == "__main__":
    logger.info("Starting Red Team Agent MCP server.")

    initialize()

    logger.info("Database initialization completed.")
    mcp.run(transport="stdio")
