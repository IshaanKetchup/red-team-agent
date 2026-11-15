import sqlite3
from contextlib import closing

from database.storage import DB_PATH


MAX_DEPTH = 32

DOMAIN_GROUPS = {
    512: ("Domain Admins", "DOMAIN_ADMIN"),
    516: ("Domain Controllers", "DOMAIN_CONTROLLER"),
    518: ("Schema Admins", "SCHEMA_ADMIN"),
    519: ("Enterprise Admins", "ENTERPRISE_ADMIN"),
    520: ("Group Policy Creator Owners", "GPO_CREATOR"),
    521: ("Read-only Domain Controllers", "RODC"),
    526: ("Key Admins", "KEY_ADMIN"),
    527: ("Enterprise Key Admins", "ENTERPRISE_KEY_ADMIN"),
}

BUILTIN_GROUPS = {
    "S-1-5-32-544": ("Administrators", "BUILTIN_ADMIN"),
    "S-1-5-32-548": ("Account Operators", "ACCOUNT_OPERATOR"),
    "S-1-5-32-549": ("Server Operators", "SERVER_OPERATOR"),
    "S-1-5-32-550": ("Print Operators", "PRINT_OPERATOR"),
    "S-1-5-32-551": ("Backup Operators", "BACKUP_OPERATOR"),
    "S-1-5-32-552": ("Replicators", "REPLICATOR"),
}


def is_security_enabled(group_type):
    """Check the AD SECURITY_ENABLED groupType bit."""

    if group_type is None:
        return False

    try:
        return bool(int(group_type) & 0x80000000)
    except (TypeError, ValueError):
        return False


def classify_sensitive_group(group, domain_sid):
    """Classify a security-enabled group using its SID."""

    object_sid = group.get("objectSid") or group.get("object_sid")

    if not object_sid or not is_security_enabled(
        group.get("groupType", group.get("group_type"))
    ):
        return None

    classification = None

    if object_sid in BUILTIN_GROUPS:
        display_name, category = BUILTIN_GROUPS[object_sid]
        classification = {
            "name": display_name,
            "category": category,
        }

    elif domain_sid and object_sid.startswith(domain_sid + "-"):
        try:
            rid = int(object_sid.rsplit("-", 1)[1])
        except (ValueError, IndexError):
            return None

        if rid in DOMAIN_GROUPS:
            display_name, category = DOMAIN_GROUPS[rid]
            classification = {
                "name": display_name,
                "category": category,
            }

    if not classification:
        return None

    return {
        "dn": group["dn"],
        "name": classification["name"],
        "category": classification["category"],
        "sid": object_sid,
    }


def build_sensitive_groups(groups, domain_sid):
    """Identify known sensitive groups from collected AD data."""

    sensitive_groups = {}

    for group in groups:
        if not group.get("dn"):
            continue

        classification = classify_sensitive_group(
            group,
            domain_sid,
        )

        if classification:
            sensitive_groups[group["dn"]] = classification

    return sensitive_groups


def build_membership_graph(memberships):
    """
    Build a graph with edges in this direction:

        member -> group

    Both DIRECT and PRIMARY relationships are included.
    """

    graph = {}

    for membership in memberships:
        member_dn = membership.get("member_dn")
        group_dn = membership.get("group_dn")

        if not member_dn or not group_dn:
            continue

        membership_type = membership.get(
            "membership_type",
            "DIRECT",
        )

        graph.setdefault(member_dn, []).append(
            (group_dn, membership_type)
        )

    return graph


def find_user_privilege_paths(users, graph, sensitive_groups):
    """Find direct and nested paths from users to sensitive groups."""

    results = []

    for user in users:
        source_dn = user.get("dn")

        if not source_dn:
            continue

        def walk(current_dn, path, relationship_types):
            if len(path) - 1 >= MAX_DEPTH:
                return

            for parent_dn, membership_type in graph.get(
                current_dn, []
            ):
                if parent_dn in path:
                    continue

                next_path = path + [parent_dn]
                next_relationships = (
                    relationship_types + [membership_type]
                )

                if parent_dn in sensitive_groups:
                    target = sensitive_groups[parent_dn]

                    results.append({
                        "source_dn": source_dn,
                        "source_sid": (
                            user.get("objectSid")
                            or user.get("object_sid")
                        ),
                        "sam_account_name": user.get(
                            "sAMAccountName",
                            user.get("sam_account_name"),
                        ),
                        "target_group_dn": parent_dn,
                        "target_group": target["name"],
                        "target_group_sid": target.get("sid"),
                        "category": target["category"],
                        "depth": len(next_path) - 1,
                        "relationship": (
                            "DIRECT"
                            if len(next_path) == 2
                            else "NESTED"
                        ),
                        "path": next_path,
                        "membership_types": next_relationships,
                    })

                walk(
                    parent_dn,
                    next_path,
                    next_relationships,
                )

        walk(source_dn, [source_dn], [])

    return results


def analyze_ad_data(data):
    """Analyse freshly collected AD data without accessing SQLite."""

    if not isinstance(data, dict):
        raise ValueError("AD data must be a dictionary.")

    domain = data.get("domain")
    users = data.get("users")
    groups = data.get("groups")
    memberships = data.get("memberships")

    if not isinstance(domain, dict):
        raise ValueError("AD domain data is missing.")

    if not all(
        isinstance(value, list)
        for value in (users, groups, memberships)
    ):
        raise ValueError(
            "AD users, groups and memberships must be lists."
        )

    domain_dn = domain.get("dn")
    domain_sid = domain.get("objectSid") or domain.get("object_sid")

    if not domain_dn:
        raise ValueError("Domain distinguished name is missing.")

    if not domain_sid:
        raise ValueError("Domain SID is missing.")

    sensitive_groups = build_sensitive_groups(
        groups,
        domain_sid,
    )

    graph = build_membership_graph(memberships)

    paths = find_user_privilege_paths(
        users,
        graph,
        sensitive_groups,
    )

    return {
        "domain_dn": domain_dn,
        "sensitive_groups": list(sensitive_groups.values()),
        "paths": paths,
    }


def get_sensitive_groups(conn, domain_sid):
    """Identify sensitive groups from stored AD data."""

    rows = conn.execute("""
        SELECT dn, name, object_sid, group_type
        FROM ad_groups
    """).fetchall()

    groups = [
        {
            "dn": row[0],
            "name": row[1],
            "objectSid": row[2],
            "groupType": row[3],
        }
        for row in rows
    ]

    return build_sensitive_groups(groups, domain_sid)


def load_membership_graph(conn):
    """Build a membership graph from stored AD relationships."""

    rows = conn.execute("""
        SELECT member_dn, group_dn, membership_type
        FROM ad_memberships
    """).fetchall()

    graph = {}

    for member_dn, group_dn, membership_type in rows:
        graph.setdefault(member_dn, []).append(
            (group_dn, membership_type)
        )

    return graph



def analyze_privileged_memberships(conn=None, domain_sid=None):
    """Analyse privileged memberships from the stored AD inventory."""

    owns_connection = conn is None

    if owns_connection:
        conn = sqlite3.connect(DB_PATH)

    try:
        if domain_sid is None:
            domain_row = conn.execute("""
                SELECT object_sid
                FROM ad_domains
                LIMIT 1
            """).fetchone()

            if not domain_row:
                raise RuntimeError("No stored AD domain SID was found.")

            domain_sid = domain_row[0]

        user_rows = conn.execute("""
            SELECT dn, sam_account_name, object_sid
            FROM ad_users
        """).fetchall()

        users = [
            {
                "dn": row[0],
                "sam_account_name": row[1],
                "objectSid": row[2],
            }
            for row in user_rows
        ]

        sensitive_groups = get_sensitive_groups(conn, domain_sid)
        graph = load_membership_graph(conn)

        return find_user_privilege_paths(
            users,
            graph,
            sensitive_groups,
        )

    finally:
        if owns_connection:
            conn.close()


def print_privilege_analysis(paths):
    """Print a readable summary of privileged membership paths."""

    print("\n[+] Privileged membership analysis")

    if not paths:
        print("No paths to recognised sensitive groups were found.")
        return

    for item in paths:
        sam = item.get("sam_account_name") or "UNKNOWN"
        group = item.get("target_group") or "Unknown group"
        category = item.get("category") or "UNKNOWN"
        relationship = item.get("relationship") or "UNKNOWN"
        path = " -> ".join(item.get("path") or [])

        print(
            f"  {sam}: {relationship} membership to "
            f"{group} ({category})"
        )
        print(f"    Path: {path}")


if __name__ == "__main__":
    with closing(sqlite3.connect(DB_PATH)) as connection:
        domain_row = connection.execute("""
            SELECT object_sid
            FROM ad_domains
            LIMIT 1
        """).fetchone()

        if not domain_row:
            raise SystemExit(
                "No stored AD domain exists. Run an AD collection first."
            )

        privilege_paths = analyze_privileged_memberships(
            connection,
            domain_row[0],
        )

        print_privilege_analysis(privilege_paths)
