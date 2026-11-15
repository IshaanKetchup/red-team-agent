import json
import sqlite3

from contextlib import closing, contextmanager
from datetime import datetime, timedelta

from database.storage import DB_PATH


MAX_NESTING_DEPTH = 32
MAX_PATHS_PER_SOURCE = 10000


@contextmanager
def _connection(conn=None):
    """Use a supplied connection without committing or closing it."""

    if conn is not None:
        yield conn
        return

    connection = sqlite3.connect(DB_PATH)

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_ad_tables():
    """Create tables for structured Active Directory data."""

    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ad_domains (
                domain_dn TEXT PRIMARY KEY,
                domain_name TEXT,
                dns_root TEXT,
                object_sid TEXT,
                functional_level INTEGER,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ad_users (
                dn TEXT PRIMARY KEY,
                domain_dn TEXT NOT NULL,
                sam_account_name TEXT,
                display_name TEXT,
                user_principal_name TEXT,
                mail TEXT,
                description TEXT,
                user_account_control INTEGER,
                enabled INTEGER,
                object_sid TEXT,
                primary_group_id INTEGER,
                pwd_last_set TEXT,
                last_logon_timestamp TEXT,
                when_created TEXT,
                admin_count INTEGER,
                service_principal_names TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ad_groups (
                dn TEXT PRIMARY KEY,
                domain_dn TEXT NOT NULL,
                name TEXT,
                cn TEXT,
                sam_account_name TEXT,
                description TEXT,
                group_type INTEGER,
                object_sid TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ad_memberships (
                group_dn TEXT NOT NULL,
                member_dn TEXT NOT NULL,
                membership_type TEXT NOT NULL DEFAULT 'DIRECT',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (
                    group_dn,
                    member_dn,
                    membership_type
                )
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ad_membership_paths (
                domain_dn TEXT NOT NULL,
                source_dn TEXT NOT NULL,
                target_group_dn TEXT NOT NULL,
                depth INTEGER NOT NULL,
                path_json TEXT NOT NULL,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (
                    domain_dn,
                    source_dn,
                    target_group_dn,
                    path_json
                )
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ad_password_policies (
                domain_dn TEXT PRIMARY KEY,
                min_password_length INTEGER,
                password_history_length INTEGER,
                max_password_age_seconds REAL,
                min_password_age_seconds REAL,
                password_properties INTEGER,
                lockout_threshold INTEGER,
                lockout_duration_seconds REAL,
                lockout_observation_window_seconds REAL,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def _to_seconds(value):
    if isinstance(value, timedelta):
        return value.total_seconds()

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_text(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    return str(value)


def _to_int(value):
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _derive_dns_root(domain_dn):
    """Convert DC=lab,DC=local into example.local."""

    labels = []

    for component in domain_dn.split(","):
        component = component.strip()

        if component.upper().startswith("DC="):
            labels.append(component[3:])

    return ".".join(labels) if labels else None


def _build_membership_paths(users, groups, memberships):
    """
    Calculate transitive membership paths.

    Relationship direction:
        member_dn -> group_dn

    Only paths with at least two edges are stored.
    """

    graph = {}

    for membership in memberships:
        member_dn = membership.get("member_dn")
        group_dn = membership.get("group_dn")

        if not member_dn or not group_dn:
            continue

        graph.setdefault(member_dn, set()).add(group_dn)

    sources = {
        item["dn"]
        for item in users + groups
        if item.get("dn")
    }

    paths = []

    for source_dn in sorted(sources):
        source_path_count = 0

        def walk(current_dn, path):
            nonlocal source_path_count

            if len(path) - 1 >= MAX_NESTING_DEPTH:
                return

            parents = sorted(graph.get(current_dn, set()))

            for parent_dn in parents:
                if parent_dn in path:
                    continue

                next_path = path + [parent_dn]
                depth = len(next_path) - 1

                if depth >= 2:
                    paths.append({
                        "source_dn": source_dn,
                        "target_group_dn": parent_dn,
                        "depth": depth,
                        "path": next_path
                    })

                    source_path_count += 1

                    if source_path_count >= MAX_PATHS_PER_SOURCE:
                        return

                walk(parent_dn, next_path)

                if source_path_count >= MAX_PATHS_PER_SOURCE:
                    return

        walk(source_dn, [source_dn])

    return paths


def _validate_ad_data(data):
    """Validate the complete AD snapshot before touching the database."""

    if not isinstance(data, dict):
        raise ValueError("AD data must be a dictionary.")

    domain = data.get("domain")
    users = data.get("users")
    groups = data.get("groups")
    memberships = data.get("memberships")
    policy = data.get("password_policy")

    if not isinstance(domain, dict) or not isinstance(policy, dict):
        raise ValueError("Domain and password policy data are required.")

    if not all(
        isinstance(value, list)
        for value in (users, groups, memberships)
    ):
        raise ValueError("Users, groups and memberships must be lists.")

    domain_dn = domain.get("dn")

    if not domain_dn:
        raise ValueError("Domain distinguished name is missing.")

    if not all(isinstance(item, dict) for item in users + groups):
        raise ValueError("Every user and group must be a dictionary.")

    if not all(isinstance(item, dict) for item in memberships):
        raise ValueError("Every membership must be a dictionary.")

    if any(not item.get("dn") for item in users + groups):
        raise ValueError(
            "Every user and group must have a distinguished name."
        )

    for membership in memberships:
        if not membership.get("group_dn") or not membership.get("member_dn"):
            raise ValueError(
                "Membership is missing a group or member DN."
            )

    return domain, users, groups, memberships, policy, domain_dn


def _delete_stale_objects(conn, table, domain_dn, current_dns):
    """
    Delete objects belonging to this domain that are absent
    from the latest successful snapshot.
    """

    existing = conn.execute(
        f"SELECT dn FROM {table} WHERE domain_dn = ?",
        (domain_dn,)
    ).fetchall()

    existing_dns = {row[0] for row in existing}
    stale_dns = existing_dns - set(current_dns)

    for dn in stale_dns:
        conn.execute(
            f"DELETE FROM {table} WHERE dn = ? AND domain_dn = ?",
            (dn, domain_dn)
        )

    return stale_dns


def save_ad_data(data, conn=None):
    """
    Persist a complete AD enumeration result.

    If conn is supplied, all changes remain part of the caller's
    transaction. Otherwise, this function manages its own transaction.
    """

    (
        domain,
        users,
        groups,
        memberships,
        policy,
        domain_dn
    ) = _validate_ad_data(data)

    dns_root = (
        domain.get("dnsRoot")
        or _derive_dns_root(domain_dn)
    )

    membership_paths = _build_membership_paths(
        users,
        groups,
        memberships
    )

    current_user_dns = {user["dn"] for user in users}
    current_group_dns = {group["dn"] for group in groups}

    with _connection(conn) as connection:

        previous_users = connection.execute(
            "SELECT dn FROM ad_users WHERE domain_dn = ?",
            (domain_dn,)
        ).fetchall()

        previous_groups = connection.execute(
            "SELECT dn FROM ad_groups WHERE domain_dn = ?",
            (domain_dn,)
        ).fetchall()

        previous_user_dns = {row[0] for row in previous_users}
        previous_group_dns = {row[0] for row in previous_groups}

        connection.execute("""
            INSERT INTO ad_domains (
                domain_dn, domain_name, dns_root,
                object_sid, functional_level, last_seen
            )
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(domain_dn) DO UPDATE SET
                domain_name = excluded.domain_name,
                dns_root = excluded.dns_root,
                object_sid = excluded.object_sid,
                functional_level = excluded.functional_level,
                last_seen = CURRENT_TIMESTAMP
        """, (
            domain_dn,
            domain.get("name"),
            dns_root,
            domain.get("objectSid"),
            _to_int(domain.get("functionalLevel"))
        ))

        # Upsert users.
        for user in users:
            connection.execute("""
                INSERT INTO ad_users (
                    dn, domain_dn, sam_account_name,
                    display_name, user_principal_name,
                    mail, description, user_account_control,
                    enabled, object_sid, primary_group_id,
                    pwd_last_set, last_logon_timestamp,
                    when_created, admin_count,
                    service_principal_names, last_seen
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
                )
                ON CONFLICT(dn) DO UPDATE SET
                    domain_dn = excluded.domain_dn,
                    sam_account_name = excluded.sam_account_name,
                    display_name = excluded.display_name,
                    user_principal_name = excluded.user_principal_name,
                    mail = excluded.mail,
                    description = excluded.description,
                    user_account_control = excluded.user_account_control,
                    enabled = excluded.enabled,
                    object_sid = excluded.object_sid,
                    primary_group_id = excluded.primary_group_id,
                    pwd_last_set = excluded.pwd_last_set,
                    last_logon_timestamp = excluded.last_logon_timestamp,
                    when_created = excluded.when_created,
                    admin_count = excluded.admin_count,
                    service_principal_names = excluded.service_principal_names,
                    last_seen = CURRENT_TIMESTAMP
            """, (
                user["dn"],
                domain_dn,
                user.get("sAMAccountName"),
                user.get("displayName"),
                user.get("userPrincipalName"),
                user.get("mail"),
                user.get("description"),
                _to_int(user.get("userAccountControl")),
                (
                    int(user["enabled"])
                    if user.get("enabled") is not None
                    else None
                ),
                user.get("objectSid"),
                _to_int(user.get("primaryGroupID")),
                _to_text(user.get("pwdLastSet")),
                _to_text(user.get("lastLogonTimestamp")),
                _to_text(user.get("whenCreated")),
                _to_int(user.get("adminCount")),
                json.dumps(user.get("servicePrincipalName", []))
            ))

        # Upsert groups.
        for group in groups:
            connection.execute("""
                INSERT INTO ad_groups (
                    dn, domain_dn, name, cn,
                    sam_account_name, description,
                    group_type, object_sid, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(dn) DO UPDATE SET
                    domain_dn = excluded.domain_dn,
                    name = excluded.name,
                    cn = excluded.cn,
                    sam_account_name = excluded.sam_account_name,
                    description = excluded.description,
                    group_type = excluded.group_type,
                    object_sid = excluded.object_sid,
                    last_seen = CURRENT_TIMESTAMP
            """, (
                group["dn"],
                domain_dn,
                group.get("name"),
                group.get("cn"),
                group.get("sAMAccountName"),
                group.get("description"),
                _to_int(group.get("groupType")),
                group.get("objectSid")
            ))

        # Identify stale objects.
        stale_users = previous_user_dns - current_user_dns
        stale_groups = previous_group_dns - current_group_dns

        # Remove old membership relationships for this domain's groups.
        # Also remove references to users/groups that disappeared.
        group_dns_to_clear = previous_group_dns | current_group_dns
        stale_member_dns = stale_users | stale_groups

        conditions = []
        parameters = []

        if group_dns_to_clear:
            placeholders = ",".join("?" for _ in group_dns_to_clear)
            conditions.append(f"group_dn IN ({placeholders})")
            parameters.extend(sorted(group_dns_to_clear))

        if stale_member_dns:
            placeholders = ",".join("?" for _ in stale_member_dns)
            conditions.append(f"member_dn IN ({placeholders})")
            parameters.extend(sorted(stale_member_dns))

        if conditions:
            connection.execute(
                "DELETE FROM ad_memberships WHERE "
                + " OR ".join(conditions),
                parameters
            )

        # Insert the newly collected membership snapshot.
        for membership in memberships:
            connection.execute("""
                INSERT INTO ad_memberships (
                    group_dn, member_dn, membership_type, last_seen
                )
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(
                    group_dn, member_dn, membership_type
                ) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP
            """, (
                membership["group_dn"],
                membership["member_dn"],
                membership.get("membership_type", "DIRECT")
            ))

        # Remove stale AD users and groups.
        _delete_stale_objects(
            connection,
            "ad_users",
            domain_dn,
            current_user_dns
        )

        _delete_stale_objects(
            connection,
            "ad_groups",
            domain_dn,
            current_group_dns
        )

        # Replace derived membership paths for this domain.
        connection.execute("""
            DELETE FROM ad_membership_paths
            WHERE domain_dn = ?
        """, (domain_dn,))

        for path in membership_paths:
            connection.execute("""
                INSERT INTO ad_membership_paths (
                    domain_dn,
                    source_dn,
                    target_group_dn,
                    depth,
                    path_json,
                    last_seen
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                domain_dn,
                path["source_dn"],
                path["target_group_dn"],
                path["depth"],
                json.dumps(path["path"])
            ))

        # Upsert password policy.
        connection.execute("""
            INSERT INTO ad_password_policies (
                domain_dn, min_password_length,
                password_history_length,
                max_password_age_seconds,
                min_password_age_seconds,
                password_properties,
                lockout_threshold,
                lockout_duration_seconds,
                lockout_observation_window_seconds,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(domain_dn) DO UPDATE SET
                min_password_length = excluded.min_password_length,
                password_history_length = excluded.password_history_length,
                max_password_age_seconds = excluded.max_password_age_seconds,
                min_password_age_seconds = excluded.min_password_age_seconds,
                password_properties = excluded.password_properties,
                lockout_threshold = excluded.lockout_threshold,
                lockout_duration_seconds = excluded.lockout_duration_seconds,
                lockout_observation_window_seconds =
                    excluded.lockout_observation_window_seconds,
                last_seen = CURRENT_TIMESTAMP
        """, (
            domain_dn,
            _to_int(policy.get("minPasswordLength")),
            _to_int(policy.get("passwordHistoryLength")),
            _to_seconds(policy.get("maxPasswordAge")),
            _to_seconds(policy.get("minPasswordAge")),
            _to_int(policy.get("passwordProperties")),
            _to_int(policy.get("lockoutThreshold")),
            _to_seconds(policy.get("lockoutDuration")),
            _to_seconds(policy.get("lockoutObservationWindow"))
        ))

    print(f"[+] Stored {len(memberships)} membership relationships.")
    print(f"[+] Derived {len(membership_paths)} nested membership paths.")


def _fetch_all(query, parameters=()):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]


def get_ad_domains():
    return _fetch_all("""
        SELECT * FROM ad_domains ORDER BY domain_name
    """)


def get_ad_users():
    return _fetch_all("""
        SELECT * FROM ad_users ORDER BY sam_account_name
    """)


def get_ad_groups():
    return _fetch_all("""
        SELECT * FROM ad_groups ORDER BY name
    """)


def get_ad_memberships():
    return _fetch_all("""
        SELECT * FROM ad_memberships
        ORDER BY membership_type, group_dn, member_dn
    """)


def get_ad_membership_paths(domain_dn=None):
    if domain_dn:
        return _fetch_all("""
            SELECT * FROM ad_membership_paths
            WHERE domain_dn = ?
            ORDER BY source_dn, depth, target_group_dn
        """, (domain_dn,))

    return _fetch_all("""
        SELECT * FROM ad_membership_paths
        ORDER BY domain_dn, source_dn, depth, target_group_dn
    """)


def get_ad_password_policies():
    return _fetch_all("""
        SELECT * FROM ad_password_policies
        ORDER BY domain_dn
    """)
