from settings import DOMAIN_LABEL

import re
import sqlite3
from contextlib import contextmanager

DB_PATH = "redteam.db"


@contextmanager
def _connection(conn=None):
    """Use a caller-provided connection or create an independent one."""

    if conn is not None:
        yield conn
        return

    connection = sqlite3.connect(DB_PATH)

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _normalise_identity(value):
    return " ".join(str(value or "").strip().casefold().split())


def _legacy_key_for_row(row):
    """Build a deterministic legacy identity from an old finding row."""

    rule_id = row[1]
    evidence = row[4] or ""

    if rule_id == "AD_USER_DISCOVERED":
        match = re.search(r"Account discovered:\s*(.+)$", evidence)
        if match:
            return (
                "legacy:user:"
                + _normalise_identity(match.group(1))
            )

    if rule_id == "AD_PRIVILEGED_MEMBERSHIP":
        match = re.search(
            r"Account\s+(.+?)\s+has\s+(direct|nested)\s+"
            r"membership path to\s+(.+?)\s+\([^)]*\)\.",
            evidence,
            re.IGNORECASE,
        )

        if match:
            sam, relationship, group_name = match.groups()
            return (
                f"legacy:priv:{_normalise_identity(sam)}"
                f":{_normalise_identity(group_name)}"
                f":{relationship.casefold()}"
            )

    return f"legacy:row:{row[0]}"


def _finding_key_for_input(finding):
    """Get the stable identity for a new or updated finding."""

    finding_key = finding.get("finding_key")

    if finding_key:
        return str(finding_key)

    rule_id = finding["rule"]

    if rule_id not in {
        "AD_USER_DISCOVERED",
        "AD_PRIVILEGED_MEMBERSHIP",
    }:
        return "host"

    legacy_key = finding.get("legacy_key")

    if legacy_key:
        return str(legacy_key)

    evidence = finding.get("evidence", "")

    if rule_id == "AD_USER_DISCOVERED":
        match = re.search(r"Account discovered:\s*(.+)$", evidence)
        if match:
            return (
                "legacy:user:"
                + _normalise_identity(match.group(1))
            )

    if rule_id == "AD_PRIVILEGED_MEMBERSHIP":
        match = re.search(
            r"Account\s+(.+?)\s+has\s+(direct|nested)\s+"
            r"membership path to\s+(.+?)\s+\([^)]*\)\.",
            evidence,
            re.IGNORECASE,
        )

        if match:
            sam, relationship, group_name = match.groups()
            return (
                f"legacy:priv:{_normalise_identity(sam)}"
                f":{_normalise_identity(group_name)}"
                f":{relationship.casefold()}"
            )

    raise ValueError(
        f"Finding {rule_id} is missing a stable identity."
    )


def _create_findings_table(conn, table_name="findings"):
    """Create the current findings schema."""

    if table_name not in {"findings", "findings_new"}:
        raise ValueError("Invalid findings table name.")

    conn.execute(f"""
        CREATE TABLE {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            host TEXT NOT NULL,
            evidence TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            last_seen_run_id INTEGER,
            resolved_at TIMESTAMP,
            finding_key TEXT NOT NULL,
            UNIQUE(rule_id, host, finding_key)
        )
    """)


def _migrate_findings_table(conn):
    """Migrate findings to stable identity while preserving all rows."""

    table = conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = 'findings'
    """).fetchone()

    if table is None:
        _create_findings_table(conn)
        return

    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(findings)")
    }

    lifecycle_migrations = {
        "status": (
            "ALTER TABLE findings "
            "ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'"
        ),
        "last_seen_run_id": (
            "ALTER TABLE findings ADD COLUMN last_seen_run_id INTEGER"
        ),
        "resolved_at": (
            "ALTER TABLE findings ADD COLUMN resolved_at TIMESTAMP"
        ),
    }

    for column, statement in lifecycle_migrations.items():
        if column not in columns:
            conn.execute(statement)

    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(findings)")
    }

    indexes = conn.execute("PRAGMA index_list(findings)").fetchall()
    unique_column_sets = []

    for index in indexes:
        if not index[2]:
            continue

        index_name = index[1].replace('"', '""')
        index_columns = tuple(
            row[2]
            for row in conn.execute(
                f'PRAGMA index_info("{index_name}")'
            )
        )
        unique_column_sets.append(index_columns)

    desired_unique = ("rule_id", "host", "finding_key")

    if (
        "finding_key" in columns
        and desired_unique in unique_column_sets
    ):
        return

    old_rows = conn.execute("""
        SELECT id, rule_id, severity, host, evidence,
               first_seen, last_seen, status,
               last_seen_run_id, resolved_at
        FROM findings
        ORDER BY id
    """).fetchall()

    conn.execute("DROP TABLE IF EXISTS findings_new")
    _create_findings_table(conn, "findings_new")

    # Host-level findings should have one canonical host identity.
    # Preserve any historical duplicates under row-specific legacy keys.
    host_groups = {}

    for row in old_rows:
        if row[1] not in {
            "AD_USER_DISCOVERED",
            "AD_PRIVILEGED_MEMBERSHIP",
        }:
            host_groups.setdefault((row[1], row[3]), []).append(row)

    canonical_host_ids = set()

    for rows in host_groups.values():
        rows.sort(
            key=lambda row: (
                row[7] == "ACTIVE",
                row[6] or "",
                row[0],
            ),
            reverse=True,
        )
        canonical_host_ids.add(rows[0][0])

    used_keys = set()

    for row in old_rows:
        if row[1] not in {
            "AD_USER_DISCOVERED",
            "AD_PRIVILEGED_MEMBERSHIP",
        }:
            if row[0] in canonical_host_ids:
                key = "host"
            else:
                key = f"legacy:row:{row[0]}"
        else:
            key = _legacy_key_for_row(row)

        unique_key = (row[1], row[3], key)

        if unique_key in used_keys:
            key = f"{key}:legacy-row:{row[0]}"
            unique_key = (row[1], row[3], key)

        used_keys.add(unique_key)

        conn.execute("""
            INSERT INTO findings_new (
                id, rule_id, severity, host, evidence,
                first_seen, last_seen, status,
                last_seen_run_id, resolved_at, finding_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
            row[8],
            row[9],
            key,
        ))

    conn.execute("DROP TABLE findings")
    conn.execute("ALTER TABLE findings_new RENAME TO findings")


def initialize_database():
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                status TEXT,
                hostname TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def initialize_users_table():
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                dn TEXT PRIMARY KEY,
                sam_account_name TEXT,
                display_name TEXT,
                user_principal_name TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def initialize_services_table():
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host_ip, port, protocol)
            )
        """)



def initialize_findings_table():
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'RUNNING',
                error TEXT
            )
        """)

        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(scan_runs)")
        }

        if "snapshot_recorded" not in columns:
            conn.execute("""
                ALTER TABLE scan_runs
                ADD COLUMN snapshot_recorded INTEGER NOT NULL DEFAULT 0
            """)

        _migrate_findings_table(conn)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_run_findings (
                run_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT NOT NULL,
                evidence TEXT NOT NULL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT NOT NULL,
                resolved_at TIMESTAMP,
                finding_key TEXT NOT NULL,
                PRIMARY KEY (run_id, finding_id)
            )
        """)



def start_scan_run():
    with _connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scan_runs DEFAULT VALUES
        """)
        return cursor.lastrowid


def save_hosts(hosts: list[dict], conn=None):
    with _connection(conn) as connection:
        for host in hosts:
            connection.execute("""
                INSERT INTO hosts (ip, status, hostname, last_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    status = excluded.status,
                    hostname = excluded.hostname,
                    last_seen = CURRENT_TIMESTAMP
            """, (
                host["ip"],
                host["status"],
                host["hostname"],
            ))


def get_hosts():
    with _connection() as conn:
        return conn.execute("""
            SELECT ip, status, hostname, last_seen
            FROM hosts
            ORDER BY ip
        """).fetchall()


def save_services(
    services: list[dict],
    checked_hosts: list[str] | None = None,
    conn=None,
):
    """
    Save discovered services.

    When checked_hosts is supplied, replace service inventory only for
    those hosts. Hosts not included remain untouched.
    """

    with _connection(conn) as connection:
        if checked_hosts is not None:
            for host_ip in set(checked_hosts):
                connection.execute("""
                    DELETE FROM services
                    WHERE host_ip = ?
                """, (host_ip,))

        for service in services:
            connection.execute("""
                INSERT INTO services (
                    host_ip, port, protocol, service,
                    product, version, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(host_ip, port, protocol) DO UPDATE SET
                    service = excluded.service,
                    product = excluded.product,
                    version = excluded.version,
                    last_seen = CURRENT_TIMESTAMP
            """, (
                service["host_ip"],
                service["port"],
                service["protocol"],
                service["service"],
                service["product"],
                service["version"],
            ))


def get_services():
    with _connection() as conn:
        return conn.execute("""
            SELECT host_ip, port, protocol, service, product, version
            FROM services
            ORDER BY host_ip, port
        """).fetchall()


def save_users(users: list[dict], conn=None):
    with _connection(conn) as connection:
        for user in users:
            connection.execute("""
                INSERT INTO users (
                    dn, sam_account_name, display_name,
                    user_principal_name, last_seen
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(dn) DO UPDATE SET
                    sam_account_name = excluded.sam_account_name,
                    display_name = excluded.display_name,
                    user_principal_name = excluded.user_principal_name,
                    last_seen = CURRENT_TIMESTAMP
            """, (
                user["dn"],
                user["sAMAccountName"],
                user["displayName"],
                user["userPrincipalName"],
            ))


def get_users():
    with _connection() as conn:
        return conn.execute("""
            SELECT dn, sam_account_name, display_name,
                   user_principal_name, last_seen
            FROM users
            ORDER BY sam_account_name
        """).fetchall()


def save_findings(findings: list[dict], run_id: int, conn=None):
    """Upsert findings using stable identity rather than evidence text."""

    with _connection(conn) as connection:
        for finding in findings:
            rule_id = finding["rule"]
            host = finding["host"]
            finding_key = _finding_key_for_input(finding)
            legacy_key = finding.get("legacy_key")

            # Upgrade the matching legacy AD finding in place.
            # This preserves its ID and first_seen timestamp.
            if legacy_key and legacy_key != finding_key:
                target_exists = connection.execute("""
                    SELECT 1
                    FROM findings
                    WHERE rule_id = ?
                      AND host = ?
                      AND finding_key = ?
                """, (
                    rule_id,
                    host,
                    finding_key,
                )).fetchone()

                if not target_exists:
                    legacy_row = connection.execute("""
                        SELECT id
                        FROM findings
                        WHERE rule_id = ?
                          AND host = ?
                          AND finding_key = ?
                        ORDER BY
                            CASE status WHEN 'ACTIVE' THEN 0 ELSE 1 END,
                            last_seen DESC,
                            id
                        LIMIT 1
                    """, (
                        rule_id,
                        host,
                        legacy_key,
                    )).fetchone()

                    if legacy_row:
                        connection.execute("""
                            UPDATE findings
                            SET finding_key = ?,
                                severity = ?,
                                evidence = ?,
                                last_seen = CURRENT_TIMESTAMP,
                                status = 'ACTIVE',
                                last_seen_run_id = ?,
                                resolved_at = NULL
                            WHERE id = ?
                        """, (
                            finding_key,
                            finding["severity"],
                            finding["evidence"],
                            run_id,
                            legacy_row[0],
                        ))
                        continue

            connection.execute("""
                INSERT INTO findings (
                    rule_id, severity, host, evidence,
                    first_seen, last_seen, status,
                    last_seen_run_id, resolved_at, finding_key
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP, 'ACTIVE', ?, NULL, ?)

                ON CONFLICT(rule_id, host, finding_key) DO UPDATE SET
                    severity = excluded.severity,
                    evidence = excluded.evidence,
                    last_seen = CURRENT_TIMESTAMP,
                    status = 'ACTIVE',
                    last_seen_run_id = excluded.last_seen_run_id,
                    resolved_at = NULL
            """, (
                rule_id,
                finding["severity"],
                host,
                finding["evidence"],
                run_id,
                finding_key,
            ))



def complete_scan_run(
    run_id: int,
    checked_hosts: list[str],
    ldap_checked: bool,
    conn=None,
):
    """Resolve findings, snapshot the final state, and complete the scan."""

    with _connection(conn) as connection:
        run = connection.execute("""
            SELECT status
            FROM scan_runs
            WHERE id = ?
        """, (run_id,)).fetchone()

        if run is None or run[0] != "RUNNING":
            raise RuntimeError(
                f"Scan run {run_id} does not exist or is not RUNNING."
            )

        if checked_hosts:
            placeholders = ",".join("?" for _ in checked_hosts)

            connection.execute(f"""
                UPDATE findings
                SET status = 'RESOLVED',
                    resolved_at = CURRENT_TIMESTAMP
                WHERE status = 'ACTIVE'
                  AND (
                      last_seen_run_id IS NULL
                      OR last_seen_run_id != ?
                  )
                  AND host IN ({placeholders})
            """, (run_id, *checked_hosts))

        if ldap_checked:
            connection.execute("""
                UPDATE findings
                SET status = 'RESOLVED',
                    resolved_at = CURRENT_TIMESTAMP
                WHERE status = 'ACTIVE'
                  AND (
                      last_seen_run_id IS NULL
                      OR last_seen_run_id != ?
                  )
                  AND host = ?
            """, (run_id, DOMAIN_LABEL))

        connection.execute("""
            INSERT INTO scan_run_findings (
                run_id, finding_id, rule_id, severity,
                host, evidence, first_seen, last_seen,
                status, resolved_at, finding_key
            )
            SELECT
                ?, id, rule_id, severity,
                host, evidence, first_seen, last_seen,
                status, resolved_at, finding_key
            FROM findings
        """, (run_id,))

        cursor = connection.execute("""
            UPDATE scan_runs
            SET status = 'COMPLETED',
                completed_at = CURRENT_TIMESTAMP,
                snapshot_recorded = 1,
                error = NULL
            WHERE id = ?
              AND status = 'RUNNING'
        """, (run_id,))

        if cursor.rowcount != 1:
            raise RuntimeError(
                f"Scan run {run_id} could not be completed."
            )



def abort_scan_run(run_id: int, reason: str = "Scan incomplete"):
    """Mark a scan failed using a separate connection."""

    with _connection() as conn:
        conn.execute("""
            UPDATE scan_runs
            SET status = 'FAILED',
                completed_at = CURRENT_TIMESTAMP,
                error = ?
            WHERE id = ?
              AND status = 'RUNNING'
        """, (reason, run_id))


def get_findings(active_only: bool = False):
    with _connection() as conn:
        query = """
            SELECT rule_id, severity, host, evidence,
                   first_seen, last_seen, status, resolved_at
            FROM findings
        """

        if active_only:
            query += " WHERE status = 'ACTIVE'"

        query += " ORDER BY severity, host, rule_id"

        return conn.execute(query).fetchall()


def get_scan_runs(limit: int = 20):
    with _connection() as conn:
        return conn.execute("""
            SELECT id, started_at, completed_at, status, error
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()


def _bounded_read_limit(limit, default=50, maximum=200):
    """Validate and cap limits for read-only inventory queries."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = default

    return max(1, min(limit, maximum))


def _rows_as_dicts(cursor):
    columns = [column[0] for column in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]



def get_findings_summary(recent_limit=10):
    """Return deterministic finding analytics and recent findings."""

    recent_limit = _bounded_read_limit(
        recent_limit,
        default=10,
        maximum=50,
    )

    with _connection() as conn:
        status_rows = conn.execute("""
            SELECT status, COUNT(*) AS count
            FROM findings
            GROUP BY status
            ORDER BY status
        """).fetchall()

        severity_rows = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM findings
            GROUP BY severity
            ORDER BY severity
        """).fetchall()

        cross_tab_rows = conn.execute("""
            SELECT severity, status, COUNT(*) AS count
            FROM findings
            GROUP BY severity, status
            ORDER BY severity, status
        """).fetchall()

        rule_cursor = conn.execute("""
            SELECT
                rule_id,
                COUNT(*) AS count,
                SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END)
                    AS active,
                SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END)
                    AS resolved
            FROM findings
            GROUP BY rule_id
            ORDER BY count DESC, rule_id
        """)

        host_cursor = conn.execute("""
            SELECT
                host,
                COUNT(*) AS count,
                SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END)
                    AS active,
                SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END)
                    AS resolved
            FROM findings
            GROUP BY host
            ORDER BY count DESC, host
        """)
        lifecycle_row = conn.execute("""
            SELECT
                COUNT(*) AS total,
                COALESCE(
                    SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END),
                    0
                ) AS active,
                COALESCE(
                    SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END),
                    0
                ) AS resolved,
                COALESCE(
                    SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END),
                    0
                ) AS with_resolved_at,
                AVG(
                    CASE
                        WHEN resolved_at IS NOT NULL
                        THEN (
                            julianday(resolved_at) - julianday(first_seen)
                        ) * 86400.0
                    END
                ) AS average_resolution_seconds,
                MIN(first_seen) AS oldest_first_seen,
                MAX(last_seen) AS newest_last_seen
            FROM findings
        """).fetchone()

        total = conn.execute("""
            SELECT COUNT(*) FROM findings
        """).fetchone()[0]

        recent_cursor = conn.execute("""
            SELECT id, rule_id, severity, host, evidence,
                   first_seen, last_seen, status, resolved_at
            FROM findings
            ORDER BY last_seen DESC, id DESC
            LIMIT ?
        """, (recent_limit,))

        by_severity_and_status = {}

        for severity, status, count in cross_tab_rows:
            by_severity_and_status.setdefault(severity, {})[status] = count

        lifecycle = dict(zip(
            (
                "total",
                "active",
                "resolved",
                "with_resolved_at",
                "average_resolution_seconds",
                "oldest_first_seen",
                "newest_last_seen",
            ),
            lifecycle_row,
        ))

        if lifecycle["average_resolution_seconds"] is not None:
            lifecycle["average_resolution_seconds"] = round(
                lifecycle["average_resolution_seconds"],
                2,
            )

        return {
            "total_findings": total,
            "by_status": {
                status: count for status, count in status_rows
            },
            "by_severity": {
                severity: count for severity, count in severity_rows
            },
            "by_severity_and_status": by_severity_and_status,
            "by_rule": _rows_as_dicts(rule_cursor),
            "by_host": _rows_as_dicts(host_cursor),
            "lifecycle": lifecycle,
            "recent_findings": _rows_as_dicts(recent_cursor),
        }



def get_finding_details(finding_id: int):
    """Return a finding and its recorded scan-by-scan history."""

    try:
        finding_id = int(finding_id)
    except (TypeError, ValueError):
        raise ValueError("finding_id must be an integer.")

    with _connection() as conn:
        finding_cursor = conn.execute("""
            SELECT
                id, rule_id, severity, host, evidence,
                first_seen, last_seen, status,
                last_seen_run_id, resolved_at, finding_key
            FROM findings
            WHERE id = ?
        """, (finding_id,))

        finding_rows = _rows_as_dicts(finding_cursor)

        if not finding_rows:
            return {
                "finding": None,
                "history": [],
            }

        history_cursor = conn.execute("""
            SELECT
                s.run_id,
                r.started_at,
                r.completed_at,
                s.severity,
                s.evidence,
                s.status,
                s.resolved_at
            FROM scan_run_findings AS s
            JOIN scan_runs AS r ON r.id = s.run_id
            WHERE s.finding_id = ?
            ORDER BY s.run_id
        """, (finding_id,))

        return {
            "finding": finding_rows[0],
            "history": _rows_as_dicts(history_cursor),
        }


def compare_scan_runs(
    older_run_id: int,
    newer_run_id: int,
    limit: int = 50,
):
    """Compare two completed scan snapshots using stable finding IDs."""

    try:
        older_run_id = int(older_run_id)
        newer_run_id = int(newer_run_id)
    except (TypeError, ValueError):
        raise ValueError("Scan run IDs must be integers.")

    if older_run_id == newer_run_id:
        raise ValueError("The two scan run IDs must be different.")

    limit = _bounded_read_limit(limit, default=50, maximum=100)

    categories = (
        "added",
        "resolved",
        "reactivated",
        "changed",
        "unchanged",
        "removed",
    )

    with _connection() as conn:
        run_cursor = conn.execute("""
            SELECT
                id, started_at, completed_at,
                status, snapshot_recorded
            FROM scan_runs
            WHERE id IN (?, ?)
            ORDER BY id
        """, (older_run_id, newer_run_id))

        runs = {
            row["id"]: row
            for row in _rows_as_dicts(run_cursor)
        }

        for run_id in (older_run_id, newer_run_id):
            if run_id not in runs:
                raise ValueError(f"Scan run {run_id} does not exist.")

            if runs[run_id]["status"] != "COMPLETED":
                raise ValueError(
                    f"Scan run {run_id} is not completed."
                )

            if not runs[run_id]["snapshot_recorded"]:
                return {
                    "available": False,
                    "reason": (
                        f"Scan run {run_id} has no recorded finding "
                        "snapshot. It may predate snapshot support."
                    ),
                    "older_run": runs[older_run_id],
                    "newer_run": runs[newer_run_id],
                }

        def load_snapshot(run_id):
            cursor = conn.execute("""
                SELECT
                    finding_id, rule_id, severity, host,
                    evidence, first_seen, last_seen,
                    status, resolved_at, finding_key
                FROM scan_run_findings
                WHERE run_id = ?
                ORDER BY finding_id
            """, (run_id,))

            return {
                row["finding_id"]: row
                for row in _rows_as_dicts(cursor)
            }

        older = load_snapshot(older_run_id)
        newer = load_snapshot(newer_run_id)

    changes = {category: [] for category in categories}
    counts = {category: 0 for category in categories}

    all_ids = sorted(set(older) | set(newer))

    for finding_id in all_ids:
        old = older.get(finding_id)
        new = newer.get(finding_id)

        category = None

        if old is None:
            category = "added"
        elif new is None:
            category = "removed"
        elif old["status"] == "ACTIVE" and new["status"] == "RESOLVED":
            category = "resolved"
        elif old["status"] == "RESOLVED" and new["status"] == "ACTIVE":
            category = "reactivated"
        else:
            changed_fields = [
                field
                for field in (
                    "rule_id",
                    "severity",
                    "host",
                    "evidence",
                    "finding_key",
                )
                if old[field] != new[field]
            ]

            if changed_fields:
                category = "changed"
            else:
                category = "unchanged"

        counts[category] += 1

        if len(changes[category]) < limit:
            changes[category].append({
                "finding_id": finding_id,
                "old": old,
                "new": new,
            })

    return {
        "available": True,
        "older_run": runs[older_run_id],
        "newer_run": runs[newer_run_id],
        "counts": counts,
        "returned": {
            category: len(records)
            for category, records in changes.items()
        },
        "limit_per_category": limit,
        "changes": changes,
    }



def query_findings(
    status=None,
    severity=None,
    host=None,
    rule_id=None,
    limit=50,
    offset=0,
):
    """Return filtered findings with a hard result limit."""
    limit = _bounded_read_limit(limit)

    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0

    filters = []
    parameters = []

    for column, value in (
        ("status", status),
        ("severity", severity),
        ("host", host),
        ("rule_id", rule_id),
    ):
        if value is not None and str(value).strip():
            filters.append(f"{column} = ?")
            parameters.append(str(value).strip().upper()
                              if column in {"status", "severity"}
                              else str(value).strip())

    where_clause = (
        " WHERE " + " AND ".join(filters)
        if filters else ""
    )

    with _connection() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM findings{where_clause}",
            parameters,
        ).fetchone()[0]

        cursor = conn.execute(
            f"""
            SELECT id, rule_id, severity, host, evidence,
                   first_seen, last_seen, status, resolved_at,
                   last_seen_run_id
            FROM findings
            {where_clause}
            ORDER BY last_seen DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (*parameters, limit, offset),
        )

        findings = _rows_as_dicts(cursor)

    return {
        "total": total,
        "returned": len(findings),
        "limit": limit,
        "offset": offset,
        "findings": findings,
    }


def query_host_inventory(limit=200):
    """Return a bounded host inventory."""
    limit = _bounded_read_limit(limit)

    with _connection() as conn:
        cursor = conn.execute("""
            SELECT ip, status, hostname, last_seen
            FROM hosts
            ORDER BY ip
            LIMIT ?
        """, (limit,))

        hosts = _rows_as_dicts(cursor)

    return {
        "returned": len(hosts),
        "limit": limit,
        "hosts": hosts,
    }


def query_service_inventory(host_ip=None, limit=200):
    """Return a bounded service inventory, optionally filtered by host."""
    limit = _bounded_read_limit(limit)

    with _connection() as conn:
        if host_ip and host_ip.strip():
            cursor = conn.execute("""
                SELECT host_ip, port, protocol, service,
                       product, version, last_seen
                FROM services
                WHERE host_ip = ?
                ORDER BY port, protocol
                LIMIT ?
            """, (host_ip.strip(), limit))
        else:
            cursor = conn.execute("""
                SELECT host_ip, port, protocol, service,
                       product, version, last_seen
                FROM services
                ORDER BY host_ip, port, protocol
                LIMIT ?
            """, (limit,))

        services = _rows_as_dicts(cursor)

    return {
        "returned": len(services),
        "limit": limit,
        "services": services,
    }


def query_scan_history(limit=20):
    """Return recent scan runs."""
    limit = _bounded_read_limit(
        limit,
        default=20,
        maximum=100,
    )

    with _connection() as conn:
        cursor = conn.execute("""
            SELECT id, started_at, completed_at, status, error
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        runs = _rows_as_dicts(cursor)

    return {
        "returned": len(runs),
        "limit": limit,
        "scan_runs": runs,
    }
