import json
import sqlite3

from contextlib import closing

from database.storage import DB_PATH


MAX_LIMIT = 100
MAX_SEARCH_LENGTH = 256


def _validate_pagination(limit, offset):
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise ValueError("Limit must be an integer.")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"Limit must be between 1 and {MAX_LIMIT}.")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise ValueError("Offset must be an integer.")
    if offset < 0:
        raise ValueError("Offset cannot be negative.")


def _validate_search(search, field="Search"):
    if search is None:
        return None
    if not isinstance(search, str):
        raise ValueError(f"{field} must be a string.")
    search = search.strip()
    if len(search) > MAX_SEARCH_LENGTH:
        raise ValueError(
            f"{field} cannot exceed {MAX_SEARCH_LENGTH} characters."
        )
    return search or None


def _like_pattern(value):
    escaped = (
        value.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    return f"%{escaped}%"


def _fetch_all(query, parameters=()):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in conn.execute(query, parameters).fetchall()
        ]


def _fetch_one(query, parameters=()):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(query, parameters).fetchone()
        return dict(row) if row else None


def _resolve_group(group):
    """Resolve a group by DN, name, CN or sAMAccountName."""
    group = _validate_search(group, "Group")
    if not group:
        raise ValueError("A group name or distinguished name is required.")

    matches = _fetch_all("""
        SELECT dn, domain_dn, name, cn, sam_account_name,
               description, group_type, object_sid
        FROM ad_groups
        WHERE dn = ? COLLATE NOCASE
           OR name = ? COLLATE NOCASE
           OR cn = ? COLLATE NOCASE
           OR sam_account_name = ? COLLATE NOCASE
        ORDER BY dn
        LIMIT 3
    """, (group, group, group, group))

    if not matches:
        raise ValueError(f"Active Directory group not found: {group}")
    if len(matches) > 1:
        raise ValueError(
            f"Group identifier '{group}' is ambiguous. Use its full DN."
        )
    return matches[0]


def _resolve_user(user):
    """Resolve a user by DN, sAMAccountName or UPN."""
    user = _validate_search(user, "User")
    if not user:
        raise ValueError("A username or distinguished name is required.")

    matches = _fetch_all("""
        SELECT dn, domain_dn, sam_account_name, display_name,
               user_principal_name, enabled, object_sid
        FROM ad_users
        WHERE dn = ? COLLATE NOCASE
           OR sam_account_name = ? COLLATE NOCASE
           OR user_principal_name = ? COLLATE NOCASE
        ORDER BY dn
        LIMIT 3
    """, (user, user, user))

    if not matches:
        raise ValueError(f"Active Directory user not found: {user}")
    if len(matches) > 1:
        raise ValueError(
            f"User identifier '{user}' is ambiguous. Use its full DN."
        )
    return matches[0]


def _page_result(total, rows, limit, offset, key):
    return {
        "total": total,
        "returned": len(rows),
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(rows) < total,
        key: rows,
    }


def query_ad_users(
    search: str | None = None,
    enabled: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Query stored AD users. This function does not contact LDAP."""
    _validate_pagination(limit, offset)

    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("Enabled must be true, false or null.")

    search = _validate_search(search)
    conditions = []
    parameters = []

    if search:
        pattern = _like_pattern(search)
        conditions.append("""
            (
                sam_account_name LIKE ? ESCAPE '\\'
                OR display_name LIKE ? ESCAPE '\\'
                OR user_principal_name LIKE ? ESCAPE '\\'
                OR mail LIKE ? ESCAPE '\\'
                OR description LIKE ? ESCAPE '\\'
            )
        """)
        parameters.extend([pattern] * 5)

    if enabled is not None:
        conditions.append("enabled = ?")
        parameters.append(int(enabled))

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    count_query = f"SELECT COUNT(*) FROM ad_users {where_clause}"

    users_query = f"""
        SELECT dn, domain_dn, sam_account_name, display_name,
               user_principal_name, mail, description,
               user_account_control, enabled, object_sid,
               primary_group_id, pwd_last_set, last_logon_timestamp,
               when_created, admin_count, service_principal_names
        FROM ad_users
        {where_clause}
        ORDER BY sam_account_name COLLATE NOCASE
        LIMIT ? OFFSET ?
    """

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(count_query, parameters).fetchone()[0]
        rows = conn.execute(
            users_query, parameters + [limit, offset]
        ).fetchall()

    users = []
    for row in rows:
        user = dict(row)
        try:
            user["service_principal_names"] = (
                json.loads(user["service_principal_names"])
                if user["service_principal_names"] else []
            )
        except (json.JSONDecodeError, TypeError):
            user["service_principal_names"] = []

        if user["enabled"] is not None:
            user["enabled"] = bool(user["enabled"])
        users.append(user)

    return _page_result(total, users, limit, offset, "users")


def query_ad_groups(
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Search stored AD groups by name, CN, sAMAccountName or description."""
    _validate_pagination(limit, offset)
    search = _validate_search(search)

    conditions = []
    parameters = []

    if search:
        pattern = _like_pattern(search)
        conditions.append("""
            (
                name LIKE ? ESCAPE '\\'
                OR cn LIKE ? ESCAPE '\\'
                OR sam_account_name LIKE ? ESCAPE '\\'
                OR description LIKE ? ESCAPE '\\'
            )
        """)
        parameters.extend([pattern] * 4)

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    count = _fetch_one(
        f"SELECT COUNT(*) AS total FROM ad_groups {where_clause}",
        parameters,
    )["total"]

    groups = _fetch_all(f"""
        SELECT dn, domain_dn, name, cn, sam_account_name,
               description, group_type, object_sid
        FROM ad_groups
        {where_clause}
        ORDER BY name COLLATE NOCASE, dn
        LIMIT ? OFFSET ?
    """, parameters + [limit, offset])

    return _page_result(count, groups, limit, offset, "groups")


def query_ad_group_members(
    group: str,
    include_nested: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """
    Return direct members and, optionally, users with stored nested paths
    ending at the requested group.
    """
    _validate_pagination(limit, offset)
    if not isinstance(include_nested, bool):
        raise ValueError("include_nested must be true or false.")

    resolved = _resolve_group(group)
    group_dn = resolved["dn"]

    direct = _fetch_all("""
        SELECT
            m.member_dn,
            CASE
                WHEN u.dn IS NOT NULL THEN 'USER'
                WHEN g.dn IS NOT NULL THEN 'GROUP'
                ELSE 'UNKNOWN'
            END AS member_object_type,
            COALESCE(u.sam_account_name, g.sam_account_name) AS sam_account_name,
            COALESCE(u.display_name, g.name) AS display_name,
            u.user_principal_name,
            u.enabled,
            1 AS membership_depth,
            'DIRECT' AS membership_kind,
            NULL AS path
        FROM ad_memberships m
        LEFT JOIN ad_users u ON u.dn = m.member_dn
        LEFT JOIN ad_groups g ON g.dn = m.member_dn
        WHERE m.group_dn = ?
        ORDER BY member_object_type, sam_account_name, m.member_dn
    """, (group_dn,))

    members_by_dn = {item["member_dn"]: item for item in direct}

    if include_nested:
        nested = _fetch_all("""
            SELECT
                p.source_dn AS member_dn,
                'USER' AS member_object_type,
                u.sam_account_name,
                u.display_name,
                u.user_principal_name,
                u.enabled,
                p.depth AS membership_depth,
                'NESTED' AS membership_kind,
                p.path_json AS path
            FROM ad_membership_paths p
            JOIN ad_users u ON u.dn = p.source_dn
            WHERE p.target_group_dn = ?
            ORDER BY u.sam_account_name COLLATE NOCASE, p.depth
        """, (group_dn,))

        for item in nested:
            if item["member_dn"] not in members_by_dn:
                try:
                    item["path"] = json.loads(item["path"]) if item["path"] else []
                except (json.JSONDecodeError, TypeError):
                    item["path"] = []
                members_by_dn[item["member_dn"]] = item

    members = sorted(
        members_by_dn.values(),
        key=lambda item: (
            (item.get("sam_account_name") or "").casefold(),
            item["member_dn"].casefold(),
        ),
    )
    total = len(members)
    page = members[offset:offset + limit]

    for item in page:
        if item.get("enabled") is not None:
            item["enabled"] = bool(item["enabled"])
        if item.get("membership_kind") == "DIRECT":
            item["path"] = [item["member_dn"], group_dn]

    return {
        "group": resolved,
        "include_nested": include_nested,
        **_page_result(total, page, limit, offset, "members"),
    }


def query_ad_user_groups(
    user: str,
    include_nested: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Return a user's direct groups and optional stored nested group paths."""
    _validate_pagination(limit, offset)
    if not isinstance(include_nested, bool):
        raise ValueError("include_nested must be true or false.")

    resolved = _resolve_user(user)
    user_dn = resolved["dn"]

    direct = _fetch_all("""
        SELECT
            g.dn AS group_dn,
            g.name,
            g.sam_account_name,
            g.description,
            1 AS membership_depth,
            'DIRECT' AS membership_kind,
            NULL AS path
        FROM ad_memberships m
        JOIN ad_groups g ON g.dn = m.group_dn
        WHERE m.member_dn = ?
        ORDER BY g.name COLLATE NOCASE, g.dn
    """, (user_dn,))

    groups_by_dn = {item["group_dn"]: item for item in direct}

    if include_nested:
        nested = _fetch_all("""
            SELECT
                g.dn AS group_dn,
                g.name,
                g.sam_account_name,
                g.description,
                p.depth AS membership_depth,
                'NESTED' AS membership_kind,
                p.path_json AS path
            FROM ad_membership_paths p
            JOIN ad_groups g ON g.dn = p.target_group_dn
            WHERE p.source_dn = ?
            ORDER BY g.name COLLATE NOCASE, p.depth
        """, (user_dn,))

        for item in nested:
            if item["group_dn"] not in groups_by_dn:
                try:
                    item["path"] = json.loads(item["path"]) if item["path"] else []
                except (json.JSONDecodeError, TypeError):
                    item["path"] = []
                groups_by_dn[item["group_dn"]] = item

    groups = sorted(
        groups_by_dn.values(),
        key=lambda item: (
            (item.get("name") or "").casefold(),
            item["group_dn"].casefold(),
        ),
    )
    total = len(groups)
    page = groups[offset:offset + limit]

    for item in page:
        if item.get("membership_kind") == "DIRECT":
            item["path"] = [user_dn, item["group_dn"]]

    return {
        "user": resolved,
        "include_nested": include_nested,
        **_page_result(total, page, limit, offset, "groups"),
    }


def query_ad_membership_paths(
    user: str | None = None,
    group: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """
    Query stored transitive membership paths.
    Filter by source user, target group, or both.
    """
    _validate_pagination(limit, offset)

    user_record = _resolve_user(user) if user else None
    group_record = _resolve_group(group) if group else None

    conditions = []
    parameters = []

    if user_record:
        conditions.append("p.source_dn = ?")
        parameters.append(user_record["dn"])

    if group_record:
        conditions.append("p.target_group_dn = ?")
        parameters.append(group_record["dn"])

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    total = _fetch_one(f"""
        SELECT COUNT(*) AS total
        FROM ad_membership_paths p
        {where_clause}
    """, parameters)["total"]

    paths = _fetch_all(f"""
        SELECT
            p.domain_dn,
            p.source_dn,
            u.sam_account_name,
            u.display_name,
            p.target_group_dn,
            g.name AS target_group_name,
            p.depth,
            p.path_json
        FROM ad_membership_paths p
        LEFT JOIN ad_users u ON u.dn = p.source_dn
        LEFT JOIN ad_groups g ON g.dn = p.target_group_dn
        {where_clause}
        ORDER BY u.sam_account_name COLLATE NOCASE,
                 g.name COLLATE NOCASE, p.depth
        LIMIT ? OFFSET ?
    """, parameters + [limit, offset])

    for item in paths:
        try:
            item["path"] = (
                json.loads(item.pop("path_json"))
                if item.get("path_json") else []
            )
        except (json.JSONDecodeError, TypeError):
            item["path"] = []
            item.pop("path_json", None)

    return {
        "user_filter": user_record,
        "group_filter": group_record,
        **_page_result(total, paths, limit, offset, "paths"),
    }
