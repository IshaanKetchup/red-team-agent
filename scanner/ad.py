
import getpass
import ssl

from ldap3 import Server, Connection, Tls, SUBTREE, BASE
from settings import LDAP_HOST, LDAP_PORT, LDAP_USER, CA_CERTS, DOMAIN_DN




def get_value(entry, attribute, default=None):
    """Safely retrieve a single LDAP attribute value."""
    try:
        value = entry[attribute].value
        return value if value is not None else default
    except (KeyError, AttributeError):
        return default


def get_values(entry, attribute):
    """Safely retrieve a multi-valued LDAP attribute."""
    try:
        values = entry[attribute].values
        return list(values) if values else []
    except (KeyError, AttributeError):
        return []


def resolve_primary_group_memberships(domain_sid, users, groups):
    """Resolve primary-group relationships using SIDs."""

    if not domain_sid:
        raise ValueError("Domain SID is required for primary-group resolution.")

    groups_by_sid = {
        str(group["objectSid"]): group
        for group in groups
        if group.get("objectSid")
    }

    memberships = []
    unresolved = 0

    for user in users:
        user_sid = user.get("objectSid")
        primary_group_id = user.get("primaryGroupID")

        if not user_sid or primary_group_id is None:
            unresolved += 1
            continue

        try:
            primary_group_sid = f"{domain_sid}-{int(primary_group_id)}"
        except (TypeError, ValueError):
            unresolved += 1
            continue

        group = groups_by_sid.get(primary_group_sid)

        if group is None:
            unresolved += 1
            continue

        memberships.append({
            "group_dn": group["dn"],
            "member_dn": user["dn"],
            "membership_type": "PRIMARY"
        })

    print(f"[+] Resolved primary groups: {len(memberships)}")

    if unresolved:
        print(f"[!] Primary groups unresolved for {unresolved} user(s).")

    return memberships


def enumerate_ad_data(domain_dn=DOMAIN_DN, password=None):
    """
    Collect read-only Active Directory information over LDAPS.

    Returns domain, users, groups, memberships and password_policy.
    Returns None if enumeration fails.
    """

    print(f"[*] Connecting to {LDAP_HOST}:{LDAP_PORT} over LDAPS...")

    conn = None

    try:
        if password is None:
            password = getpass.getpass("LDAP password: ")

        if not password:
            raise ValueError("LDAP password is required.")

        tls_config = Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=CA_CERTS
        )

        server = Server(
            LDAP_HOST,
            port=LDAP_PORT,
            use_ssl=True,
            tls=tls_config,
            connect_timeout=10
        )

        conn = Connection(
            server,
            user=LDAP_USER,
            password=password,
            auto_bind=True,
            receive_timeout=30
        )

        print("[+] LDAPS authentication successful.")

        # Domain information and password policy
        print("[*] Enumerating domain information...")

        domain_attributes = [
            "distinguishedName",
            "name",
            "dnsRoot",
            "objectSid",
            "msDS-Behavior-Version",
            "minPwdLength",
            "pwdHistoryLength",
            "maxPwdAge",
            "minPwdAge",
            "pwdProperties",
            "lockoutThreshold",
            "lockoutDuration",
            "lockOutObservationWindow"
        ]

        success = conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=domain_attributes
        )

        if not success or conn.result.get("result") != 0:
            raise RuntimeError(f"Domain query failed: {conn.result}")

        if not conn.entries:
            raise RuntimeError("Domain object was not returned.")

        domain_entry = conn.entries[0]

        domain = {
            "dn": get_value(domain_entry, "distinguishedName"),
            "name": get_value(domain_entry, "name"),
            "dnsRoot": get_value(domain_entry, "dnsRoot"),
            "objectSid": get_value(domain_entry, "objectSid"),
            "functionalLevel": get_value(
                domain_entry, "msDS-Behavior-Version"
            )
        }

        password_policy = {
            "minPasswordLength": get_value(domain_entry, "minPwdLength"),
            "passwordHistoryLength": get_value(
                domain_entry, "pwdHistoryLength"
            ),
            "maxPasswordAge": get_value(domain_entry, "maxPwdAge"),
            "minPasswordAge": get_value(domain_entry, "minPwdAge"),
            "passwordProperties": get_value(
                domain_entry, "pwdProperties"
            ),
            "lockoutThreshold": get_value(
                domain_entry, "lockoutThreshold"
            ),
            "lockoutDuration": get_value(
                domain_entry, "lockoutDuration"
            ),
            "lockoutObservationWindow": get_value(
                domain_entry, "lockOutObservationWindow"
            )
        }

        if not domain.get("objectSid"):
            raise RuntimeError("Domain SID was not returned by LDAP.")

        # Users
        print("[*] Enumerating domain users...")

        user_attributes = [
            "sAMAccountName",
            "displayName",
            "userPrincipalName",
            "mail",
            "description",
            "userAccountControl",
            "objectSid",
            "primaryGroupID",
            "pwdLastSet",
            "lastLogonTimestamp",
            "whenCreated",
            "adminCount",
            "servicePrincipalName"
        ]

        success = conn.search(
            search_base=domain_dn,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            search_scope=SUBTREE,
            attributes=user_attributes,
            paged_size=500
        )

        if not success or conn.result.get("result") != 0:
            raise RuntimeError(f"User enumeration failed: {conn.result}")

        users = []

        for entry in conn.entries:
            account_control = get_value(entry, "userAccountControl")

            try:
                account_control = int(account_control)
                enabled = not bool(account_control & 2)
            except (TypeError, ValueError):
                account_control = None
                enabled = None

            users.append({
                "dn": entry.entry_dn,
                "sAMAccountName": get_value(entry, "sAMAccountName"),
                "displayName": get_value(entry, "displayName"),
                "userPrincipalName": get_value(
                    entry, "userPrincipalName"
                ),
                "mail": get_value(entry, "mail"),
                "description": get_value(entry, "description"),
                "userAccountControl": account_control,
                "enabled": enabled,
                "objectSid": get_value(entry, "objectSid"),
                "primaryGroupID": get_value(entry, "primaryGroupID"),
                "pwdLastSet": get_value(entry, "pwdLastSet"),
                "lastLogonTimestamp": get_value(
                    entry, "lastLogonTimestamp"
                ),
                "whenCreated": get_value(entry, "whenCreated"),
                "adminCount": get_value(entry, "adminCount"),
                "servicePrincipalName": get_values(
                    entry, "servicePrincipalName"
                )
            })

        # Groups and direct memberships
        print("[*] Enumerating domain groups...")

        group_attributes = [
            "cn",
            "name",
            "sAMAccountName",
            "description",
            "groupType",
            "objectSid",
            "member"
        ]

        success = conn.search(
            search_base=domain_dn,
            search_filter="(objectClass=group)",
            search_scope=SUBTREE,
            attributes=group_attributes,
            paged_size=500
        )

        if not success or conn.result.get("result") != 0:
            raise RuntimeError(f"Group enumeration failed: {conn.result}")

        groups = []
        memberships = []

        for entry in conn.entries:
            group_dn = entry.entry_dn

            groups.append({
                "dn": group_dn,
                "name": get_value(entry, "name"),
                "cn": get_value(entry, "cn"),
                "sAMAccountName": get_value(entry, "sAMAccountName"),
                "description": get_value(entry, "description"),
                "groupType": get_value(entry, "groupType"),
                "objectSid": get_value(entry, "objectSid")
            })

            for member_dn in get_values(entry, "member"):
                memberships.append({
                    "group_dn": group_dn,
                    "member_dn": str(member_dn),
                    "membership_type": "DIRECT"
                })

        # Primary-group relationships
        print("[*] Resolving primary group memberships...")

        primary_memberships = resolve_primary_group_memberships(
            domain["objectSid"],
            users,
            groups
        )

        memberships.extend(primary_memberships)

        direct_count = sum(
            item["membership_type"] == "DIRECT"
            for item in memberships
        )

        primary_count = sum(
            item["membership_type"] == "PRIMARY"
            for item in memberships
        )

        print("[+] AD enumeration completed.")
        print(f"    Domain: {domain.get('dnsRoot') or domain_dn}")
        print(f"    Users: {len(users)}")
        print(f"    Groups: {len(groups)}")
        print(f"    Direct memberships: {direct_count}")
        print(f"    Primary memberships: {primary_count}")

        return {
            "domain": domain,
            "users": users,
            "groups": groups,
            "memberships": memberships,
            "password_policy": password_policy
        }

    except Exception as error:
        print(f"[!] AD enumeration failed: {error}")
        return None

    finally:
        if conn is not None and conn.bound:
            conn.unbind()


if __name__ == "__main__":
    result = enumerate_ad_data()

    if result is None:
        raise SystemExit(1)

    print("\n[+] Domain:")
    print(result["domain"])

    print("\n[+] Password policy:")
    print(result["password_policy"])

    print("\n[+] Memberships:")
    for membership in result["memberships"]:
        print(
            f"[{membership['membership_type']}] "
            f"{membership['member_dn']} -> {membership['group_dn']}"
        )
