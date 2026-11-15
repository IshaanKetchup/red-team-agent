import getpass
import ssl

from ldap3 import Server, Connection, Tls, SUBTREE
from ldap3.core.exceptions import LDAPException
from settings import LDAP_HOST, LDAP_PORT, LDAP_USER, CA_CERTS




def enumerate_ldap_users(
    domain_dn: str,
    password: str | None = None
) -> list[dict] | None:

    print(f"[*] Enumerating LDAP users on {LDAP_HOST}...")

    conn = None

    try:
        if password is None:
            password = getpass.getpass("LDAP password: ")

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
            receive_timeout=20
        )

        success = conn.search(
            search_base=domain_dn,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "displayName",
                "userPrincipalName"
            ],
            paged_size=500
        )

        if not success or conn.result.get("result") != 0:
            raise RuntimeError(f"LDAP search failed: {conn.result}")

        users = []

        for entry in conn.entries:
            users.append({
                "dn": entry.entry_dn,
                "sAMAccountName": entry.sAMAccountName.value,
                "displayName": entry.displayName.value,
                "userPrincipalName": entry.userPrincipalName.value
            })

        print(f"[+] Retrieved {len(users)} LDAP user entries.")
        return users

    except Exception as error:
        print(f"[!] LDAP enumeration failed: {error}")
        return None

    finally:
        if conn is not None and conn.bound:
            conn.unbind()
