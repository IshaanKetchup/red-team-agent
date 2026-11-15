
import sqlite3

import pandas as pd
import streamlit as st

from engine.orchestrator import (
    run_full_scan,
    run_discovery,
    run_service_enumeration,
    run_ldap_enumeration
)

from database.storage import (
    DB_PATH,
    get_hosts,
    get_services,
    get_users,
    get_findings,
    get_scan_runs
)


st.set_page_config(
    page_title="Red Team Agent",
    page_icon="",
    layout="wide"
)


# ==========================================================
# STYLING
# ==========================================================

st.markdown("""
<style>
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    div[data-testid="stMetric"] {
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.2);
        padding: 14px;
        border-radius: 8px;
    }

    .section-note {
        color: gray;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================================
# SESSION STATE
# ==========================================================

if "activity" not in st.session_state:
    st.session_state.activity = []

if "last_action" not in st.session_state:
    st.session_state.last_action = "No scan started."


def log_event(message):
    st.session_state.activity.append(str(message))


def refresh_data():
    st.rerun()


# ==========================================================
# DATABASE HELPERS
# ==========================================================

def read_scan_runs():
    return get_scan_runs()


def get_latest_scan():
    runs = read_scan_runs()
    return runs[0] if runs else None


def read_ad_table(table_name):
    """
    Read an AD table if it exists.

    Table names are selected internally from a fixed list.
    """

    allowed_tables = {
        "ad_domains",
        "ad_users",
        "ad_groups",
        "ad_memberships",
        "ad_membership_paths",
        "ad_password_policies"
    }

    if table_name not in allowed_tables:
        raise ValueError("Unsupported table name.")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            return pd.read_sql_query(
                f'SELECT * FROM "{table_name}"',
                conn
            )
    except (sqlite3.OperationalError, pd.errors.DatabaseError):
        return pd.DataFrame()


def read_ad_inventory():
    return {
        "domains": read_ad_table("ad_domains"),
        "users": read_ad_table("ad_users"),
        "groups": read_ad_table("ad_groups"),
        "memberships": read_ad_table("ad_memberships"),
        "paths": read_ad_table("ad_membership_paths"),
        "policies": read_ad_table("ad_password_policies")
    }


def display_table(dataframe, empty_message):
    if dataframe.empty:
        st.info(empty_message)
    else:
        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True
        )


# ==========================================================
# HEADER
# ==========================================================

st.title("Red Team Agent")
st.caption("Internal security assessment dashboard")

latest = get_latest_scan()

if latest:
    st.caption(
        f"Latest scan: #{latest[0]} | "
        f"{latest[3]} | Started: {latest[1]}"
    )
else:
    st.caption("No scan history available.")


# ==========================================================
# LOAD INVENTORY
# ==========================================================

hosts = get_hosts()
services = get_services()
users = get_users()
findings = get_findings()

active_findings = [
    finding for finding in findings
    if finding[6] == "ACTIVE"
]

resolved_findings = [
    finding for finding in findings
    if finding[6] == "RESOLVED"
]

ad = read_ad_inventory()


# ==========================================================
# OVERVIEW METRICS
# ==========================================================

st.subheader("Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Hosts", len(hosts))
col2.metric("Services", len(services))
col3.metric("AD users", len(ad["users"]))
col4.metric("AD groups", len(ad["groups"]))
col5.metric("Active findings", len(active_findings))

st.divider()


# ==========================================================
# SCAN CONTROLS
# ==========================================================

st.subheader("Scan controls")

ldap_password = st.text_input(
    "LDAP password",
    type="password",
    help="Used for LDAPS enumeration. It is not written to the database."
)

c1, c2, c3, c4 = st.columns(4)

full_scan_clicked = c1.button(
    "Run full scan",
    type="primary",
    use_container_width=True
)

discovery_clicked = c2.button(
    "Discover hosts",
    use_container_width=True
)

service_clicked = c3.button(
    "Enumerate services",
    use_container_width=True
)

ldap_clicked = c4.button(
    "Enumerate AD",
    use_container_width=True
)


# ==========================================================
# EXECUTE SELECTED ACTION
# ==========================================================

if full_scan_clicked or ldap_clicked:
    if not ldap_password:
        st.error("Enter the LDAP password first.")
        st.stop()


if any([
    full_scan_clicked,
    discovery_clicked,
    service_clicked,
    ldap_clicked
]):
    st.session_state.activity = []

    console = st.empty()

    def dashboard_log(message):
        log_event(message)

        console.code(
            "\n".join(st.session_state.activity[-25:]),
            language="text"
        )

    try:
        with st.spinner("Operation running..."):

            if full_scan_clicked:
                dashboard_log("Starting full scan...")

                result = run_full_scan(
                    ldap_password,
                    log=dashboard_log
                )

                st.session_state.last_action = (
                    f"Full scan #{result['run_id']} completed."
                )

            elif discovery_clicked:
                run_discovery(log=dashboard_log)

                st.session_state.last_action = (
                    "Host discovery completed."
                )

            elif service_clicked:
                run_service_enumeration(log=dashboard_log)

                st.session_state.last_action = (
                    "Service enumeration completed."
                )

            elif ldap_clicked:
                run_ldap_enumeration(
                    ldap_password,
                    log=dashboard_log
                )

                st.session_state.last_action = (
                    "Active Directory enumeration completed."
                )

        st.success(st.session_state.last_action)

        # Reload inventory from SQLite after the operation.
        st.rerun()

    except Exception as error:
        st.error(f"Operation failed: {error}")


st.caption(f"Last action: {st.session_state.last_action}")

st.divider()


# ==========================================================
# DASHBOARD TABS
# ==========================================================

(
    overview_tab,
    hosts_tab,
    services_tab,
    domain_tab,
    ad_users_tab,
    groups_tab,
    memberships_tab,
    privilege_tab,
    findings_tab,
    history_tab,
    console_tab
) = st.tabs([
    "Overview",
    "Hosts",
    "Services",
    "Domain",
    "AD Users",
    "AD Groups",
    "Memberships",
    "Privilege Analysis",
    "Findings",
    "Scan History",
    "Activity"
])


# ==========================================================
# OVERVIEW TAB
# ==========================================================

with overview_tab:

    st.subheader("Finding summary")

    if active_findings:
        severity_counts = {}

        for finding in active_findings:
            severity = finding[1]

            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

        cols = st.columns(4)

        for index, severity in enumerate(
            ["CRITICAL", "HIGH", "WARNING", "INFO"]
        ):
            cols[index].metric(
                severity,
                severity_counts.get(severity, 0)
            )
    else:
        st.info("No active findings.")

    st.subheader("AD inventory summary")

    ad_col1, ad_col2, ad_col3, ad_col4 = st.columns(4)

    ad_col1.metric("Domains", len(ad["domains"]))
    ad_col2.metric("AD users", len(ad["users"]))
    ad_col3.metric("AD groups", len(ad["groups"]))
    ad_col4.metric("Memberships", len(ad["memberships"]))

    st.subheader("Privilege analysis summary")

    privilege_col1, privilege_col2 = st.columns(2)

    privilege_col1.metric(
        "Sensitive groups",
        ad["groups"].shape[0]
        if ad["groups"].empty
        else len(ad["groups"])
    )

    privilege_col2.metric(
        "Derived membership paths",
        len(ad["paths"])
    )

    st.subheader("Recently discovered hosts")

    if hosts:
        st.dataframe(
            pd.DataFrame(
                hosts,
                columns=[
                    "IP address",
                    "Status",
                    "Hostname",
                    "Last seen"
                ]
            ),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No hosts discovered yet.")


# ==========================================================
# HOSTS TAB
# ==========================================================

with hosts_tab:

    st.subheader("Host inventory")

    if hosts:
        for host in hosts:
            ip, status, hostname, last_seen = host

            with st.expander(
                f"{ip} — {hostname or 'Unknown hostname'}"
            ):
                st.write(f"Status: {status}")
                st.write(f"Last seen: {last_seen}")

                host_services = [
                    service for service in services
                    if service[0] == ip
                ]

                st.write(
                    f"Services discovered: {len(host_services)}"
                )

                if host_services:
                    st.dataframe(
                        pd.DataFrame(
                            host_services,
                            columns=[
                                "IP",
                                "Port",
                                "Protocol",
                                "Service",
                                "Product",
                                "Version"
                            ]
                        ),
                        use_container_width=True,
                        hide_index=True
                    )
    else:
        st.info("No hosts in inventory.")


# ==========================================================
# SERVICES TAB
# ==========================================================

with services_tab:

    st.subheader("Service inventory")

    if services:
        service_df = pd.DataFrame(
            services,
            columns=[
                "Host",
                "Port",
                "Protocol",
                "Service",
                "Product",
                "Version"
            ]
        )

        selected_host = st.selectbox(
            "Filter by host",
            ["All hosts"] + sorted(
                service_df["Host"].unique().tolist()
            )
        )

        if selected_host != "All hosts":
            service_df = service_df[
                service_df["Host"] == selected_host
            ]

        st.dataframe(
            service_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No services discovered yet.")


# ==========================================================
# DOMAIN TAB
# ==========================================================

with domain_tab:

    st.subheader("Active Directory domain")

    st.write("Domain information")
    display_table(
        ad["domains"],
        "No domain information collected yet."
    )

    st.write("Domain password policy")
    display_table(
        ad["policies"],
        "No password policy information collected yet."
    )


# ==========================================================
# AD USERS TAB
# ==========================================================

with ad_users_tab:

    st.subheader("Active Directory users")

    if not ad["users"].empty:

        user_df = ad["users"].copy()

        search = st.text_input(
            "Search accounts",
            key="ad_user_search"
        )

        if search:
            mask = user_df.astype(str).apply(
                lambda column: column.str.contains(
                    search,
                    case=False,
                    na=False
                )
            ).any(axis=1)

            user_df = user_df[mask]

        st.dataframe(
            user_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No AD users enumerated yet.")

    st.subheader("Legacy LDAP user inventory")

    if users:
        st.dataframe(
            pd.DataFrame(
                users,
                columns=[
                    "Distinguished name",
                    "Account",
                    "Display name",
                    "User principal name",
                    "Last seen"
                ]
            ),
            use_container_width=True,
            hide_index=True
        )


# ==========================================================
# AD GROUPS TAB
# ==========================================================

with groups_tab:

    st.subheader("Active Directory groups")

    if not ad["groups"].empty:

        group_df = ad["groups"].copy()

        group_search = st.text_input(
            "Search groups",
            key="ad_group_search"
        )

        if group_search:
            mask = group_df.astype(str).apply(
                lambda column: column.str.contains(
                    group_search,
                    case=False,
                    na=False
                )
            ).any(axis=1)

            group_df = group_df[mask]

        st.dataframe(
            group_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No AD groups enumerated yet.")


# ==========================================================
# MEMBERSHIPS TAB
# ==========================================================

with memberships_tab:

    st.subheader("AD group memberships")

    if not ad["memberships"].empty:

        membership_df = ad["memberships"].copy()

        if "membership_type" in membership_df.columns:
            membership_types = sorted(
                membership_df["membership_type"]
                .dropna()
                .unique()
                .tolist()
            )

            selected_type = st.selectbox(
                "Membership type",
                ["All"] + membership_types
            )

            if selected_type != "All":
                membership_df = membership_df[
                    membership_df["membership_type"]
                    == selected_type
                ]

        st.dataframe(
            membership_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No membership relationships collected yet.")


# ==========================================================
# PRIVILEGE ANALYSIS TAB
# ==========================================================

with privilege_tab:

    st.subheader("Derived AD membership paths")

    st.caption(
        "These records represent direct and nested membership paths "
        "to groups classified by the privilege analysis module."
    )

    if not ad["paths"].empty:

        path_df = ad["paths"].copy()

        st.metric(
            "Stored membership paths",
            len(path_df)
        )

        st.dataframe(
            path_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info(
            "No derived membership paths stored. "
            "Run AD enumeration and privilege analysis first."
        )

    st.subheader("Privilege-related findings")

    privilege_findings = [
        finding for finding in active_findings
        if finding[0] == "AD_PRIVILEGED_MEMBERSHIP"
    ]

    if privilege_findings:

        privilege_findings_df = pd.DataFrame(
            privilege_findings,
            columns=[
                "Rule",
                "Severity",
                "Host",
                "Evidence",
                "First seen",
                "Last seen",
                "Status",
                "Resolved at"
            ]
        )

        st.dataframe(
            privilege_findings_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No active privilege-related findings.")


# ==========================================================
# FINDINGS TAB
# ==========================================================

with findings_tab:

    st.subheader("Security findings")

    finding_filter = st.selectbox(
        "Finding status",
        ["ACTIVE", "RESOLVED", "ALL"]
    )

    severity_filter = st.selectbox(
        "Severity",
        ["ALL", "CRITICAL", "HIGH", "WARNING", "INFO"]
    )

    filtered_findings = [
        finding for finding in findings
        if (
            finding_filter == "ALL"
            or finding[6] == finding_filter
        )
        and (
            severity_filter == "ALL"
            or finding[1] == severity_filter
        )
    ]

    if filtered_findings:

        finding_df = pd.DataFrame(
            filtered_findings,
            columns=[
                "Rule",
                "Severity",
                "Host",
                "Evidence",
                "First seen",
                "Last seen",
                "Status",
                "Resolved at"
            ]
        )

        st.dataframe(
            finding_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No findings match these filters.")


# ==========================================================
# SCAN HISTORY TAB
# ==========================================================

with history_tab:

    st.subheader("Scan history")

    runs = read_scan_runs()

    if runs:

        history_df = pd.DataFrame(
            runs,
            columns=[
                "Run ID",
                "Started",
                "Completed",
                "Status",
                "Error"
            ]
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No scan history available.")


# ==========================================================
# ACTIVITY TAB
# ==========================================================

with console_tab:

    st.subheader("Recent activity")

    if st.session_state.activity:

        st.code(
            "\n".join(st.session_state.activity[-100:]),
            language="text"
        )

    else:
        st.info("No activity in this dashboard session.")


# ==========================================================
# FOOTER
# ==========================================================

st.divider()

if st.button("Refresh dashboard"):
    refresh_data()
