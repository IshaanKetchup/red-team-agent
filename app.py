
import json
import sqlite3
import traceback
import pandas as pd
import streamlit as st

from engine.orchestrator import (
    run_full_scan,
    run_discovery,
    run_service_enumeration,
    run_ldap_enumeration,
)

from database.storage import (
    DB_PATH,
    get_hosts,
    get_services,
    get_users,
    get_findings,
    get_scan_runs,
    get_findings_summary,
    get_finding_details,
    compare_scan_runs,
    query_findings,
)

from llm.runtime import (
    run_agent_step,
    run_readonly_command,
)


# ==========================================================
# PAGE CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="Red Team Agent",
    page_icon="",
    layout="wide",
)


# ==========================================================
# STYLING
# ==========================================================

st.markdown(
    """
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
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# SESSION STATE
# ==========================================================

SESSION_DEFAULTS = {
    "activity": [],
    "last_action": "No scan started.",
    "active_view": "dashboard",
    "agent_history": [],
    "agent_provider": None,
    "pending_tool_calls": [],
    "agent_status": "Ready",
}

for key, value in SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def set_view(view):
    st.session_state.active_view = view


def log_event(message):
    st.session_state.activity.append(str(message))


def refresh_data():
    st.rerun()


# ==========================================================
# AI ASSISTANT HELPERS
# ==========================================================

def process_agent_prompt(prompt):
    """Process a user prompt using the existing agent runtime."""

    prompt = prompt.strip()

    if not prompt:
        return

    if st.session_state.pending_tool_calls:
        st.warning(
            "Approve or decline the pending tool call before "
            "sending another prompt."
        )
        return

    st.session_state.agent_history.append({
        "role": "user",
        "content": prompt,
    })

    st.session_state.agent_status = "Processing"

    try:
        # Explicit read-only commands bypass the LLM entirely.
        
        if prompt.startswith("/"):
            result = run_readonly_command(prompt)

            if result.get("error"):
                st.session_state.agent_history.append({
                    "role": "assistant",
                    "content": str(result["error"]),
                })
            else:
                output = result.get("result", "")
                tool_name = result.get("tool", "")

                parsed = parse_json_result(output)

                message = {
                    "role": "assistant",
                    "content": str(output),
                }

                if tool_name == "get_findings_summary" and isinstance(parsed, dict):
                    message["display_type"] = "findings_summary"
                    message["display_data"] = parsed
                elif parsed is not None:
                    message["display_type"] = "direct_tool_result"
                    message["display_data"] = parsed
                    message["tool_name"] = tool_name

                st.session_state.agent_history.append(message)

            st.session_state.agent_status = "Ready"
            return


        result = run_agent_step(
            history=st.session_state.agent_history,
            preferred_provider=st.session_state.agent_provider,
            pending_calls=st.session_state.pending_tool_calls,
        )

        st.session_state.agent_provider = result.get("provider")
        st.session_state.pending_tool_calls = result.get(
            "pending_calls",
            [],
        )

        st.session_state.agent_status = result.get("status", "complete")

        if result.get("error"):
            st.session_state.agent_history.append({
                "role": "assistant",
                "content": f"Agent error: {result['error']}",
            })

        elif result.get("assistant_text"):
            # The runtime already appends normal assistant responses
            # to history. Only append here if it has not done so.
            last_message = (
                st.session_state.agent_history[-1]
                if st.session_state.agent_history
                else {}
            )

            if not (
                last_message.get("role") == "assistant"
                and last_message.get("content")
                == result["assistant_text"]
            ):
                st.session_state.agent_history.append({
                    "role": "assistant",
                    "content": result["assistant_text"],
                })

    except Exception as error:
        st.session_state.agent_status = "Error"

        st.session_state.agent_history.append({
            "role": "assistant",
            "content": (
                f"Agent execution failed: "
                f"{type(error).__name__}: {error}"
            ),
        })


def process_tool_decision(decision):
    """Approve or decline the next pending MCP tool call."""

    if not st.session_state.pending_tool_calls:
        st.warning("There is no pending tool call.")
        return

    st.session_state.agent_status = "Executing tool"

    try:
        result = run_agent_step(
            history=st.session_state.agent_history,
            preferred_provider=st.session_state.agent_provider,
            pending_calls=st.session_state.pending_tool_calls,
            decision=decision,
        )

        st.session_state.agent_provider = result.get("provider")
        st.session_state.pending_tool_calls = result.get(
            "pending_calls",
            [],
        )

        st.session_state.agent_status = result.get("status", "complete")

        if result.get("error"):
            st.session_state.agent_history.append({
                "role": "assistant",
                "content": f"Agent error: {result['error']}",
            })

        elif result.get("assistant_text"):
            last_message = (
                st.session_state.agent_history[-1]
                if st.session_state.agent_history
                else {}
            )

            if not (
                last_message.get("role") == "assistant"
                and last_message.get("content")
                == result["assistant_text"]
            ):
                st.session_state.agent_history.append({
                    "role": "assistant",
                    "content": result["assistant_text"],
                })

    except Exception as error:
        st.session_state.agent_status = "Error"

        details = "".join(
            traceback.format_exception(error)
        )

        st.session_state.agent_history.append({
            "role": "assistant",
            "content": (
                f"Tool processing failed:\n\n{details}"
            ),
        })


def clear_agent_conversation():
    if st.session_state.pending_tool_calls:
        st.warning(
            "Resolve pending tool calls before clearing the conversation."
        )
        return

    st.session_state.agent_history = []
    st.session_state.agent_provider = None
    st.session_state.agent_status = "Ready"


def parse_json_result(content):
    """Parse JSON tool output without failing on ordinary text."""
    if isinstance(content, (dict, list)):
        return content

    if not isinstance(content, str):
        return None

    try:
        return json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None


def render_findings_summary(data):
    """Render get_findings_summary output as a structured report."""

    if not isinstance(data, dict):
        st.write(data)
        return

    lifecycle = data.get("lifecycle", {})
    total = data.get("total_findings", 0)

    st.subheader("Findings overview")

    metric_cols = st.columns(4)

    metric_cols[0].metric("Total findings", total)
    metric_cols[1].metric(
        "Active",
        lifecycle.get("active", data.get("by_status", {}).get("ACTIVE", 0)),
    )
    metric_cols[2].metric(
        "Resolved",
        lifecycle.get("resolved", data.get("by_status", {}).get("RESOLVED", 0)),
    )
    metric_cols[3].metric(
        "Average resolution time",
        format_duration(lifecycle.get("average_resolution_seconds")),
    )

    st.subheader("Findings by severity")

    severity_status = data.get("by_severity_and_status", {})
    severity_rows = []

    for severity in ["CRITICAL", "HIGH", "WARNING", "INFO"]:
        counts = severity_status.get(severity, {})

        severity_rows.append({
            "Severity": severity,
            "Active": counts.get("ACTIVE", 0),
            "Resolved": counts.get("RESOLVED", 0),
        })

    severity_df = pd.DataFrame(severity_rows)

    if severity_df[["Active", "Resolved"]].to_numpy().sum():
        st.bar_chart(
            severity_df.set_index("Severity"),
            use_container_width=True,
        )
    else:
        st.info("No findings have been recorded.")

    st.subheader("Findings by detection rule")

    by_rule = data.get("by_rule", [])

    if by_rule:
        rule_df = pd.DataFrame(by_rule).rename(columns={
            "rule_id": "Rule",
            "count": "Total",
            "active": "Active",
            "resolved": "Resolved",
        })
        st.dataframe(rule_df, use_container_width=True, hide_index=True)
    else:
        st.info("No rule-based findings available.")

    st.subheader("Findings by host")

    by_host = data.get("by_host", [])

    if by_host:
        host_df = pd.DataFrame(by_host).rename(columns={
            "host": "Host",
            "count": "Total",
            "active": "Active",
            "resolved": "Resolved",
        })
        st.dataframe(host_df, use_container_width=True, hide_index=True)
    else:
        st.info("No host-based findings available.")

    st.subheader("Lifecycle details")

    lifecycle_details = {
        "Findings with resolution timestamps": lifecycle.get(
            "with_resolved_at", 0
        ),
        "Oldest finding": lifecycle.get("oldest_first_seen") or "N/A",
        "Most recently seen": lifecycle.get("newest_last_seen") or "N/A",
    }

    st.dataframe(
        pd.DataFrame(
            [
                {"Metric": key, "Value": value}
                for key, value in lifecycle_details.items()
            ]
        ),
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Recent findings")

    recent = data.get("recent_findings", [])

    if recent:
        recent_df = pd.DataFrame(recent).rename(columns={
            "id": "ID",
            "rule_id": "Rule",
            "severity": "Severity",
            "host": "Host",
            "evidence": "Evidence",
            "first_seen": "First seen",
            "last_seen": "Last seen",
            "status": "Status",
            "resolved_at": "Resolved at",
        })
        st.dataframe(
            recent_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recent findings.")


def render_agent_result(name, content):
    """Render known MCP results structurally; preserve a text fallback."""

    parsed = parse_json_result(content)

    if name == "get_findings_summary" and isinstance(parsed, dict):
        render_findings_summary(parsed)
        return

    if parsed is not None:
        st.json(parsed)
    else:
        st.code(str(content), language="text")



def display_agent_history():
    """Render canonical agent history in the chat interface."""

    for message in st.session_state.agent_history:
        role = message.get("role")

        if role == "user":
            with st.chat_message("user"):
                st.markdown(message.get("content", ""))

        elif role == "assistant":
            with st.chat_message("assistant"):
                display_type = message.get("display_type")

                if display_type == "findings_summary":
                    render_findings_summary(
                        message.get("display_data", {})
                    )

                elif display_type == "direct_tool_result":
                    st.caption(
                        f"Direct MCP query: "
                        f"{message.get('tool_name') or 'Unknown'}"
                    )
                    st.json(message.get("display_data"))

                else:
                    st.markdown(message.get("content", ""))

        elif role == "assistant_tool_calls":
            content = message.get("content")

            if content:
                with st.chat_message("assistant"):
                    st.markdown(content)

            for call in message.get("tool_calls", []):
                with st.expander(
                    f"Proposed MCP tool: {call.get('name', 'Unknown')}"
                ):
                    st.code(
                        json.dumps(
                            call.get("arguments", {}),
                            indent=2,
                        ),
                        language="json",
                    )

        elif role == "tool_result":
            tool_name = message.get("name", "Unknown")

            with st.chat_message("assistant"):
                with st.expander(
                    f"Tool result: {tool_name}",
                    expanded=(tool_name == "get_findings_summary"),
                ):
                    render_agent_result(
                        tool_name,
                        message.get(
                            "display_content",
                            message.get("content", ""),
                        ),
                    )


def render_ai_assistant():
    """Render the independent AI Assistant view."""

    st.title("AI Assistant")
    st.caption(
        "MCP-backed security assessment assistant"
    )

    status_col, provider_col, action_col = st.columns(3)

    status_col.metric(
        "Agent status",
        st.session_state.agent_status,
    )

    provider_col.metric(
        "Active provider",
        st.session_state.agent_provider or "Not selected",
    )

    action_col.metric(
        "Pending tool approvals",
        len(st.session_state.pending_tool_calls),
    )

    st.divider()

    # ------------------------------------------------------
    # Conversation
    # ------------------------------------------------------

    st.subheader("Conversation")

    display_agent_history()

    # ------------------------------------------------------
    # Pending tool approval
    # ------------------------------------------------------

    pending_calls = st.session_state.pending_tool_calls

    if pending_calls:
        st.divider()
        st.subheader("Tool approval required")

        call = pending_calls[0]

        st.warning(
            "The agent has proposed an MCP operation. "
            "Review its arguments before approving."
        )

        st.write(f"**Tool:** `{call.get('name', 'Unknown')}`")

        st.write("**Arguments:**")

        st.code(
            json.dumps(
                call.get("arguments", {}),
                indent=2,
            ),
            language="json",
        )

        if len(pending_calls) > 1:
            st.caption(
                f"{len(pending_calls)} tool calls are awaiting approval. "
                "Each call must be reviewed individually."
            )

        approve_col, decline_col = st.columns(2)

        if approve_col.button(
            "Approve tool call",
            type="primary",
            use_container_width=True,
            key="approve_agent_tool",
        ):
            process_tool_decision("approve")
            st.rerun()

        if decline_col.button(
            "Decline tool call",
            use_container_width=True,
            key="decline_agent_tool",
        ):
            process_tool_decision("decline")
            st.rerun()

    # ------------------------------------------------------
    # Prompt input
    # ------------------------------------------------------

    st.divider()
    st.subheader("Send a message")

    if st.session_state.pending_tool_calls:
        st.info(
            "Resolve the pending tool approval before sending "
            "another message."
        )

    with st.form("agent_prompt_form", clear_on_submit=True):

        prompt = st.text_area(
            "Message",
            height=130,
            placeholder=(
                "Ask the agent to analyze findings, inspect hosts, "
                "summarize the environment, or perform an assessment."
            ),
            disabled=bool(st.session_state.pending_tool_calls),
        )

        submit_col, clear_col = st.columns(2)

        submitted = submit_col.form_submit_button(
            "Send",
            type="primary",
            use_container_width=True,
            disabled=bool(st.session_state.pending_tool_calls),
        )

        clear_requested = clear_col.form_submit_button(
            "Clear conversation",
            use_container_width=True,
        )

    if submitted and prompt.strip():
        process_agent_prompt(prompt)
        st.rerun()

    if clear_requested:
        clear_agent_conversation()
        st.rerun()

    with st.expander("Read-only commands"):
        st.markdown(
            """
            These commands execute directly through MCP without an
            LLM request:

            ```text
            /help
            /summary
            /summary 10
            /findings
            /findings --status ACTIVE --severity HIGH
            /findings --host 192.168.56.10 --limit 20
            /history
            /history 10
            /hosts
            /hosts 20
            /services
            /services --host-ip 192.168.56.10
            /detail 42
            /compare 12 15
            /compare 12 15 20
            ```
            """
        )

    st.caption(
        "Tool execution requires explicit approval. "
        "Read-only commands bypass the LLM."
    )


# ==========================================================
# DATABASE HELPERS
# ==========================================================

def read_scan_runs():
    return get_scan_runs()


def get_latest_scan():
    runs = read_scan_runs()
    return runs[0] if runs else None


def read_ad_table(table_name):
    allowed_tables = {
        "ad_domains",
        "ad_users",
        "ad_groups",
        "ad_memberships",
        "ad_membership_paths",
        "ad_password_policies",
    }

    if table_name not in allowed_tables:
        raise ValueError("Unsupported table name.")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            return pd.read_sql_query(
                f'SELECT * FROM "{table_name}"',
                conn,
            )
    except (
        sqlite3.OperationalError,
        pd.errors.DatabaseError,
    ):
        return pd.DataFrame()


def read_ad_inventory():
    return {
        "domains": read_ad_table("ad_domains"),
        "users": read_ad_table("ad_users"),
        "groups": read_ad_table("ad_groups"),
        "memberships": read_ad_table("ad_memberships"),
        "paths": read_ad_table("ad_membership_paths"),
        "policies": read_ad_table("ad_password_policies"),
    }


def display_table(dataframe, empty_message):
    if dataframe.empty:
        st.info(empty_message)
    else:
        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )


def load_finding_records():
    result = query_findings(limit=200, offset=0)

    if not isinstance(result, dict):
        return []

    return result.get("findings", [])


def format_finding_label(finding):
    return (
        f"#{finding['id']} | "
        f"{finding.get('severity', 'UNKNOWN')} | "
        f"{finding.get('rule_id', 'Unknown rule')} | "
        f"{finding.get('host', 'Unknown host')}"
    )


def format_duration(seconds):
    if seconds is None:
        return "N/A"

    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "N/A"

    if seconds < 60:
        return f"{seconds:.1f} seconds"

    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"

    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"

    return f"{seconds / 86400:.1f} days"


def display_comparison_category(category, changes):
    if not changes:
        st.caption("No findings in this category.")
        return

    for change in changes:
        finding_id = change.get("finding_id", "Unknown")
        old = change.get("old") or {}
        new = change.get("new") or {}

        with st.expander(f"Finding #{finding_id}"):

            if category == "changed":
                st.write("Changed fields:")

                fields = [
                    "rule_id",
                    "severity",
                    "host",
                    "evidence",
                    "finding_key",
                ]

                for field in fields:
                    old_value = old.get(field)
                    new_value = new.get(field)

                    if old_value != new_value:
                        st.markdown(
                            f"**{field.replace('_', ' ').title()}**"
                        )
                        st.write(f"Previous: {old_value}")
                        st.write(f"Current: {new_value}")

            elif category == "added":
                st.write("Finding added in the newer scan.")
                st.json(new)

            elif category == "removed":
                st.write("Finding absent from the newer scan.")
                st.json(old)

            elif category == "resolved":
                st.write("Finding resolved.")
                st.json(new or old)

            elif category == "reactivated":
                st.write(
                    "Previously resolved finding is active again."
                )
                st.json(new)

            else:
                st.json(new or old)


# ==========================================================
# APPLICATION NAVIGATION
# ==========================================================

header_col, dashboard_col, assistant_col = st.columns(
    [5, 1.5, 1.5]
)

with header_col:
    st.title("Red Team Agent")

with dashboard_col:
    st.write("")
    if st.button(
        "Dashboard",
        type=(
            "primary"
            if st.session_state.active_view == "dashboard"
            else "secondary"
        ),
        use_container_width=True,
        key="open_dashboard",
    ):
        set_view("dashboard")
        st.rerun()

with assistant_col:
    st.write("")
    if st.button(
        "AI Assistant",
        type=(
            "primary"
            if st.session_state.active_view == "assistant"
            else "secondary"
        ),
        use_container_width=True,
        key="open_ai_assistant",
    ):
        set_view("assistant")
        st.rerun()


# ==========================================================
# AI ASSISTANT VIEW
# ==========================================================

if st.session_state.active_view == "assistant":

    render_ai_assistant()

    st.stop()


# ==========================================================
# DASHBOARD VIEW
# ==========================================================

st.caption("Security assessment and automated reasoning platform")

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
finding_summary = get_findings_summary()

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
    help=(
        "Used for LDAPS enumeration. "
        "It is not written to the database."
    ),
)

c1, c2, c3, c4 = st.columns(4)

full_scan_clicked = c1.button(
    "Run full scan",
    type="primary",
    use_container_width=True,
)

discovery_clicked = c2.button(
    "Discover hosts",
    use_container_width=True,
)

service_clicked = c3.button(
    "Enumerate services",
    use_container_width=True,
)

ldap_clicked = c4.button(
    "Enumerate AD",
    use_container_width=True,
)


# ==========================================================
# EXECUTE SELECTED SCAN ACTION
# ==========================================================

if full_scan_clicked or ldap_clicked:
    if not ldap_password:
        st.error("Enter the LDAP password first.")
        st.stop()


if any([
    full_scan_clicked,
    discovery_clicked,
    service_clicked,
    ldap_clicked,
]):
    st.session_state.activity = []

    console = st.empty()

    def dashboard_log(message):
        log_event(message)

        console.code(
            "\n".join(st.session_state.activity[-25:]),
            language="text",
        )

    try:
        with st.spinner("Operation running..."):

            if full_scan_clicked:
                dashboard_log("Starting full scan...")

                result = run_full_scan(
                    ldap_password,
                    log=dashboard_log,
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
                    log=dashboard_log,
                )

                st.session_state.last_action = (
                    "Active Directory enumeration completed."
                )

        st.success(st.session_state.last_action)
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
    console_tab,
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
    "Activity",
])


# ==========================================================
# OVERVIEW TAB
# ==========================================================

with overview_tab:

    st.subheader("Finding lifecycle")

    lifecycle = finding_summary.get("lifecycle", {})

    lifecycle_col1, lifecycle_col2, lifecycle_col3, lifecycle_col4 = (
        st.columns(4)
    )

    lifecycle_col1.metric(
        "Total findings",
        lifecycle.get(
            "total",
            finding_summary.get("total_findings", 0),
        ),
    )

    lifecycle_col2.metric(
        "Active",
        lifecycle.get("active", 0),
    )

    lifecycle_col3.metric(
        "Resolved",
        lifecycle.get("resolved", 0),
    )

    lifecycle_col4.metric(
        "Average resolution time",
        format_duration(
            lifecycle.get("average_resolution_seconds")
        ),
    )

    st.subheader("Active findings by severity")

    severity_status = finding_summary.get(
        "by_severity_and_status",
        {},
    )

    severity_rows = []

    for severity in ["CRITICAL", "HIGH", "WARNING", "INFO"]:
        status_counts = severity_status.get(severity, {})

        severity_rows.append({
            "Severity": severity,
            "Active": status_counts.get("ACTIVE", 0),
            "Resolved": status_counts.get("RESOLVED", 0),
        })

    severity_df = pd.DataFrame(severity_rows)

    if severity_df[["Active", "Resolved"]].to_numpy().sum() > 0:
        st.bar_chart(
            severity_df.set_index("Severity"),
            use_container_width=True,
        )
    else:
        st.info("No findings have been recorded.")

    st.subheader("Findings by detection rule")

    by_rule = finding_summary.get("by_rule", [])

    if by_rule:
        rule_df = pd.DataFrame(by_rule)

        rule_df = rule_df.rename(columns={
            "rule_id": "Rule",
            "count": "Total",
            "active": "Active",
            "resolved": "Resolved",
        })

        st.dataframe(
            rule_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No rule-based findings available.")

    st.subheader("Findings by host")

    by_host = finding_summary.get("by_host", [])

    if by_host:
        host_finding_df = pd.DataFrame(by_host)

        host_finding_df = host_finding_df.rename(columns={
            "host": "Host",
            "count": "Total",
            "active": "Active",
            "resolved": "Resolved",
        })

        st.dataframe(
            host_finding_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No host-based findings available.")

    st.subheader("AD inventory summary")

    ad_col1, ad_col2, ad_col3, ad_col4 = st.columns(4)

    ad_col1.metric("Domains", len(ad["domains"]))
    ad_col2.metric("AD users", len(ad["users"]))
    ad_col3.metric("AD groups", len(ad["groups"]))
    ad_col4.metric("Memberships", len(ad["memberships"]))

    st.subheader("Privilege analysis summary")

    privilege_col1, privilege_col2 = st.columns(2)

    privilege_col1.metric(
        "AD groups collected",
        len(ad["groups"]),
    )

    privilege_col2.metric(
        "Derived membership paths",
        len(ad["paths"]),
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
                    "Last seen",
                ],
            ),
            use_container_width=True,
            hide_index=True,
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
                                "Version",
                            ],
                        ),
                        use_container_width=True,
                        hide_index=True,
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
                "Version",
            ],
        )

        selected_host = st.selectbox(
            "Filter by host",
            ["All hosts"] + sorted(
                service_df["Host"].unique().tolist()
            ),
        )

        if selected_host != "All hosts":
            service_df = service_df[
                service_df["Host"] == selected_host
            ]

        st.dataframe(
            service_df,
            use_container_width=True,
            hide_index=True,
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
        "No domain information collected yet.",
    )

    st.write("Domain password policy")

    display_table(
        ad["policies"],
        "No password policy information collected yet.",
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
            key="ad_user_search",
        )

        if search:
            mask = user_df.astype(str).apply(
                lambda column: column.str.contains(
                    search,
                    case=False,
                    na=False,
                )
            ).any(axis=1)

            user_df = user_df[mask]

        st.dataframe(
            user_df,
            use_container_width=True,
            hide_index=True,
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
                    "Last seen",
                ],
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No legacy LDAP users available.")


# ==========================================================
# AD GROUPS TAB
# ==========================================================

with groups_tab:

    st.subheader("Active Directory groups")

    if not ad["groups"].empty:

        group_df = ad["groups"].copy()

        group_search = st.text_input(
            "Search groups",
            key="ad_group_search",
        )

        if group_search:
            mask = group_df.astype(str).apply(
                lambda column: column.str.contains(
                    group_search,
                    case=False,
                    na=False,
                )
            ).any(axis=1)

            group_df = group_df[mask]

        st.dataframe(
            group_df,
            use_container_width=True,
            hide_index=True,
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
                ["All"] + membership_types,
            )

            if selected_type != "All":
                membership_df = membership_df[
                    membership_df["membership_type"]
                    == selected_type
                ]

        st.dataframe(
            membership_df,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info(
            "No membership relationships collected yet."
        )


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
            len(path_df),
        )

        st.dataframe(
            path_df,
            use_container_width=True,
            hide_index=True,
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
                "Resolved at",
            ],
        )

        st.dataframe(
            privilege_findings_df,
            use_container_width=True,
            hide_index=True,
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
        ["ACTIVE", "RESOLVED", "ALL"],
        key="finding_status_filter",
    )

    severity_filter = st.selectbox(
        "Severity",
        ["ALL", "CRITICAL", "HIGH", "WARNING", "INFO"],
        key="finding_severity_filter",
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
                "Resolved at",
            ],
        )

        st.dataframe(
            finding_df,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No findings match these filters.")

    st.divider()

    st.subheader("Finding details and history")

    try:
        finding_records = load_finding_records()
    except Exception as error:
        finding_records = []
        st.error(f"Could not load finding records: {error}")

    if finding_records:

        selected_finding = st.selectbox(
            "Select a finding",
            finding_records,
            format_func=format_finding_label,
            key="finding_detail_selector",
        )

        if selected_finding:
            try:
                details = get_finding_details(
                    int(selected_finding["id"])
                )

                finding_detail = details.get("finding")

                if finding_detail:
                    st.markdown(
                        f"**Finding #{finding_detail['id']}**"
                    )

                    detail_col1, detail_col2, detail_col3 = (
                        st.columns(3)
                    )

                    detail_col1.metric(
                        "Severity",
                        finding_detail.get("severity", "N/A"),
                    )

                    detail_col2.metric(
                        "Status",
                        finding_detail.get("status", "N/A"),
                    )

                    detail_col3.metric(
                        "Last seen run",
                        finding_detail.get("last_seen_run_id") or "N/A",
                    )

                    st.write(
                        f"**Rule:** "
                        f"{finding_detail.get('rule_id', 'N/A')}"
                    )

                    st.write(
                        f"**Host:** "
                        f"{finding_detail.get('host', 'N/A')}"
                    )

                    st.write(
                        f"**First seen:** "
                        f"{finding_detail.get('first_seen', 'N/A')}"
                    )

                    st.write(
                        f"**Last seen:** "
                        f"{finding_detail.get('last_seen', 'N/A')}"
                    )

                    st.write(
                        f"**Resolved at:** "
                        f"{finding_detail.get('resolved_at') or 'Not resolved'}"
                    )

                    st.write("**Evidence**")

                    st.code(
                        finding_detail.get("evidence")
                        or "No evidence recorded.",
                        language="text",
                    )

                    with st.expander("Finding identity"):
                        st.code(
                            finding_detail.get("finding_key") or "N/A",
                            language="text",
                        )

                history = details.get("history", [])

                st.markdown(
                    "**Scan history for this finding**"
                )

                if history:
                    history_df = pd.DataFrame(history)

                    history_df = history_df.rename(columns={
                        "run_id": "Run ID",
                        "started_at": "Scan started",
                        "completed_at": "Scan completed",
                        "severity": "Severity",
                        "evidence": "Evidence",
                        "status": "Status",
                        "resolved_at": "Resolved at",
                    })

                    st.dataframe(
                        history_df,
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info(
                        "No snapshot history is available for this finding. "
                        "It may predate snapshot support."
                    )

            except Exception as error:
                st.error(
                    f"Could not load finding details: {error}"
                )

    else:
        st.info(
            "No findings are available for detailed inspection."
        )


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
                "Error",
            ],
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No scan history available.")

    st.divider()

    st.subheader("Compare scan runs")

    completed_runs = [
        run for run in runs
        if run[3] == "COMPLETED"
    ]

    completed_runs = sorted(
        completed_runs,
        key=lambda run: run[0],
    )

    if len(completed_runs) < 2:
        st.info(
            "At least two completed scans are required for comparison."
        )

    else:
        run_options = {
            run[0]: run
            for run in completed_runs
        }

        run_ids = list(run_options.keys())

        older_default = run_ids[-2]
        newer_default = run_ids[-1]

        compare_col1, compare_col2 = st.columns(2)

        older_run_id = compare_col1.selectbox(
            "Older scan",
            run_ids,
            index=run_ids.index(older_default),
            format_func=lambda run_id: (
                f"Run #{run_id} — "
                f"{run_options[run_id][1]}"
            ),
            key="compare_older_run",
        )

        newer_run_id = compare_col2.selectbox(
            "Newer scan",
            run_ids,
            index=run_ids.index(newer_default),
            format_func=lambda run_id: (
                f"Run #{run_id} — "
                f"{run_options[run_id][1]}"
            ),
            key="compare_newer_run",
        )

        comparison_limit = st.number_input(
            "Maximum findings per category",
            min_value=1,
            max_value=100,
            value=50,
            step=1,
        )

        if older_run_id >= newer_run_id:
            st.warning(
                "Select an older scan with a lower run ID "
                "than the newer scan."
            )

        else:
            try:
                comparison = compare_scan_runs(
                    older_run_id=int(older_run_id),
                    newer_run_id=int(newer_run_id),
                    limit=int(comparison_limit),
                )

                if not comparison.get("available", False):
                    st.warning(
                        comparison.get(
                            "reason",
                            "Comparison is unavailable.",
                        )
                    )

                else:
                    st.markdown(
                        f"Comparing scan #{older_run_id} "
                        f"against scan #{newer_run_id}"
                    )

                    counts = comparison.get("counts", {})
                    changes = comparison.get("changes", {})

                    st.markdown("**Comparison summary**")

                    categories = [
                        "added",
                        "removed",
                        "resolved",
                        "reactivated",
                        "changed",
                        "unchanged",
                    ]

                    for row_start in range(0, len(categories), 3):
                        metric_cols = st.columns(3)

                        for index, category in enumerate(
                            categories[row_start:row_start + 3]
                        ):
                            metric_cols[index].metric(
                                category.replace("_", " ").title(),
                                counts.get(category, 0),
                            )

                    st.caption(
                        "Category totals represent all matching findings. "
                        "The detail lists below are limited by the selected "
                        "maximum per category."
                    )

                    st.divider()

                    for category in categories:
                        category_changes = changes.get(category, [])

                        with st.expander(
                            f"{category.replace('_', ' ').title()} "
                            f"({counts.get(category, 0)})"
                        ):
                            display_comparison_category(
                                category,
                                category_changes,
                            )

            except Exception as error:
                st.error(
                    f"Scan comparison failed: {error}"
                )


# ==========================================================
# ACTIVITY TAB
# ==========================================================

with console_tab:

    st.subheader("Recent activity")

    if st.session_state.activity:

        st.code(
            "\n".join(st.session_state.activity[-100:]),
            language="text",
        )

    else:
        st.info("No activity in this dashboard session.")


# ==========================================================
# FOOTER
# ==========================================================

st.divider()

if st.button("Refresh dashboard"):
    refresh_data()
