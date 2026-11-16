import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from llm.agent import (
    READ_ONLY_COMMANDS,
    build_read_command,
    handle_local_command,
    parse_command_arguments,
)


class TestCommandParsing(unittest.TestCase):

    def test_parse_valid_options(self):
        result = parse_command_arguments(
            [
                "--status", "ACTIVE",
                "--severity", "HIGH",
                "--limit", "20",
                "--offset", "5",
            ],
            {"status", "severity", "limit", "offset"},
        )

        self.assertEqual(result, {
            "status": "ACTIVE",
            "severity": "HIGH",
            "limit": 20,
            "offset": 5,
        })

    def test_reject_unknown_option(self):
        with self.assertRaisesRegex(ValueError, "Unknown option"):
            parse_command_arguments(
                ["--unknown", "value"],
                {"status"},
            )

    def test_reject_duplicate_option(self):
        with self.assertRaisesRegex(ValueError, "Duplicate option"):
            parse_command_arguments(
                ["--status", "ACTIVE", "--status", "RESOLVED"],
                {"status"},
            )

    def test_reject_missing_value(self):
        with self.assertRaisesRegex(ValueError, "Missing value"):
            parse_command_arguments(
                ["--status"],
                {"status"},
            )

    def test_reject_option_without_value(self):
        with self.assertRaisesRegex(ValueError, "Missing value"):
            parse_command_arguments(
                ["--status", "--severity", "HIGH"],
                {"status", "severity"},
            )

    def test_reject_non_integer_limit(self):
        with self.assertRaisesRegex(ValueError, "must be an integer"):
            parse_command_arguments(
                ["--limit", "many"],
                {"limit"},
            )

    def test_build_summary_command(self):
        self.assertEqual(
            build_read_command("/summary", ["15"]),
            {"recent_limit": 15},
        )

    def test_build_history_command(self):
        self.assertEqual(
            build_read_command("/history", ["8"]),
            {"limit": 8},
        )

    def test_build_findings_command(self):
        self.assertEqual(
            build_read_command(
                "/findings",
                ["--status", "ACTIVE", "--limit", "25"],
            ),
            {"status": "ACTIVE", "limit": 25},
        )

    def test_reject_extra_positional_arguments(self):
        with self.assertRaisesRegex(ValueError, "Too many arguments"):
            build_read_command("/history", ["5", "10"])

    def test_only_explicit_read_commands_are_whitelisted(self):
        self.assertEqual(set(READ_ONLY_COMMANDS), {
            "/summary",
            "/findings",
            "/history",
            "/hosts",
            "/services",
            "/detail",
            "/compare",
            "/ad-groups",
            "/ad-group-members",
            "/ad-user-groups",
            "/ad-paths",
        })
    def test_build_detail_command(self):
        self.assertEqual(
            build_read_command("/detail", ["42"]),
            {"finding_id": 42},
        )

    def test_build_compare_command(self):
        self.assertEqual(
            build_read_command("/compare", ["12", "15"]),
            {
                "older_run_id": 12,
                "newer_run_id": 15,
                "limit": 50,
            },
        )

    def test_build_compare_command_with_limit(self):
        self.assertEqual(
            build_read_command("/compare", ["12", "15", "20"]),
            {
                "older_run_id": 12,
                "newer_run_id": 15,
                "limit": 20,
            },
        )

    def test_detail_rejects_invalid_id(self):
        with self.assertRaisesRegex(ValueError, "integer"):
            build_read_command("/detail", ["abc"])

    def test_compare_rejects_identical_ids(self):
        with self.assertRaisesRegex(ValueError, "different"):
            build_read_command("/compare", ["12", "12"])

    def test_compare_rejects_invalid_limit(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 100"):
            build_read_command("/compare", ["12", "15", "200"])

class TestReadOnlyCommandRouting(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.session = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=SimpleNamespace(
                    content=[SimpleNamespace(text='{"ok": true}')],
                    isError=False,
                )
            )
        )

        self.tools = {
            name: SimpleNamespace(
                inputSchema={
                    "type": "object",
                    "properties": properties,
                    "required": [],
                }
            )
            for name, properties in {
                "get_findings_summary": {
                    "recent_limit": {"type": "integer"},
                },
                "get_findings": {
                    "status": {"type": "string"},
                    "severity": {"type": "string"},
                    "host": {"type": "string"},
                    "rule_id": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
                "get_scan_history": {
                    "limit": {"type": "integer"},
                },
                "get_host_inventory": {
                    "limit": {"type": "integer"},
                },
                "get_service_inventory": {
                    "host_ip": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "get_finding_details": {
                    "finding_id": {"type": "integer"},
                },
                "compare_scan_runs": {
                    "older_run_id": {"type": "integer"},
                    "newer_run_id": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                "get_ad_groups": {
                    "search": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
                "get_ad_group_members": {
                    "group": {"type": "string"},
                    "include_nested": {"type": "boolean"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
                "get_ad_user_groups": {
                    "user": {"type": "string"},
                    "include_nested": {"type": "boolean"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
                "get_ad_membership_paths": {
                    "user": {"type": "string"},
                    "group": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },                
            }.items()
        }

    async def test_summary_routes_directly_without_approval(self):
        with patch(
            "llm.agent.approve_tool_call",
            side_effect=AssertionError("Approval must be bypassed"),
        ), patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/summary 12",
                self.tools,
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_awaited_once_with(
            "get_findings_summary",
            arguments={"recent_limit": 12},
        )

    async def test_findings_routes_with_filters(self):
        with patch(
            "llm.agent.approve_tool_call",
            side_effect=AssertionError("Approval must be bypassed"),
        ), patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/findings --status ACTIVE --limit 10",
                self.tools,
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_awaited_once_with(
            "get_findings",
            arguments={"status": "ACTIVE", "limit": 10},
        )

    async def test_invalid_command_does_not_call_mcp(self):
        with patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/findings --not-a-filter value",
                self.tools,
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_not_awaited()

    async def test_missing_mcp_tool_does_not_call_session(self):
        with patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/summary",
                {},
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_not_awaited()

    async def test_non_command_is_not_intercepted(self):
        handled = await handle_local_command(
            self.session,
            "Summarize the latest findings",
            self.tools,
        )

        self.assertFalse(handled)
        self.session.call_tool.assert_not_awaited()
    async def test_detail_routes_directly_without_approval(self):
        with patch(
            "llm.agent.approve_tool_call",
            side_effect=AssertionError("Approval must be bypassed"),
        ), patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/detail 42",
                self.tools,
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_awaited_once_with(
            "get_finding_details",
            arguments={"finding_id": 42},
        )

    async def test_compare_routes_directly_without_approval(self):
        with patch(
            "llm.agent.approve_tool_call",
            side_effect=AssertionError("Approval must be bypassed"),
        ), patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/compare 12 15",
                self.tools,
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_awaited_once_with(
            "compare_scan_runs",
            arguments={
                "older_run_id": 12,
                "newer_run_id": 15,
                "limit": 50,
            },
        )

    async def test_ad_user_groups_routes_directly_without_approval(self):
        with patch(
            "llm.agent.approve_tool_call",
            side_effect=AssertionError("Approval must be bypassed"),
        ), patch("llm.agent.print_direct_result"):
            handled = await handle_local_command(
                self.session,
                "/ad-user-groups alice",
                self.tools,
            )

        self.assertTrue(handled)
        self.session.call_tool.assert_awaited_once_with(
            "get_ad_user_groups",
            arguments={"user": "alice"},
        )


class TestADCommandParsing(unittest.TestCase):

    def test_build_ad_groups_command(self):
        self.assertEqual(
            build_read_command(
                "/ad-groups",
                ["--search", "admin", "--limit", "20"],
            ),
            {"search": "admin", "limit": 20},
        )

    def test_build_ad_group_members_command(self):
        self.assertEqual(
            build_read_command(
                "/ad-group-members",
                ["Domain Admins", "--include-nested", "false", "--limit", "10"],
            ),
            {
                "group": "Domain Admins",
                "include_nested": False,
                "limit": 10,
            },
        )

    def test_build_ad_user_groups_command(self):
        self.assertEqual(
            build_read_command("/ad-user-groups", ["alice"]),
            {"user": "alice"},
        )

    def test_build_ad_paths_command(self):
        self.assertEqual(
            build_read_command(
                "/ad-paths",
                ["--user", "alice", "--group", "Domain Admins"],
            ),
            {"user": "alice", "group": "Domain Admins"},
        )

    def test_reject_invalid_include_nested(self):
        with self.assertRaisesRegex(ValueError, "true or false"):
            build_read_command(
                "/ad-user-groups",
                ["alice", "--include-nested", "sometimes"],
            )

    def test_reject_missing_ad_group_identifier(self):
        with self.assertRaisesRegex(ValueError, "Usage"):
            build_read_command("/ad-group-members", [])

    def test_reject_unexpected_ad_group_arguments(self):
        with self.assertRaisesRegex(ValueError, "Unexpected argument"):
            build_read_command(
                "/ad-group-members",
                ["Domain", "Admins"],
            )


if __name__ == "__main__":
    unittest.main()
