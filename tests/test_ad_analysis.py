
import sqlite3
import unittest

from engine.ad_analysis import (
    is_security_enabled,
    get_sensitive_groups,
    load_membership_graph,
    find_user_privilege_paths,
    analyze_ad_data,
)


class TestADAnalysis(unittest.TestCase):

    def setUp(self):
        """Create an isolated database for database-backed tests."""

        self.conn = sqlite3.connect(":memory:")

        self.conn.execute("""
            CREATE TABLE ad_groups (
                dn TEXT,
                name TEXT,
                object_sid TEXT,
                group_type INTEGER
            )
        """)

        self.conn.execute("""
            CREATE TABLE ad_memberships (
                member_dn TEXT,
                group_dn TEXT,
                membership_type TEXT
            )
        """)

        self.domain_sid = "S-1-5-21-111-222-333"
        self.domain_dn = "DC=lab,DC=local"

    def tearDown(self):
        self.conn.close()

    def make_ad_data(self, memberships=None):
        """Build raw AD data in the structure expected by analysis."""

        user_dn = "CN=Alice,CN=Users,DC=lab,DC=local"
        helpdesk_dn = "CN=Helpdesk,CN=Users,DC=lab,DC=local"
        admins_dn = "CN=Domain Admins,CN=Users,DC=lab,DC=local"

        groups = [
            {
                "dn": admins_dn,
                "name": "Domain Admins",
                "cn": "Domain Admins",
                "objectSid": self.domain_sid + "-512",
                "groupType": -2147483646,
            },
            {
                "dn": helpdesk_dn,
                "name": "Helpdesk",
                "cn": "Helpdesk",
                "objectSid": self.domain_sid + "-1001",
                "groupType": -2147483646,
            },
        ]

        if memberships is None:
            memberships = [
                {
                    "member_dn": user_dn,
                    "group_dn": admins_dn,
                    "membership_type": "DIRECT",
                }
            ]

        return {
            "domain": {
                "dn": self.domain_dn,
                "objectSid": self.domain_sid,
            },
            "users": [
                {
                    "dn": user_dn,
                    "sAMAccountName": "alice",
                }
            ],
            "groups": groups,
            "memberships": memberships,
        }

    def test_security_enabled_group(self):
        self.assertTrue(is_security_enabled(-2147483646))

    def test_distribution_group_is_not_security_enabled(self):
        self.assertFalse(is_security_enabled(2))

    def test_invalid_group_type_is_rejected(self):
        self.assertFalse(is_security_enabled("invalid"))
        self.assertFalse(is_security_enabled(None))

    def test_sensitive_groups_are_identified_by_sid(self):
        self.conn.executemany(
            """
            INSERT INTO ad_groups
            (dn, name, object_sid, group_type)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    "CN=Domain Admins,DC=lab,DC=local",
                    "Renamed Admin Group",
                    self.domain_sid + "-512",
                    -2147483646,
                ),
                (
                    "CN=Administrators,CN=Builtin,DC=lab,DC=local",
                    "Administrators",
                    "S-1-5-32-544",
                    -2147483646,
                ),
                (
                    "CN=Distribution Group,DC=lab,DC=local",
                    "Distribution Group",
                    self.domain_sid + "-600",
                    2,
                ),
            ],
        )

        groups = get_sensitive_groups(self.conn, self.domain_sid)

        self.assertEqual(len(groups), 2)

        domain_admins = groups[
            "CN=Domain Admins,DC=lab,DC=local"
        ]

        self.assertEqual(domain_admins["name"], "Domain Admins")
        self.assertEqual(domain_admins["category"], "DOMAIN_ADMIN")

        self.assertNotIn(
            "CN=Distribution Group,DC=lab,DC=local",
            groups,
        )

    def test_membership_graph_includes_primary_memberships(self):
        self.conn.executemany(
            """
            INSERT INTO ad_memberships
            (member_dn, group_dn, membership_type)
            VALUES (?, ?, ?)
            """,
            [
                ("alice", "Helpdesk", "DIRECT"),
                ("bob", "Domain Users", "PRIMARY"),
            ],
        )

        graph = load_membership_graph(self.conn)

        self.assertEqual(graph["alice"], [("Helpdesk", "DIRECT")])
        self.assertEqual(graph["bob"], [("Domain Users", "PRIMARY")])

    def test_direct_privilege_path(self):
        users = [
            {
                "dn": "alice",
                "sam_account_name": "alice",
            }
        ]

        graph = {
            "alice": [("Domain Admins", "DIRECT")]
        }

        sensitive_groups = {
            "Domain Admins": {
                "dn": "Domain Admins",
                "name": "Domain Admins",
                "category": "DOMAIN_ADMIN",
            }
        }

        paths = find_user_privilege_paths(
            users,
            graph,
            sensitive_groups,
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["relationship"], "DIRECT")
        self.assertEqual(paths[0]["depth"], 1)
        self.assertEqual(paths[0]["category"], "DOMAIN_ADMIN")

    def test_nested_privilege_path(self):
        users = [
            {
                "dn": "alice",
                "sam_account_name": "alice",
            }
        ]

        graph = {
            "alice": [("Helpdesk", "DIRECT")],
            "Helpdesk": [("Domain Admins", "DIRECT")],
        }

        sensitive_groups = {
            "Domain Admins": {
                "dn": "Domain Admins",
                "name": "Domain Admins",
                "category": "DOMAIN_ADMIN",
            }
        }

        paths = find_user_privilege_paths(
            users,
            graph,
            sensitive_groups,
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["relationship"], "NESTED")
        self.assertEqual(paths[0]["depth"], 2)
        self.assertEqual(
            paths[0]["path"],
            ["alice", "Helpdesk", "Domain Admins"],
        )

    def test_membership_cycle_does_not_cause_infinite_traversal(self):
        users = [
            {
                "dn": "alice",
                "sam_account_name": "alice",
            }
        ]

        graph = {
            "alice": [("Group A", "DIRECT")],
            "Group A": [("Domain Admins", "DIRECT")],
            "Domain Admins": [("Group A", "DIRECT")],
        }

        sensitive_groups = {
            "Domain Admins": {
                "dn": "Domain Admins",
                "name": "Domain Admins",
                "category": "DOMAIN_ADMIN",
            }
        }

        paths = find_user_privilege_paths(
            users,
            graph,
            sensitive_groups,
        )

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["target_group"], "Domain Admins")

    def test_analyze_ad_data_detects_direct_privilege_path(self):
        data = self.make_ad_data()

        result = analyze_ad_data(data)

        self.assertEqual(result["domain_dn"], self.domain_dn)
        self.assertEqual(len(result["sensitive_groups"]), 1)
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["relationship"], "DIRECT")
        self.assertEqual(result["paths"][0]["category"], "DOMAIN_ADMIN")

    def test_analyze_ad_data_detects_nested_privilege_path(self):
        data = self.make_ad_data()
        user_dn = data["users"][0]["dn"]
        helpdesk_dn = data["groups"][1]["dn"]
        admins_dn = data["groups"][0]["dn"]

        data["memberships"] = [
            {
                "member_dn": user_dn,
                "group_dn": helpdesk_dn,
                "membership_type": "DIRECT",
            },
            {
                "member_dn": helpdesk_dn,
                "group_dn": admins_dn,
                "membership_type": "DIRECT",
            },
        ]

        result = analyze_ad_data(data)

        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(result["paths"][0]["relationship"], "NESTED")
        self.assertEqual(result["paths"][0]["depth"], 2)

    def test_analyze_ad_data_handles_membership_cycles(self):
        data = self.make_ad_data()
        user_dn = data["users"][0]["dn"]
        helpdesk_dn = data["groups"][1]["dn"]
        admins_dn = data["groups"][0]["dn"]

        data["memberships"] = [
            {
                "member_dn": user_dn,
                "group_dn": helpdesk_dn,
                "membership_type": "DIRECT",
            },
            {
                "member_dn": helpdesk_dn,
                "group_dn": admins_dn,
                "membership_type": "DIRECT",
            },
            {
                "member_dn": admins_dn,
                "group_dn": helpdesk_dn,
                "membership_type": "DIRECT",
            },
        ]

        result = analyze_ad_data(data)

        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(
            result["paths"][0]["target_group"],
            "Domain Admins",
        )

    def test_analyze_ad_data_rejects_missing_domain_sid(self):
        data = self.make_ad_data()
        data["domain"].pop("objectSid")

        with self.assertRaises((ValueError, KeyError)):
            analyze_ad_data(data)

    def test_analyze_ad_data_rejects_malformed_input(self):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            analyze_ad_data({"domain": {}, "users": [], "groups": []})


if __name__ == "__main__":
    unittest.main()
