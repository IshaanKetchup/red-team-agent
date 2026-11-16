
import os
import sqlite3
import tempfile
import unittest

from unittest.mock import patch

from database.ad_queries import query_ad_users


class TestADUserQueries(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")

        self.db_patch = patch(
            "database.ad_queries.DB_PATH",
            self.db_path,
        )
        self.db_patch.start()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE ad_users (
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

            users = [
                (
                    "CN=alice,CN=Users,DC=lab,DC=local",
                    "DC=lab,DC=local",
                    "alice",
                    "Alice Smith",
                    "alice@lab.local",
                    "alice@lab.local",
                    "Administrator account",
                    512,
                    1,
                    "S-1-5-21-100-200-300-1001",
                    513,
                    None,
                    None,
                    None,
                    1,
                    '["HTTP/server.lab.local"]',
                ),
                (
                    "CN=bob,CN=Users,DC=lab,DC=local",
                    "DC=lab,DC=local",
                    "bob",
                    "Bob Jones",
                    "bob@lab.local",
                    "bob@lab.local",
                    "Standard user",
                    514,
                    0,
                    "S-1-5-21-100-200-300-1002",
                    513,
                    None,
                    None,
                    None,
                    0,
                    "[]",
                ),
                (
                    "CN=charlie,CN=Users,DC=lab,DC=local",
                    "DC=lab,DC=local",
                    "charlie",
                    "Charlie Brown",
                    "charlie@lab.local",
                    "charlie@lab.local",
                    "Helpdesk account",
                    512,
                    1,
                    "S-1-5-21-100-200-300-1003",
                    513,
                    None,
                    None,
                    None,
                    0,
                    "[]",
                ),
            ]

            conn.executemany("""
                INSERT INTO ad_users (
                    dn, domain_dn, sam_account_name,
                    display_name, user_principal_name, mail,
                    description, user_account_control, enabled,
                    object_sid, primary_group_id, pwd_last_set,
                    last_logon_timestamp, when_created, admin_count,
                    service_principal_names
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, users)

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_returns_all_users(self):
        result = query_ad_users()

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["returned"], 3)
        self.assertEqual(len(result["users"]), 3)

    def test_searches_username(self):
        result = query_ad_users(search="alice")

        self.assertEqual(result["total"], 1)
        self.assertEqual(
            result["users"][0]["sam_account_name"],
            "alice",
        )

    def test_searches_display_name(self):
        result = query_ad_users(search="Bob Jones")

        self.assertEqual(result["total"], 1)
        self.assertEqual(
            result["users"][0]["sam_account_name"],
            "bob",
        )

    def test_searches_email(self):
        result = query_ad_users(search="charlie@lab.local")

        self.assertEqual(result["total"], 1)
        self.assertEqual(
            result["users"][0]["sam_account_name"],
            "charlie",
        )

    def test_filters_enabled_users(self):
        result = query_ad_users(enabled=True)

        self.assertEqual(result["total"], 2)
        self.assertTrue(
            all(user["enabled"] for user in result["users"])
        )

    def test_filters_disabled_users(self):
        result = query_ad_users(enabled=False)

        self.assertEqual(result["total"], 1)
        self.assertEqual(
            result["users"][0]["sam_account_name"],
            "bob",
        )

    def test_pagination(self):
        result = query_ad_users(limit=2, offset=1)

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["returned"], 2)
        self.assertTrue(result["has_more"] is False)

    def test_has_more_pages(self):
        result = query_ad_users(limit=1, offset=0)

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["returned"], 1)
        self.assertTrue(result["has_more"])

    def test_service_principal_names_are_decoded(self):
        result = query_ad_users(search="alice")

        self.assertEqual(
            result["users"][0]["service_principal_names"],
            ["HTTP/server.lab.local"],
        )

    def test_rejects_invalid_limit(self):
        with self.assertRaises(ValueError):
            query_ad_users(limit=101)

    def test_rejects_negative_offset(self):
        with self.assertRaises(ValueError):
            query_ad_users(offset=-1)

    def test_rejects_invalid_enabled_filter(self):
        with self.assertRaises(ValueError):
            query_ad_users(enabled="yes")

    def test_rejects_excessive_search_length(self):
        with self.assertRaises(ValueError):
            query_ad_users(search="a" * 257)


class TestADRelationshipQueries(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "relationships.db")

        self.db_patch = patch(
            "database.ad_queries.DB_PATH",
            self.db_path,
        )
        self.db_patch.start()

        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE ad_users (
                    dn TEXT PRIMARY KEY,
                    domain_dn TEXT NOT NULL,
                    sam_account_name TEXT,
                    display_name TEXT,
                    user_principal_name TEXT,
                    enabled INTEGER,
                    object_sid TEXT
                );

                CREATE TABLE ad_groups (
                    dn TEXT PRIMARY KEY,
                    domain_dn TEXT NOT NULL,
                    name TEXT,
                    cn TEXT,
                    sam_account_name TEXT,
                    description TEXT,
                    group_type INTEGER,
                    object_sid TEXT
                );

                CREATE TABLE ad_memberships (
                    group_dn TEXT NOT NULL,
                    member_dn TEXT NOT NULL,
                    membership_type TEXT NOT NULL
                );

                CREATE TABLE ad_membership_paths (
                    domain_dn TEXT NOT NULL,
                    source_dn TEXT NOT NULL,
                    target_group_dn TEXT NOT NULL,
                    depth INTEGER NOT NULL,
                    path_json TEXT NOT NULL
                );
            """)

            domain = "DC=lab,DC=local"
            alice = f"CN=alice,CN=Users,{domain}"
            helpdesk = f"CN=Helpdesk,CN=Users,{domain}"
            it_admins = f"CN=IT Admins,CN=Users,{domain}"
            domain_admins = f"CN=Domain Admins,CN=Users,{domain}"

            conn.execute("""
                INSERT INTO ad_users (
                    dn, domain_dn, sam_account_name,
                    display_name, user_principal_name, enabled
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alice, domain, "alice", "Alice Smith",
                "alice@lab.local", 1,
            ))

            groups = [
                (helpdesk, domain, "Helpdesk", "Helpdesk", "Helpdesk"),
                (it_admins, domain, "IT Admins", "IT Admins", "IT-Admins"),
                (
                    domain_admins, domain, "Domain Admins",
                    "Domain Admins", "Domain Admins",
                ),
            ]

            conn.executemany("""
                INSERT INTO ad_groups (
                    dn, domain_dn, name, cn, sam_account_name
                ) VALUES (?, ?, ?, ?, ?)
            """, groups)

            conn.execute("""
                INSERT INTO ad_memberships (
                    group_dn, member_dn, membership_type
                ) VALUES (?, ?, 'DIRECT')
            """, (helpdesk, alice))

            conn.execute("""
                INSERT INTO ad_memberships (
                    group_dn, member_dn, membership_type
                ) VALUES (?, ?, 'DIRECT')
            """, (it_admins, helpdesk))

            conn.execute("""
                INSERT INTO ad_memberships (
                    group_dn, member_dn, membership_type
                ) VALUES (?, ?, 'DIRECT')
            """, (domain_admins, it_admins))

            conn.execute("""
                INSERT INTO ad_membership_paths (
                    domain_dn, source_dn, target_group_dn,
                    depth, path_json
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                domain, alice, it_admins, 2,
                __import__("json").dumps([alice, helpdesk, it_admins]),
            ))

            conn.execute("""
                INSERT INTO ad_membership_paths (
                    domain_dn, source_dn, target_group_dn,
                    depth, path_json
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                domain, alice, domain_admins, 3,
                __import__("json").dumps(
                    [alice, helpdesk, it_admins, domain_admins]
                ),
            ))

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_searches_groups(self):
        from database.ad_queries import query_ad_groups

        result = query_ad_groups(search="Domain")

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["groups"][0]["name"], "Domain Admins")

    def test_rejects_ambiguous_group(self):
        from database.ad_queries import query_ad_group_members

        with self.assertRaisesRegex(ValueError, "not found"):
            query_ad_group_members("Missing Group")

    def test_group_members_include_direct_and_nested_users(self):
        from database.ad_queries import query_ad_group_members

        result = query_ad_group_members("Domain Admins")

        self.assertEqual(result["total"], 2)
        alice = next(
            member for member in result["members"]
            if member["sam_account_name"] == "alice"
        )
        self.assertEqual(alice["membership_kind"], "NESTED")
        self.assertEqual(alice["membership_depth"], 3)

    def test_group_members_can_exclude_nested_users(self):
        from database.ad_queries import query_ad_group_members

        result = query_ad_group_members(
            "Domain Admins",
            include_nested=False,
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["members"][0]["member_object_type"], "GROUP")

    def test_user_groups_include_direct_and_nested(self):
        from database.ad_queries import query_ad_user_groups

        result = query_ad_user_groups("alice")

        names = {
            group["name"]
            for group in result["groups"]
        }

        self.assertEqual(names, {"Helpdesk", "IT Admins", "Domain Admins"})

        domain_admins = next(
            group for group in result["groups"]
            if group["name"] == "Domain Admins"
        )
        self.assertEqual(domain_admins["membership_kind"], "NESTED")
        self.assertEqual(domain_admins["membership_depth"], 3)

    def test_user_groups_can_exclude_nested(self):
        from database.ad_queries import query_ad_user_groups

        result = query_ad_user_groups(
            "alice",
            include_nested=False,
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["groups"][0]["name"], "Helpdesk")
        self.assertEqual(result["groups"][0]["membership_kind"], "DIRECT")

    def test_filters_membership_paths_by_user_and_group(self):
        from database.ad_queries import query_ad_membership_paths

        result = query_ad_membership_paths(
            user="alice",
            group="Domain Admins",
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["paths"][0]["depth"], 3)
        self.assertEqual(
            len(result["paths"][0]["path"]),
            4,
        )

    def test_membership_path_pagination(self):
        from database.ad_queries import query_ad_membership_paths

        result = query_ad_membership_paths(user="alice", limit=1)

        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["total"], 2)
        self.assertTrue(result["has_more"])

    def test_rejects_invalid_nested_flag(self):
        from database.ad_queries import query_ad_user_groups

        with self.assertRaises(ValueError):
            query_ad_user_groups("alice", include_nested="yes")

    def test_rejects_invalid_pagination(self):
        from database.ad_queries import query_ad_groups

        with self.assertRaises(ValueError):
            query_ad_groups(limit=101)


if __name__ == "__main__":
    unittest.main()
