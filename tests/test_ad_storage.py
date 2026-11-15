
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import database.ad_storage as ad_storage


class TestADStorage(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.db")

        self.db_patch = patch.object(
            ad_storage,
            "DB_PATH",
            self.db_path
        )
        self.db_patch.start()

        ad_storage.initialize_ad_tables()

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def make_ad_data(
        self,
        domain_dn="DC=lab,DC=local",
        users=None,
        groups=None,
        memberships=None
    ):
        return {
            "domain": {
                "dn": domain_dn,
                "name": "LAB",
                "dnsRoot": "lab.local",
                "objectSid": "S-1-5-21-100-200-300",
                "functionalLevel": 7
            },
            "users": users or [],
            "groups": groups or [],
            "memberships": memberships or [],
            "password_policy": {}
        }

    def make_user(self, name, domain_dn="DC=lab,DC=local"):
        return {
            "dn": f"CN={name},CN=Users,{domain_dn}",
            "sAMAccountName": name,
            "displayName": name,
            "enabled": True
        }

    def make_group(self, name, domain_dn="DC=lab,DC=local"):
        return {
            "dn": f"CN={name},CN=Users,{domain_dn}",
            "name": name,
            "cn": name,
            "groupType": -2147483646,
            "objectSid": f"S-1-5-21-100-200-300-{1000 + len(name)}"
        }

    def test_stale_users_are_deleted(self):
        old_user = self.make_user("olduser")
        new_user = self.make_user("newuser")

        ad_storage.save_ad_data(
            self.make_ad_data(users=[old_user])
        )

        ad_storage.save_ad_data(
            self.make_ad_data(users=[new_user])
        )

        stored_names = {
            user["sam_account_name"]
            for user in ad_storage.get_ad_users()
        }

        self.assertEqual(stored_names, {"newuser"})

    def test_stale_groups_are_deleted(self):
        old_group = self.make_group("OldGroup")
        new_group = self.make_group("NewGroup")

        ad_storage.save_ad_data(
            self.make_ad_data(groups=[old_group])
        )

        ad_storage.save_ad_data(
            self.make_ad_data(groups=[new_group])
        )

        stored_names = {
            group["name"]
            for group in ad_storage.get_ad_groups()
        }

        self.assertEqual(stored_names, {"NewGroup"})

    def test_stale_memberships_are_removed(self):
        old_user = self.make_user("olduser")
        new_user = self.make_user("newuser")

        old_group = self.make_group("OldGroup")
        new_group = self.make_group("NewGroup")

        ad_storage.save_ad_data(
            self.make_ad_data(
                users=[old_user],
                groups=[old_group],
                memberships=[{
                    "member_dn": old_user["dn"],
                    "group_dn": old_group["dn"],
                    "membership_type": "DIRECT"
                }]
            )
        )

        ad_storage.save_ad_data(
            self.make_ad_data(
                users=[new_user],
                groups=[new_group],
                memberships=[{
                    "member_dn": new_user["dn"],
                    "group_dn": new_group["dn"],
                    "membership_type": "DIRECT"
                }]
            )
        )

        memberships = ad_storage.get_ad_memberships()

        self.assertEqual(len(memberships), 1)
        self.assertEqual(memberships[0]["member_dn"], new_user["dn"])
        self.assertEqual(memberships[0]["group_dn"], new_group["dn"])

    def test_other_domain_objects_are_preserved(self):
        domain_a = "DC=lab,DC=local"
        domain_b = "DC=other,DC=local"

        user_a = self.make_user("user_a", domain_a)
        user_b = self.make_user("user_b", domain_b)

        group_a = self.make_group("GroupA", domain_a)
        group_b = self.make_group("GroupB", domain_b)

        ad_storage.save_ad_data(
            self.make_ad_data(
                domain_dn=domain_a,
                users=[user_a],
                groups=[group_a]
            )
        )

        ad_storage.save_ad_data(
            self.make_ad_data(
                domain_dn=domain_b,
                users=[user_b],
                groups=[group_b]
            )
        )

        # A valid empty snapshot removes domain A's objects.
        ad_storage.save_ad_data(
            self.make_ad_data(domain_dn=domain_a)
        )

        stored_users = {
            user["dn"]
            for user in ad_storage.get_ad_users()
        }

        stored_groups = {
            group["dn"]
            for group in ad_storage.get_ad_groups()
        }

        self.assertNotIn(user_a["dn"], stored_users)
        self.assertIn(user_b["dn"], stored_users)

        self.assertNotIn(group_a["dn"], stored_groups)
        self.assertIn(group_b["dn"], stored_groups)

    def test_supplied_connection_does_not_commit(self):
        user = self.make_user("transaction_user")
        data = self.make_ad_data(users=[user])

        conn = sqlite3.connect(self.db_path)

        try:
            ad_storage.save_ad_data(data, conn=conn)

            # The write is visible inside the current transaction.
            count = conn.execute(
                "SELECT COUNT(*) FROM ad_users"
            ).fetchone()[0]

            self.assertEqual(count, 1)

            # Roll back the caller's transaction.
            conn.rollback()

            count = conn.execute(
                "SELECT COUNT(*) FROM ad_users"
            ).fetchone()[0]

            self.assertEqual(count, 0)

        finally:
            conn.close()

        self.assertEqual(ad_storage.get_ad_users(), [])


if __name__ == "__main__":
    unittest.main()
