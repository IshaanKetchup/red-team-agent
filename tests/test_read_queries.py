
import os
import tempfile
import unittest

from database import storage


class TestReadQueries(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = storage.DB_PATH
        storage.DB_PATH = os.path.join(
            self.temp_dir.name,
            "test.db",
        )

        storage.initialize_database()
        storage.initialize_services_table()
        storage.initialize_findings_table()

    def tearDown(self):
        storage.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def seed_data(self):
        run_id = storage.start_scan_run()

        storage.save_findings([
            {
                "rule": "SMB_EXPOSURE",
                "severity": "HIGH",
                "host": "192.168.56.20",
                "evidence": "TCP port 445 is open",
            },
            {
                "rule": "LDAP_EXPOSURE",
                "severity": "INFO",
                "host": "192.168.56.10",
                "evidence": "LDAP service detected",
            },
        ], run_id)

        storage.save_hosts([
            {
                "ip": "192.168.56.10",
                "status": "up",
                "hostname": "LAB-DC.lab.local",
            },
            {
                "ip": "192.168.56.20",
                "status": "up",
                "hostname": "LAB-PC01",
            },
        ])

        storage.save_services([
            {
                "host_ip": "192.168.56.20",
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
                "product": "Windows SMB",
                "version": "",
            },
            {
                "host_ip": "192.168.56.10",
                "port": 636,
                "protocol": "tcp",
                "service": "ldap",
                "product": "Microsoft Active Directory LDAP",
                "version": "",
            },
        ])

    def test_empty_findings_summary(self):
        result = storage.get_findings_summary()

        self.assertEqual(result["total_findings"], 0)
        self.assertEqual(result["by_status"], {})
        self.assertEqual(result["by_severity"], {})
        self.assertEqual(result["recent_findings"], [])

    def test_findings_summary_counts(self):
        self.seed_data()

        result = storage.get_findings_summary()

        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["by_status"], {"ACTIVE": 2})
        self.assertEqual(
            result["by_severity"],
            {"HIGH": 1, "INFO": 1},
        )
        self.assertEqual(len(result["recent_findings"]), 2)

    def test_findings_can_be_filtered(self):
        self.seed_data()

        result = storage.query_findings(
            severity="HIGH",
            host="192.168.56.20",
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["returned"], 1)
        self.assertEqual(
            result["findings"][0]["rule_id"],
            "SMB_EXPOSURE",
        )

    def test_findings_pagination(self):
        self.seed_data()

        first_page = storage.query_findings(limit=1, offset=0)
        second_page = storage.query_findings(limit=1, offset=1)

        self.assertEqual(first_page["total"], 2)
        self.assertEqual(first_page["returned"], 1)
        self.assertEqual(second_page["returned"], 1)

        self.assertNotEqual(
            first_page["findings"][0]["id"],
            second_page["findings"][0]["id"],
        )

    def test_finding_limit_is_capped(self):
        self.seed_data()

        result = storage.query_findings(limit=999999)

        self.assertEqual(result["limit"], 200)
        self.assertLessEqual(result["returned"], 200)

    def test_host_inventory(self):
        self.seed_data()

        result = storage.query_host_inventory()

        self.assertEqual(result["returned"], 2)
        self.assertEqual(
            result["hosts"][0]["ip"],
            "192.168.56.10",
        )

    def test_service_inventory_host_filter(self):
        self.seed_data()

        result = storage.query_service_inventory(
            host_ip="192.168.56.20",
        )

        self.assertEqual(result["returned"], 1)
        self.assertEqual(
            result["services"][0]["port"],
            445,
        )

    def test_scan_history(self):
        self.seed_data()

        result = storage.query_scan_history()

        self.assertEqual(result["returned"], 1)
        self.assertEqual(
            result["scan_runs"][0]["status"],
            "RUNNING",
        )

    def test_read_queries_do_not_modify_database(self):
        self.seed_data()

        before = (
            len(storage.get_findings()),
            len(storage.get_hosts()),
            len(storage.get_services()),
            len(storage.get_scan_runs()),
        )

        storage.get_findings_summary()
        storage.query_findings()
        storage.query_host_inventory()
        storage.query_service_inventory()
        storage.query_scan_history()

        after = (
            len(storage.get_findings()),
            len(storage.get_hosts()),
            len(storage.get_services()),
            len(storage.get_scan_runs()),
        )

        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
