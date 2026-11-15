
import os
import sqlite3
import tempfile
import unittest

from contextlib import closing

from database import storage


class TestFindingStorage(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = storage.DB_PATH
        storage.DB_PATH = os.path.join(self.temp_dir.name, "test.db")

        storage.initialize_findings_table()

    def tearDown(self):
        storage.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def create_finding(
        self,
        rule="SMB_EXPOSURE",
        host="192.168.56.20",
        evidence="TCP port 445 is open",
        severity="INFO",
    ):
        return {
            "rule": rule,
            "severity": severity,
            "host": host,
            "evidence": evidence,
        }

    def get_finding_record(self, rule, host, evidence):
        with closing(sqlite3.connect(storage.DB_PATH)) as conn:
            return conn.execute("""
                SELECT status, last_seen_run_id, resolved_at, severity
                FROM findings
                WHERE rule_id = ? AND host = ? AND evidence = ?
            """, (rule, host, evidence)).fetchone()

    def test_new_finding_is_saved_as_active(self):
        run_id = storage.start_scan_run()
        finding = self.create_finding()

        storage.save_findings([finding], run_id)

        record = self.get_finding_record(
            "SMB_EXPOSURE",
            "192.168.56.20",
            "TCP port 445 is open"
        )

        self.assertIsNotNone(record)
        self.assertEqual(record[0], "ACTIVE")
        self.assertEqual(record[1], run_id)
        self.assertIsNone(record[2])

    def test_duplicate_finding_is_updated_not_duplicated(self):
        first_run = storage.start_scan_run()
        second_run = storage.start_scan_run()

        storage.save_findings([self.create_finding()], first_run)
        storage.save_findings(
            [self.create_finding(severity="HIGH")],
            second_run
        )

        with closing(sqlite3.connect(storage.DB_PATH)) as conn:
            count = conn.execute("""
                SELECT COUNT(*) FROM findings
                WHERE rule_id = 'SMB_EXPOSURE'
            """).fetchone()[0]

        record = self.get_finding_record(
            "SMB_EXPOSURE",
            "192.168.56.20",
            "TCP port 445 is open"
        )

        self.assertEqual(count, 1)
        self.assertEqual(record[0], "ACTIVE")
        self.assertEqual(record[1], second_run)
        self.assertEqual(record[3], "HIGH")

    def test_missing_finding_is_resolved_after_successful_scan(self):
        first_run = storage.start_scan_run()
        storage.save_findings([self.create_finding()], first_run)

        second_run = storage.start_scan_run()
        storage.complete_scan_run(
            second_run,
            checked_hosts=["192.168.56.20"],
            ldap_checked=False
        )

        record = self.get_finding_record(
            "SMB_EXPOSURE",
            "192.168.56.20",
            "TCP port 445 is open"
        )

        self.assertEqual(record[0], "RESOLVED")
        self.assertIsNotNone(record[2])

    def test_unchecked_host_finding_remains_active(self):
        first_run = storage.start_scan_run()
        storage.save_findings([self.create_finding()], first_run)

        second_run = storage.start_scan_run()
        storage.complete_scan_run(
            second_run,
            checked_hosts=["192.168.56.10"],
            ldap_checked=False
        )

        record = self.get_finding_record(
            "SMB_EXPOSURE",
            "192.168.56.20",
            "TCP port 445 is open"
        )

        self.assertEqual(record[0], "ACTIVE")

    def test_failed_scan_does_not_resolve_existing_findings(self):
        first_run = storage.start_scan_run()
        storage.save_findings([self.create_finding()], first_run)

        second_run = storage.start_scan_run()
        storage.abort_scan_run(second_run, "Simulated scan failure")

        record = self.get_finding_record(
            "SMB_EXPOSURE",
            "192.168.56.20",
            "TCP port 445 is open"
        )

        self.assertEqual(record[0], "ACTIVE")

        runs = storage.get_scan_runs()
        failed_run = next(run for run in runs if run[0] == second_run)

        self.assertEqual(failed_run[3], "FAILED")
        self.assertEqual(failed_run[4], "Simulated scan failure")

    def test_resolved_finding_becomes_active_when_rediscovered(self):
        finding = self.create_finding()

        first_run = storage.start_scan_run()
        storage.save_findings([finding], first_run)

        second_run = storage.start_scan_run()
        storage.complete_scan_run(
            second_run,
            checked_hosts=["192.168.56.20"],
            ldap_checked=False
        )

        third_run = storage.start_scan_run()
        storage.save_findings([finding], third_run)

        record = self.get_finding_record(
            "SMB_EXPOSURE",
            "192.168.56.20",
            "TCP port 445 is open"
        )

        self.assertEqual(record[0], "ACTIVE")
        self.assertEqual(record[1], third_run)
        self.assertIsNone(record[2])

    def test_ldap_findings_are_resolved_only_when_ldap_checked(self):
        finding = self.create_finding(
            rule="AD_USER_DISCOVERED",
            host="LAB.LOCAL",
            evidence="Account discovered: alice"
        )

        first_run = storage.start_scan_run()
        storage.save_findings([finding], first_run)

        second_run = storage.start_scan_run()
        storage.complete_scan_run(
            second_run,
            checked_hosts=[],
            ldap_checked=False
        )

        record = self.get_finding_record(
            "AD_USER_DISCOVERED",
            "LAB.LOCAL",
            "Account discovered: alice"
        )
        self.assertEqual(record[0], "ACTIVE")

        third_run = storage.start_scan_run()
        storage.complete_scan_run(
            third_run,
            checked_hosts=[],
            ldap_checked=True
        )

        record = self.get_finding_record(
            "AD_USER_DISCOVERED",
            "LAB.LOCAL",
            "Account discovered: alice"
        )
        self.assertEqual(record[0], "RESOLVED")


class TestServiceStorage(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = storage.DB_PATH
        storage.DB_PATH = os.path.join(self.temp_dir.name, "test.db")

        storage.initialize_services_table()

    def tearDown(self):
        storage.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def make_service(self, host, port, service="http"):
        return {
            "host_ip": host,
            "port": port,
            "protocol": "tcp",
            "service": service,
            "product": "TestServer",
            "version": "1.0"
        }

    def test_stale_services_are_deleted(self):
        host = "192.168.56.20"

        storage.save_services([
            self.make_service(host, 80),
            self.make_service(host, 443, "https")
        ])

        storage.save_services(
            [self.make_service(host, 443, "https")],
            checked_hosts=[host]
        )

        services = storage.get_services()

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0][1], 443)

    def test_empty_result_clears_checked_host_services(self):
        host = "192.168.56.20"

        storage.save_services([
            self.make_service(host, 80),
            self.make_service(host, 443, "https")
        ])

        storage.save_services([], checked_hosts=[host])

        self.assertEqual(storage.get_services(), [])

    def test_unchecked_host_services_are_preserved(self):
        checked_host = "192.168.56.20"
        unchecked_host = "192.168.56.10"

        storage.save_services([
            self.make_service(checked_host, 80),
            self.make_service(unchecked_host, 445, "smb")
        ])

        storage.save_services(
            [self.make_service(checked_host, 443, "https")],
            checked_hosts=[checked_host]
        )

        services = storage.get_services()
        stored = {(row[0], row[1]) for row in services}

        self.assertEqual(
            stored,
            {
                (checked_host, 443),
                (unchecked_host, 445)
            }
        )

    def test_omitting_checked_hosts_preserves_upsert_behaviour(self):
        host = "192.168.56.20"

        storage.save_services([
            self.make_service(host, 80),
            self.make_service(host, 443, "https")
        ])

        storage.save_services([
            self.make_service(host, 8080)
        ])

        services = storage.get_services()
        ports = {row[1] for row in services}

        self.assertEqual(ports, {80, 443, 8080})

    def test_reconciliation_respects_caller_transaction(self):
        host = "192.168.56.20"

        storage.save_services([
            self.make_service(host, 80)
        ])

        conn = sqlite3.connect(storage.DB_PATH)

        try:
            storage.save_services(
                [self.make_service(host, 443, "https")],
                conn=conn,
                checked_hosts=[host]
            )

            ports_inside_transaction = {
                row[0]
                for row in conn.execute(
                    "SELECT port FROM services"
                ).fetchall()
            }

            self.assertEqual(ports_inside_transaction, {443})

            conn.rollback()

        finally:
            conn.close()

        ports_after_rollback = {
            row[1]
            for row in storage.get_services()
        }

        self.assertEqual(ports_after_rollback, {80})


if __name__ == "__main__":
    unittest.main()
