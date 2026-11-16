import sqlite3
import tempfile
import unittest
from pathlib import Path

from database import storage


class TestScanSnapshots(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = storage.DB_PATH
        storage.DB_PATH = Path(self.temp_dir.name) / "test.db"

        storage.initialize_database()
        storage.initialize_services_table()
        storage.initialize_findings_table()

    def tearDown(self):
        storage.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()
        
    def finding(
        self,
        rule_id="SMB_EXPOSURE",
        severity="HIGH",
        host="192.168.56.20",
        evidence="TCP port 445 is open",
        finding_key="stable-test-key",
    ):
        return {
            "rule": rule_id,
            "severity": severity,
            "host": host,
            "evidence": evidence,
            "finding_key": finding_key,
        }

    def completed_scan(self, findings, checked_hosts=None):
        run_id = storage.start_scan_run()

        storage.save_findings(findings, run_id)

        storage.complete_scan_run(
            run_id,
            checked_hosts=(
                checked_hosts
                if checked_hosts is not None
                else ["192.168.56.20"]
            ),
            ldap_checked=False,
        )

        return run_id

    def test_summary_contains_extended_analytics(self):
        self.completed_scan([
            self.finding(),
            self.finding(
                rule_id="RDP_EXPOSURE",
                severity="MEDIUM",
                evidence="TCP port 3389 is open",
                finding_key="rdp-test-key",
            ),
        ])

        summary = storage.get_findings_summary()

        self.assertIn("by_severity_and_status", summary)
        self.assertIn("by_rule", summary)
        self.assertIn("by_host", summary)
        self.assertIn("lifecycle", summary)

        self.assertEqual(
            summary["by_severity_and_status"]["HIGH"]["ACTIVE"],
            1,
        )
        self.assertEqual(
            summary["by_severity_and_status"]["MEDIUM"]["ACTIVE"],
            1,
        )

        self.assertEqual(summary["lifecycle"]["total"], 2)
        self.assertEqual(summary["lifecycle"]["active"], 2)
        self.assertEqual(summary["lifecycle"]["resolved"], 0)

    def test_empty_summary_has_zero_lifecycle_counts(self):
        summary = storage.get_findings_summary()

        lifecycle = summary["lifecycle"]

        self.assertEqual(lifecycle["total"], 0)
        self.assertEqual(lifecycle["active"], 0)
        self.assertEqual(lifecycle["resolved"], 0)
        self.assertEqual(lifecycle["with_resolved_at"], 0)
        self.assertIsNone(lifecycle["average_resolution_seconds"])

    def test_finding_details_include_scan_history(self):
        first_run = self.completed_scan([
            self.finding(severity="MEDIUM"),
        ])

        second_run = self.completed_scan([
            self.finding(severity="HIGH"),
        ])

        details = storage.get_finding_details(1)

        self.assertIsNotNone(details["finding"])
        self.assertEqual(details["finding"]["severity"], "HIGH")

        history = details["history"]
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["run_id"], first_run)
        self.assertEqual(history[1]["run_id"], second_run)

    def test_missing_finding_details_return_empty_result(self):
        details = storage.get_finding_details(99999)

        self.assertIsNone(details["finding"])
        self.assertEqual(details["history"], [])

    def test_compare_detects_added_and_changed_findings(self):
        older_run = self.completed_scan([
            self.finding(severity="MEDIUM"),
        ])

        newer_run = self.completed_scan([
            self.finding(severity="HIGH"),
            self.finding(
                rule_id="RDP_EXPOSURE",
                severity="MEDIUM",
                evidence="TCP port 3389 is open",
                finding_key="rdp-test-key",
            ),
        ])

        result = storage.compare_scan_runs(older_run, newer_run)

        self.assertTrue(result["available"])
        self.assertEqual(result["counts"]["changed"], 1)
        self.assertEqual(result["counts"]["added"], 1)
        self.assertEqual(result["counts"]["resolved"], 0)

    def test_compare_detects_resolved_findings(self):
        older_run = self.completed_scan([
            self.finding(),
        ])

        newer_run = self.completed_scan(
            [],
            checked_hosts=["192.168.56.20"],
        )

        result = storage.compare_scan_runs(older_run, newer_run)

        self.assertTrue(result["available"])
        self.assertEqual(result["counts"]["resolved"], 1)

    def test_compare_detects_reactivated_findings(self):
        first_run = self.completed_scan([
            self.finding(),
        ])

        resolved_run = self.completed_scan(
            [],
            checked_hosts=["192.168.56.20"],
        )

        reactivated_run = self.completed_scan([
            self.finding(),
        ])

        result = storage.compare_scan_runs(
            resolved_run,
            reactivated_run,
        )

        self.assertTrue(result["available"])
        self.assertEqual(result["counts"]["reactivated"], 1)

    def test_compare_rejects_identical_run_ids(self):
        run_id = self.completed_scan([
            self.finding(),
        ])

        with self.assertRaises(ValueError):
            storage.compare_scan_runs(run_id, run_id)

    def test_compare_rejects_incomplete_scan(self):
        run_id = storage.start_scan_run()
        completed_run = self.completed_scan([
            self.finding(),
        ])

        with self.assertRaises(ValueError):
            storage.compare_scan_runs(run_id, completed_run)

    def test_compare_reports_unavailable_legacy_snapshots(self):
        older_run = self.completed_scan([
            self.finding(),
        ])

        newer_run = self.completed_scan([
            self.finding(),
        ])

        with sqlite3.connect(storage.DB_PATH) as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET snapshot_recorded = 0
                WHERE id = ?
                """,
                (older_run,),
            )

        result = storage.compare_scan_runs(older_run, newer_run)

        self.assertFalse(result["available"])
        self.assertIn("reason", result)

    def test_snapshot_and_findings_roll_back_together(self):
        run_id = storage.start_scan_run()

        with self.assertRaises(RuntimeError):
            with sqlite3.connect(storage.DB_PATH) as conn:
                storage.save_findings(
                    [self.finding()],
                    run_id,
                    conn=conn,
                )

                storage.complete_scan_run(
                    run_id,
                    checked_hosts=["192.168.56.20"],
                    ldap_checked=False,
                    conn=conn,
                )

                raise RuntimeError("Simulated transaction failure")

        with sqlite3.connect(storage.DB_PATH) as conn:
            finding_count = conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]

            snapshot_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM scan_run_findings
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()[0]

            run_status = conn.execute(
                "SELECT status FROM scan_runs WHERE id = ?",
                (run_id,),
            ).fetchone()[0]

        self.assertEqual(finding_count, 0)
        self.assertEqual(snapshot_count, 0)
        self.assertEqual(run_status, "RUNNING")


if __name__ == "__main__":
    unittest.main()
