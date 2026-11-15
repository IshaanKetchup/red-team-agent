
import os
import sqlite3
import tempfile
import unittest

from contextlib import ExitStack, closing
from unittest.mock import patch

import engine.orchestrator as orchestrator


class TestOrchestrator(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = os.path.join(
            self.temp_dir.name,
            "test_redteam.db"
        )

        self.stack.enter_context(
            patch.object(orchestrator, "DB_PATH", self.db_path)
        )

        # Create the table used by the transaction rollback test.
        # closing() closes the connection; the inner context manages
        # the transaction.
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute("""
                    CREATE TABLE transaction_test (
                        value TEXT
                    )
                """)

        self.logs = []

        self.initialize = self.stack.enter_context(
            patch.object(orchestrator, "initialize")
        )

        self.start_scan_run = self.stack.enter_context(
            patch.object(
                orchestrator,
                "start_scan_run",
                return_value=1
            )
        )

        self.discover_hosts = self.stack.enter_context(
            patch.object(orchestrator, "discover_hosts")
        )

        self.scan_services = self.stack.enter_context(
            patch.object(orchestrator, "scan_services")
        )

        self.enumerate_ad_data = self.stack.enter_context(
            patch.object(orchestrator, "enumerate_ad_data")
        )

        self.analyze_ad_data = self.stack.enter_context(
            patch.object(orchestrator, "analyze_ad_data")
        )

        self.run_all_rules = self.stack.enter_context(
            patch.object(orchestrator, "run_all_rules")
        )

        self.save_hosts = self.stack.enter_context(
            patch.object(orchestrator, "save_hosts")
        )

        self.save_services = self.stack.enter_context(
            patch.object(orchestrator, "save_services")
        )

        self.save_ad_data = self.stack.enter_context(
            patch.object(orchestrator, "save_ad_data")
        )

        self.save_users = self.stack.enter_context(
            patch.object(orchestrator, "save_users")
        )

        self.save_findings = self.stack.enter_context(
            patch.object(orchestrator, "save_findings")
        )

        self.complete_scan_run = self.stack.enter_context(
            patch.object(orchestrator, "complete_scan_run")
        )

        self.abort_scan_run = self.stack.enter_context(
            patch.object(orchestrator, "abort_scan_run")
        )

        self.hosts = [
            {
                "ip": "192.168.56.10",
                "status": "up",
                "hostname": "LAB-DC"
            },
            {
                "ip": "192.168.56.103",
                "status": "up",
                "hostname": "kali"
            },
            {
                "ip": "192.168.56.20",
                "status": "up",
                "hostname": "WORKSTATION"
            }
        ]

        self.services = {
            "192.168.56.10": [
                {
                    "host_ip": "192.168.56.10",
                    "port": 88,
                    "protocol": "tcp",
                    "service": "kerberos",
                    "product": "",
                    "version": ""
                },
                {
                    "host_ip": "192.168.56.10",
                    "port": 389,
                    "protocol": "tcp",
                    "service": "ldap",
                    "product": "",
                    "version": ""
                }
            ],
            "192.168.56.20": [
                {
                    "host_ip": "192.168.56.20",
                    "port": 445,
                    "protocol": "tcp",
                    "service": "microsoft-ds",
                    "product": "",
                    "version": ""
                }
            ]
        }

        self.ad_data = {
            "domain": {
                "dn": "DC=lab,DC=local",
                "objectSid": "S-1-5-21-111111111-222222222-333333333"
            },
            "users": [
                {
                    "dn": "CN=testuser,CN=Users,DC=lab,DC=local",
                    "sAMAccountName": "testuser"
                }
            ],
            "groups": [],
            "memberships": [],
            "password_policy": {}
        }

        self.ad_analysis = {
            "domain_dn": "DC=lab,DC=local",
            "sensitive_groups": [],
            "paths": []
        }

        self.findings = [
            {
                "rule_id": "TEST_RULE",
                "severity": "INFO",
                "title": "Test finding",
                "description": "Test description",
                "host_ip": "192.168.56.20"
            }
        ]

        self.discover_hosts.return_value = self.hosts

        self.scan_services.side_effect = (
            lambda ip: self.services.get(ip, [])
        )

        self.enumerate_ad_data.return_value = self.ad_data
        self.analyze_ad_data.return_value = self.ad_analysis
        self.run_all_rules.return_value = self.findings

    def run_scan(self, password="test-password"):
        return orchestrator.run_full_scan(
            password=password,
            log=self.logs.append
        )

    def test_successful_full_scan(self):
        self.run_scan()

        self.initialize.assert_called_once()
        self.start_scan_run.assert_called_once()
        self.discover_hosts.assert_called_once()

        self.enumerate_ad_data.assert_called_once()
        self.analyze_ad_data.assert_called_once_with(self.ad_data)
        self.run_all_rules.assert_called_once()

        self.save_hosts.assert_called_once()
        self.save_services.assert_called_once()
        self.save_ad_data.assert_called_once()
        self.save_users.assert_called_once()
        self.save_findings.assert_called_once()

        self.complete_scan_run.assert_called_once()
        self.abort_scan_run.assert_not_called()

    def test_kali_host_is_not_scanned(self):
        self.run_scan()

        scanned_ips = [
            call.args[0]
            for call in self.scan_services.call_args_list
        ]

        self.assertNotIn("192.168.56.103", scanned_ips)
        self.assertIn("192.168.56.10", scanned_ips)
        self.assertIn("192.168.56.20", scanned_ips)

    def test_all_persistence_uses_same_connection(self):
        self.run_scan()

        persistence_calls = [
            self.save_hosts,
            self.save_services,
            self.save_ad_data,
            self.save_users,
            self.save_findings,
            self.complete_scan_run
        ]

        connections = [
            item.call_args.kwargs["conn"]
            for item in persistence_calls
        ]

        self.assertTrue(
            all(conn is not None for conn in connections)
        )

        first_connection = connections[0]

        self.assertTrue(
            all(conn is first_connection for conn in connections)
        )

    def test_service_enumeration_failure_aborts_scan(self):
        self.scan_services.side_effect = RuntimeError(
            "Service enumeration failed"
        )

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()

        self.save_hosts.assert_not_called()
        self.save_services.assert_not_called()
        self.save_ad_data.assert_not_called()
        self.save_users.assert_not_called()
        self.save_findings.assert_not_called()

    def test_missing_domain_controller_aborts_scan(self):
        self.scan_services.side_effect = lambda ip: []

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()

        self.save_hosts.assert_not_called()
        self.save_services.assert_not_called()

    def test_ad_enumeration_exception_aborts_scan(self):
        self.enumerate_ad_data.side_effect = RuntimeError(
            "AD enumeration failed"
        )

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()

        self.save_hosts.assert_not_called()
        self.save_services.assert_not_called()
        self.save_ad_data.assert_not_called()

    def test_empty_ad_data_aborts_scan(self):
        self.enumerate_ad_data.return_value = None

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()

        self.save_hosts.assert_not_called()
        self.save_services.assert_not_called()
        self.save_ad_data.assert_not_called()

    def test_ad_analysis_failure_aborts_scan(self):
        self.analyze_ad_data.side_effect = RuntimeError(
            "AD analysis failed"
        )

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()

        self.save_hosts.assert_not_called()
        self.save_services.assert_not_called()
        self.save_ad_data.assert_not_called()

    def test_discovery_exception_aborts_scan(self):
        self.discover_hosts.side_effect = RuntimeError(
            "Discovery failed"
        )

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()
        self.save_hosts.assert_not_called()

    def test_empty_discovery_aborts_scan(self):
        self.discover_hosts.return_value = []

        with self.assertRaises(RuntimeError):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()
        self.save_hosts.assert_not_called()

    def test_missing_password_does_not_start_scan(self):
        with self.assertRaises(ValueError):
            self.run_scan(password=None)

        self.start_scan_run.assert_not_called()
        self.discover_hosts.assert_not_called()
        self.abort_scan_run.assert_not_called()

    def test_database_failure_rolls_back_transaction(self):

        # hosts is positional; conn is keyword-only in this callback.
        def write_host(*args, conn=None, **kwargs):
            conn.execute(
                "INSERT INTO transaction_test (value) VALUES (?)",
                ("host",)
            )

        def write_finding_and_fail(*args, conn=None, **kwargs):
            conn.execute(
                "INSERT INTO transaction_test (value) VALUES (?)",
                ("finding",)
            )
            raise RuntimeError("Simulated database failure")

        self.save_hosts.side_effect = write_host
        self.save_findings.side_effect = write_finding_and_fail

        with self.assertRaisesRegex(
            RuntimeError,
            "Simulated database failure"
        ):
            self.run_scan()

        self.abort_scan_run.assert_called_once()
        self.complete_scan_run.assert_not_called()

        with closing(sqlite3.connect(self.db_path)) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM transaction_test"
            ).fetchone()[0]

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
