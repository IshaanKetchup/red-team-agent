
import unittest

from engine.rules import (
    detect_domain_controllers,
    detect_smb_exposure,
    detect_ldap_exposure,
    detect_ad_users,
    detect_ad_privilege_paths,
    run_all_rules,
)


class TestDetectionRules(unittest.TestCase):

    def test_detect_domain_controller(self):
        services = [
            {"host_ip": "192.168.56.10", "port": 88, "protocol": "tcp"},
            {"host_ip": "192.168.56.10", "port": 389, "protocol": "tcp"},
        ]

        findings = detect_domain_controllers(services)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["host"], "192.168.56.10")
        self.assertEqual(findings[0]["rule"], "DOMAIN_CONTROLLER")

    def test_domain_controller_ports_must_be_on_same_host(self):
        services = [
            {"host_ip": "192.168.56.10", "port": 88, "protocol": "tcp"},
            {"host_ip": "192.168.56.20", "port": 389, "protocol": "tcp"},
        ]

        findings = detect_domain_controllers(services)

        self.assertEqual(findings, [])

    def test_udp_ports_do_not_identify_domain_controller(self):
        services = [
            {"host_ip": "192.168.56.10", "port": 88, "protocol": "udp"},
            {"host_ip": "192.168.56.10", "port": 389, "protocol": "tcp"},
        ]

        findings = detect_domain_controllers(services)

        self.assertEqual(findings, [])

    def test_detect_smb_exposure(self):
        services = [
            {"host_ip": "192.168.56.20", "port": 445, "protocol": "tcp"},
        ]

        findings = detect_smb_exposure(services)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "SMB_EXPOSURE")
        self.assertEqual(findings[0]["host"], "192.168.56.20")

    def test_detect_ldap_and_ldaps(self):
        services = [
            {"host_ip": "192.168.56.10", "port": 389, "protocol": "tcp"},
            {"host_ip": "192.168.56.10", "port": 636, "protocol": "tcp"},
        ]

        findings = detect_ldap_exposure(services)

        rules = {finding["rule"] for finding in findings}

        self.assertEqual(
            rules,
            {"LDAP_EXPOSURE", "LDAPS_EXPOSURE"}
        )

    def test_detect_ad_users(self):
        users = [
            {"sAMAccountName": "alice"},
            {"sAMAccountName": "bob"},
        ]

        findings = detect_ad_users(users)

        self.assertEqual(len(findings), 2)
        self.assertEqual(
            findings[0]["evidence"],
            "Account discovered: alice"
        )

    def test_ad_users_without_account_name_are_skipped(self):
        users = [
            {"displayName": "Unknown User"},
            {"sAMAccountName": "alice"},
        ]

        findings = detect_ad_users(users)

        self.assertEqual(len(findings), 1)
        self.assertIn("alice", findings[0]["evidence"])

    def test_detect_direct_privilege_path(self):
        analysis = {
            "paths": [
                {
                    "sam_account_name": "alice",
                    "target_group": "Domain Admins",
                    "category": "DOMAIN_ADMIN",
                    "relationship": "DIRECT",
                    "path": [
                        "CN=alice,DC=lab,DC=local",
                        "CN=Domain Admins,DC=lab,DC=local",
                    ],
                }
            ]
        }

        findings = detect_ad_privilege_paths(analysis)

        self.assertEqual(len(findings), 1)
        self.assertIn("alice", findings[0]["evidence"])
        self.assertIn("Domain Admins", findings[0]["evidence"])
        self.assertIn("DOMAIN_ADMIN", findings[0]["evidence"])
        self.assertIn("direct", findings[0]["evidence"])

    def test_empty_privilege_analysis(self):
        findings = detect_ad_privilege_paths({"paths": []})

        self.assertEqual(findings, [])

    def test_run_all_rules_combines_findings(self):
        services = [
            {"host_ip": "192.168.56.10", "port": 88, "protocol": "tcp"},
            {"host_ip": "192.168.56.10", "port": 389, "protocol": "tcp"},
            {"host_ip": "192.168.56.10", "port": 445, "protocol": "tcp"},
            {"host_ip": "192.168.56.10", "port": 636, "protocol": "tcp"},
        ]

        users = [
            {"sAMAccountName": "alice"},
        ]

        analysis = {
            "paths": [
                {
                    "sam_account_name": "alice",
                    "target_group": "Domain Admins",
                    "category": "DOMAIN_ADMIN",
                    "relationship": "DIRECT",
                    "path": ["alice", "Domain Admins"],
                }
            ]
        }

        findings = run_all_rules(
            services,
            users,
            ad_analysis=analysis
        )

        self.assertEqual(len(findings), 6)

        rules = {finding["rule"] for finding in findings}

        self.assertEqual(
            rules,
            {
                "DOMAIN_CONTROLLER",
                "SMB_EXPOSURE",
                "LDAP_EXPOSURE",
                "LDAPS_EXPOSURE",
                "AD_USER_DISCOVERED",
                "AD_PRIVILEGED_MEMBERSHIP",
            }
        )


if __name__ == "__main__":
    unittest.main()
