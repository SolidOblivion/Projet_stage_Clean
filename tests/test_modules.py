import unittest
from unittest.mock import patch

from bson import ObjectId

from database.mongo_client import nettoyer_id
from modules.data_mapper import assembler_resultats, calculer_summary
from modules.tech_detector import (
    analyser_cookies,
    analyser_headers,
    analyser_html,
    normaliser_technologies,
)
from pipeline import runner


SAMPLE_SUBDOMAINS = [
    {
        "subdomain": "www.example.com",
        "ips": ["1.1.1.1", "2.2.2.2"],
        "mx": [],
        "ns": [],
        "cname": None,
        "ports_par_ip": {
            "1.1.1.1": [{"port": 80}, {"port": 443}],
            "2.2.2.2": [{"port": 22}],
        },
        "services_web": [
            {"technologies": ["nginx", "WordPress"]},
            {"technologies": ["Cloudflare"]},
        ],
    },
    {
        "subdomain": "api.example.com",
        "ips": ["2.2.2.2"],
        "mx": [],
        "ns": [],
        "cname": None,
        "ports_par_ip": {
            "2.2.2.2": [{"port": 8080}],
        },
        "services_web": [
            {"technologies": ["nginx", "FastAPI"]},
        ],
    },
]


class TechDetectorTests(unittest.TestCase):
    def test_analyser_headers(self):
        out = analyser_headers(
            {
                "Server": "nginx",
                "X-Powered-By": "PHP/8.2",
                "X-Generator": "WordPress 6.4",
                "Via": "1.1 cloudflare",
                "CF-RAY": "abc",
                "X-Amz-Cf-Id": "def",
            }
        )

        self.assertIn("nginx", out)
        self.assertIn("PHP/8.2", out)
        self.assertIn("WordPress 6.4", out)
        self.assertIn("Cloudflare", out)
        self.assertIn("AWS CloudFront", out)
        self.assertEqual(out.count("Cloudflare"), 1)

    def test_analyser_cookies(self):
        out = analyser_cookies(
            {
                "Set-Cookie": (
                    "PHPSESSID=a; Path=/, "
                    "laravel_session=b; Path=/, "
                    "django_session=c; Path=/"
                )
            }
        )

        self.assertIn("PHP", out)
        self.assertIn("Laravel", out)
        self.assertIn("Django", out)

    def test_analyser_html(self):
        out = analyser_html(
            """
            <html><head>
                <meta name="generator" content="WordPress 6.4">
            </head><body>
                <script src="/wp-content/themes/site.js"></script>
                <script src="/_next/static/chunk.js"></script>
                <script>gtag('config','x')</script>
            </body></html>
            """
        )

        self.assertIn("WordPress 6.4", out)
        self.assertIn("WordPress", out)
        self.assertIn("Next.js", out)
        self.assertIn("Google Analytics", out)

    def test_normaliser_technologies(self):
        out = normaliser_technologies(
            ["cloudflare", "Cloudflare", "AWS CloudFront", "aws cloudfront"]
        )
        self.assertEqual(out, ["Cloudflare", "AWS CloudFront"])


class DataMapperTests(unittest.TestCase):
    def test_calculer_summary(self):
        summary = calculer_summary(SAMPLE_SUBDOMAINS)

        self.assertEqual(summary["total_subdomains"], 2)
        self.assertEqual(summary["total_ips"], 2)
        self.assertEqual(summary["total_open_ports"], 4)
        self.assertEqual(summary["total_technologies"], 4)

    def test_assembler_resultats(self):
        out = assembler_resultats("example.com", SAMPLE_SUBDOMAINS)

        self.assertIn("scan_id", out)
        self.assertEqual(out["target"], "example.com")
        self.assertIn("scan_date", out)
        self.assertEqual(len(out["subdomains"]), 2)
        self.assertEqual(out["summary"]["total_open_ports"], 4)


class MongoClientTests(unittest.TestCase):
    def test_nettoyer_id(self):
        out = nettoyer_id({"_id": ObjectId(), "x": 1})
        self.assertIsInstance(out["_id"], str)


class RunnerIntegrationTests(unittest.TestCase):
    def test_lancer_scan_orchestration(self):
        calls = []

        subs = ["www.example.com"]
        resolved = [
            {
                "subdomain": "www.example.com",
                "ips": ["1.1.1.1"],
                "mx": [],
                "ns": [],
                "cname": None,
            }
        ]
        scanned = [
            {
                "subdomain": "www.example.com",
                "ips": ["1.1.1.1"],
                "mx": [],
                "ns": [],
                "cname": None,
                "ports_par_ip": {
                    "1.1.1.1": [
                        {
                            "port": 80,
                            "service": "http",
                            "protocole": "tcp",
                            "state": "open",
                        }
                    ]
                },
            }
        ]
        enriched = [
            {
                "subdomain": "www.example.com",
                "ips": ["1.1.1.1"],
                "mx": [],
                "ns": [],
                "cname": None,
                "ports_par_ip": {
                    "1.1.1.1": [
                        {
                            "port": 80,
                            "service": "http",
                            "protocole": "tcp",
                            "state": "open",
                        }
                    ]
                },
                "services_web": [
                    {
                        "url": "http://www.example.com",
                        "final_url": "http://www.example.com",
                        "status_code": 200,
                        "technologies": ["nginx"],
                    }
                ],
            }
        ]
        final_result = {
            "scan_id": "test-scan-id",
            "target": "example.com",
            "scan_date": "2026-05-07T00:00:00Z",
            "subdomains": [],
            "summary": {
                "total_subdomains": 1,
                "total_ips": 1,
                "total_open_ports": 1,
                "total_technologies": 1,
            },
        }

        def fake_trouver(domaine):
            calls.append(("trouver_sous_domaines", domaine))
            return subs

        def fake_resoudre(items):
            calls.append(("resoudre_dns", items))
            return resolved

        def fake_scanner(items):
            calls.append(("scanner_ports", items))
            return scanned

        async def fake_detecter(items):
            calls.append(("detecter_technologies", items))
            return enriched

        def fake_assembler(domaine, items):
            calls.append(("assembler_resultats", domaine, items))
            return final_result

        def fake_save(doc):
            calls.append(("sauvegarder_scan", doc))
            return None

        with patch("pipeline.runner.trouver_sous_domaines", fake_trouver), patch(
            "pipeline.runner.resoudre_dns", fake_resoudre
        ), patch("pipeline.runner.scanner_ports", fake_scanner), patch(
            "pipeline.runner.detecter_technologies", fake_detecter
        ), patch(
            "pipeline.runner.assembler_resultats", fake_assembler
        ), patch(
            "database.mongo_client.sauvegarder_scan", fake_save
        ):
            out = runner.lancer_scan("example.com")

        self.assertEqual(out, final_result)
        self.assertEqual(
            [name for name, *_ in calls],
            [
                "trouver_sous_domaines",
                "resoudre_dns",
                "scanner_ports",
                "detecter_technologies",
                "assembler_resultats",
                "sauvegarder_scan",
            ],
        )


if __name__ == "__main__":
    unittest.main()
