import json
import tempfile
import unittest
from pathlib import Path

from app.scanner import scan_repository


class ScannerTests(unittest.TestCase):
    def test_detects_requested_checks_with_locations_and_severities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "API_KEY = 'sk_live_aB9xQ7mN2pL4vR8tK6zD'\n"
                'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
                "eval(payload)\n",
                encoding="utf-8",
            )
            (root / "view.tsx").write_text("dangerouslySetInnerHTML={{ html }}\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8"
            )
            (root / "requirements.txt").write_text("PyYAML==5.4\n", encoding="utf-8")

            findings, scanned_files = scan_repository(root)

        rules = {finding["rule"] for finding in findings}
        self.assertEqual(scanned_files, 4)
        self.assertTrue(any("Hardcoded high-entropy secret" in rule for rule in rules))
        self.assertTrue(any("SQL query built" in rule for rule in rules))
        self.assertTrue(any("dangerouslySetInnerHTML" in rule for rule in rules))
        self.assertTrue(any("Dynamic eval/exec" in rule for rule in rules))
        self.assertTrue(any("lodash" in rule for rule in rules))
        self.assertTrue(any("PyYAML" in rule for rule in rules))
        self.assertTrue(all({"file", "line_number", "rule", "severity"} <= finding.keys() for finding in findings))


if __name__ == "__main__":
    unittest.main()
