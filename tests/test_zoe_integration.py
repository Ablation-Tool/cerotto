import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import unittest


ROOT = Path(__file__).resolve().parents[1]
ZOE_ROOT = ROOT / "zoe"


class ZoeIntegrationTests(unittest.TestCase):
    def test_cerotto_is_the_host_component(self):
        sys.path.insert(0, str(ZOE_ROOT / "guiai-lab"))
        from guiai.gem.unified import ComponentRegistry

        registry = ComponentRegistry(ZOE_ROOT)
        source = registry.source("cerotto")
        self.assertEqual(source["mode"], "host")
        self.assertEqual(source["path"], ROOT)
        self.assertTrue(source["available"])
        for identifier in ("ablation", "gem-lab"):
            bundled = registry.source(identifier)
            self.assertEqual(bundled["mode"], "bundled")
            self.assertEqual(bundled["path"], ZOE_ROOT / "components" / "ablation")
            self.assertTrue(bundled["available"])
        manifest = registry.manifest()
        self.assertEqual(manifest["identity"], "ZOE is allgems")
        self.assertEqual(len(manifest["components"]), 11)
        self.assertTrue(all(row["source"]["source_present"] for row in manifest["components"]))

    def test_zoe_cli_launches_host_cerotto(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ZOE_ROOT / "guiai-lab")
        environment["ZOE_ROOT"] = str(ZOE_ROOT)
        environment["ZOE_CEROTTO_ROOT"] = str(ROOT)
        environment["ZOE_PYTHON"] = sys.executable
        environment["ZOE_PYTHON_DEPENDENCIES"] = sysconfig.get_paths()["purelib"]
        result = subprocess.run(
            [sys.executable, "-m", "guiai.gem.unified_cli", "list"],
            cwd=ROOT, env=environment, check=True, capture_output=True, text=True,
        )
        rows = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 11)
        self.assertEqual(sum("host" in line for line in rows), 1)
        self.assertTrue(all("present" in line for line in rows))
        launch = subprocess.run(
            [sys.executable, "-m", "guiai.gem.unified_cli", "launch", "cerotto", "--", "--help"],
            cwd=ROOT, env=environment, capture_output=True, text=True,
        )
        self.assertEqual(launch.returncode, 0, launch.stdout + launch.stderr)
        self.assertIn("usage: cerotto-gem", launch.stdout)
        source_record = json.loads((ZOE_ROOT / "ZOE-SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual(source_record["revision"], "8ac90bb7364d27eb4814498c93a2b7c00ef109f6")
        self.assertEqual(source_record["host"]["components"], ["cerotto"])


if __name__ == "__main__":
    unittest.main()
