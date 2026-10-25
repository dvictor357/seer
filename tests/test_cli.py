"""Every entry script starts and prints --help in isolated mode (-I), the way README runs them."""
import os
import subprocess
import sys
import unittest

import support

SCRIPTS = ("analyze", "screener", "picker", "lp_fees", "lp_range", "contract_dossier", "onchain_check")


class CliTest(unittest.TestCase):
    def test_help(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                p = subprocess.run([sys.executable, "-I", "-B", os.path.join(support.SCRIPTS, name + ".py"), "--help"],
                                   env=support.clean_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, timeout=60)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("usage", p.stdout.lower())

    def test_lp_range_offline_calculator(self):
        p = subprocess.run([sys.executable, "-I", "-B", os.path.join(support.SCRIPTS, "lp_range.py"),
                            "--price", "0.00125", "--fee", "0.3", "--vol24", "160000", "--liq", "65000",
                            "--sigma-1h", "3.5", "--json"],
                           env=support.clean_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("capital_efficiency", p.stdout)


if __name__ == "__main__":
    unittest.main()
