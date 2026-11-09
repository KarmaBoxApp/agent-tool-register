# -*- coding: utf-8 -*-
"""Tests for agent_tool_register. Run:  python3 -m unittest -v test_agent_tool_register.py"""
import contextlib
import io
import json
import os
import shutil
import tempfile
import textwrap
import unittest

import agent_tool_register as atr

FAKE_KEY = "sk-" + "test" + "A1b2C3d4E5f6G7h8"          # placeholder, assembled so the file itself stays clean


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="atr-test-")
        self.reg = os.path.join(self.dir, "agent-tools.json")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def write(self, name, body):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(body))
        return path

    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = atr.main(["--registry", self.reg] + list(argv))
        return code, buf.getvalue()

    def scan(self, body, name="tool.py", globs=None):
        return atr.scan_file(self.write(name, body), globs or atr.DEFAULT_SENSITIVE_GLOBS)


class SystemsDetection(Base):
    def test_plain_script_has_no_findings(self):
        f = self.scan("""
            import csv, statistics
            rows = list(csv.reader(open('my_notes.csv')))
            print(len(rows))
        """)
        self.assertEqual(f["systems"], [])
        self.assertEqual(f["secrets"], [])
        self.assertEqual(f["paths"], [])

    def test_requests_alias_and_smtp(self):
        f = self.scan("""
            import requests as r
            import smtplib
            r.post('https://example.invalid/api', json={})
        """)
        kinds = {s["kind"] for s in f["systems"]}
        self.assertEqual(kinds, {"network", "email"})

    def test_subprocess_and_os_system(self):
        f = self.scan("""
            import os
            from subprocess import run
            os.system('ls')
            run(['ls'])
        """)
        whats = {s["what"] for s in f["systems"]}
        self.assertIn("os.system()", whats)
        self.assertIn("import subprocess", whats)

    def test_from_urllib_request_urlopen(self):
        f = self.scan("""
            from urllib.request import urlopen
            urlopen('https://example.invalid')
        """)
        self.assertIn("urllib.request.urlopen()", {s["what"] for s in f["systems"]})

    def test_dynamic_import_is_missed(self):
        # Known limit, kept as a test so the README stays honest.
        f = self.scan("""
            import importlib
            mod = importlib.import_module('req' + 'uests')
            mod.get('https://example.invalid')
        """)
        self.assertEqual(f["systems"], [])

    def test_shell_script_text_fallback(self):
        f = self.scan("curl -s https://example.invalid/upload -F file=@clients.csv\n", name="push.sh")
        self.assertEqual(f["systems"][0]["what"], "curl")
        self.assertTrue(f["paths"])
        self.assertIn("not Python: text checks only", f["notes"])

    def test_syntax_error_falls_back(self):
        f = self.scan("print 'python 2'\nimport requests\n")
        self.assertTrue(any("could not parse" in n for n in f["notes"]))


class SecretsDetection(Base):
    def test_key_shaped_string_found_but_never_printed(self):
        path = self.write("pull.py", "API = '%s'\n" % FAKE_KEY)
        code, out = self.run_cli("add", path, "--owner", "dana")
        self.assertIn("stored credentials", out)
        code, out = self.run_cli("scan", path)
        self.assertIn("value not shown", out)
        self.assertNotIn(FAKE_KEY, out)
        code, out = self.run_cli("report")
        self.assertNotIn(FAKE_KEY, out)
        with open(self.reg, encoding="utf-8") as fh:
            self.assertNotIn(FAKE_KEY, fh.read())

    def test_hard_coded_password_assignment_and_keyword(self):
        f = self.scan("""
            db_password = 'hunter22'
            connect(host='db', password='hunter22')
        """)
        kinds = {s["kind"] for s in f["secrets"]}
        self.assertIn("hard-coded db_password", kinds)
        self.assertIn("hard-coded password argument", kinds)

    def test_password_from_environment_is_fine(self):
        f = self.scan("""
            import os
            password = os.environ['DB_PASSWORD']
        """)
        self.assertEqual(f["secrets"], [])


class Triggers(Base):
    def test_sensitive_glob_default_and_custom(self):
        f = self.scan("df = open('/data/Clients/positions.csv')\n")
        self.assertEqual(f["paths"][0]["glob"], "*client*")
        f = self.scan("x = open('/mnt/deals/q4.xlsx')\n", globs=["*/deals/*"])
        self.assertEqual(f["paths"][0]["glob"], "*/deals/*")

    def test_messages_mentioning_clients_are_not_paths(self):
        f = self.scan("""
            print('%d client flow rows today' % 3)
            open('clients.xlsx')
        """)
        self.assertEqual(len(f["paths"]), 1)
        self.assertEqual(f["paths"][0]["value"], "clients.xlsx")

    def test_second_user_and_quantitative_are_declared(self):
        path = self.write("est.py", "import pandas\n")
        code, out = self.run_cli("add", path, "--owner", "dana")
        self.assertIn("personal", out)
        self.assertIn("hint: imports numeric libraries", out)
        code, out = self.run_cli("add", path, "--user", "lee", "--quantitative")
        self.assertIn("needs review", out)
        self.assertIn("a second regular user", out)
        self.assertIn("produces quantitative estimates", out)

    def test_same_user_twice_is_still_one_user(self):
        path = self.write("solo.py", "print(1)\n")
        self.run_cli("add", path, "--owner", "dana", "--user", "dana")
        code, out = self.run_cli("list")
        self.assertIn("personal", out)

    def test_review_holds_until_a_new_trigger_appears(self):
        path = self.write("flow.py", "import requests\n")
        self.run_cli("add", path, "--owner", "dana", "--reviewed-by", "sam")
        code, out = self.run_cli("list")
        self.assertIn("reviewed", out)
        self.write("flow.py", "import requests\nopen('/srv/customer_export.csv')\n")
        code, out = self.run_cli("add", path)
        self.assertIn("needs review", out)

    def test_added_sensitive_glob_persists(self):
        path = self.write("a.py", "open('/mnt/deals/q4.xlsx')\n")
        self.run_cli("add", path, "--sensitive-glob", "*/deals/*")
        with open(self.reg, encoding="utf-8") as fh:
            self.assertIn("*/deals/*", json.load(fh)["settings"]["sensitive_globs"])


class Commands(Base):
    def test_scan_directory_json_and_fail_on_trigger(self):
        self.write("tools/clean.py", "print('hi')\n")
        self.write("tools/mailer.py", "import smtplib\n")
        self.write("tools/README.md", "import requests\n")       # not a script, skipped
        code, out = self.run_cli("scan", os.path.join(self.dir, "tools"), "--json", "--fail-on-trigger")
        data = json.loads(out)
        self.assertEqual(len(data), 2)
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.reg), "scan must not write the registry")

    def test_list_empty_and_report_markdown(self):
        code, out = self.run_cli("list")
        self.assertIn("registry is empty", out)
        p1 = self.write("a.py", "print(1)\n")
        p2 = self.write("b.py", "import subprocess\n")
        self.run_cli("add", p1, "--owner", "dana", "--purpose", "tidy my notes")
        self.run_cli("add", p2, "--owner", "lee")
        report = os.path.join(self.dir, "report.md")
        self.run_cli("report", "--out", report)
        with open(report, encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("| Tool | Status | Owner | Users | Triggers |", md)
        self.assertIn("2 registered · 1 need review · 0 reviewed · 1 personal", md)
        self.assertIn("## b", md)
        self.assertNotIn("## a", md)
        self.assertLess(md.index("| b |"), md.index("| a |"))

    def test_add_missing_file_errors(self):
        with self.assertRaises(SystemExit):
            self.run_cli("add", os.path.join(self.dir, "nope.py"))


if __name__ == "__main__":
    unittest.main()
