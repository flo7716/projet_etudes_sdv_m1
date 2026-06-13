import contextlib
import os
import shutil
import tempfile
import unittest
from unittest import mock

from app.modules import report as report_module


class ReportLogoTests(unittest.TestCase):
    def test_generate_pdf_report_copies_logo_used_by_template(self):
        temp_root = tempfile.mkdtemp(prefix="report-logo-test-")
        output_path = os.path.join(temp_root, "report.pdf")

        class FakeProcess:
            def __init__(self):
                self.returncode = 0
                self.stdout = ""
                self.stderr = ""

        def fake_run(cmd, cwd, capture_output, text):
            with open(os.path.join(cwd, "report.pdf"), "wb") as handle:
                handle.write(b"%PDF")
            return FakeProcess()

        try:
            with mock.patch(
                "app.modules.report.tempfile.TemporaryDirectory",
                return_value=contextlib.nullcontext(temp_root),
            ), mock.patch("app.modules.report.subprocess.run", side_effect=fake_run):
                result = report_module.generate_pdf_report({}, "Test report", output_path)

            self.assertEqual(result["pdf_path"], output_path)
            self.assertTrue(os.path.exists(os.path.join(temp_root, "swissknife_logo.jpg")))
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
