import unittest
from unittest import mock

from app.modules.sqlmap import _should_prompt_for_sqlmap_output, run_sqlmap


class SqlmapPromptTests(unittest.TestCase):
    def test_detects_sqlmap_yes_no_questions(self):
        self.assertTrue(
            _should_prompt_for_sqlmap_output(
                "Do you want to skip test payloads specific for other DBMSes? [Y/n]"
            )
        )
        self.assertTrue(
            _should_prompt_for_sqlmap_output(
                "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"
            )
        )

    def test_run_sqlmap_prompts_user_instead_of_auto_answering(self):
        class FakeProcess:
            def __init__(self):
                self.stdout = self
                self.stdin = self
                self._lines = [
                    "Do you want to skip test payloads specific for other DBMSes? [Y/n]\n",
                ]
                self.returncode = None

            def readline(self):
                if self._lines:
                    return self._lines.pop(0)
                return ""

            def read(self):
                return ""

            def poll(self):
                return self.returncode

            def wait(self):
                self.returncode = 0
                return 0

            def write(self, data):
                self.written = data

            def flush(self):
                return None

        fake_proc = FakeProcess()

        with mock.patch("app.modules.sqlmap.subprocess.Popen", return_value=fake_proc), \
             mock.patch("app.modules.sqlmap.prompt_text", return_value="y") as prompt_mock:
            result = run_sqlmap("http://example.test")

        self.assertIn("Do you want to skip test payloads specific for other DBMSes? [Y/n]", result["output"])
        self.assertIn("[USER-ANSWER] y", result["output"])
        prompt_mock.assert_called_once()
        self.assertEqual(fake_proc.written, "y\n")


if __name__ == "__main__":
    unittest.main()
