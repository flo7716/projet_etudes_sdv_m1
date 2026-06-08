import unittest

from app.modules.john import build_john_options


class JohnModeSelectionTests(unittest.TestCase):
    def test_windows_hash_adds_nt_format(self):
        options = build_john_options("Windows hash", "")

        self.assertIn("--format=nt", options)

    def test_single_crack_adds_single_mode(self):
        options = build_john_options("Single crack", "")

        self.assertIn("--single", options)

    def test_basic_hash_keeps_default_options(self):
        options = build_john_options("Basic hash", "--show")

        self.assertIn("--show", options)
        self.assertNotIn("--single", options)


if __name__ == "__main__":
    unittest.main()
