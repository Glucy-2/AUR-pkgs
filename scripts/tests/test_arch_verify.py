from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import arch_verify


class PackageMetadataTests(unittest.TestCase):
    def test_empty_optional_pkginfo_fields_are_valid(self):
        fields = arch_verify.metadata('pkgname = example\npkgver = 1.2-3\nurl = \narch = x86_64\n')
        self.assertEqual(fields['url'], [''])
        self.assertEqual(arch_verify.one(fields, 'pkgver'), '1.2-3')

    def test_malformed_pkginfo_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Malformed'):
            arch_verify.metadata('pkgver 1.2-3\n')
