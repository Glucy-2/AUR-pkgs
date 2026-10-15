import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aur_update as update


class ReleaseTests(unittest.TestCase):
    def test_arch_numeric_order(self):
        releases = [{'tag_name': tag, 'draft': False, 'prerelease': False} for tag in ['v1.9', 'v1.10', 'v1.2']]
        self.assertEqual(update.highest_release(releases)['tag_name'], 'v1.10')

    def test_only_stable_numeric_tags(self):
        releases = [{'tag_name': 'v9.0', 'draft': True}, {'tag_name': 'v8.0', 'prerelease': True}, {'tag_name': 'v7.0-rc1'}, {'tag_name': '6.0'}, {'tag_name': 'v01.2'}]
        self.assertEqual(update.highest_release(releases)['tag_name'], 'v01.2')
        self.assertIsNone(update.highest_release(releases[:-1]))

    def test_missing_architecture_asset_rejected(self):
        release = {'tag_name': 'v1.10', 'assets': [{'name': 'app-1.10-x86_64.zip'}]}
        info = {'source_x86_64': ['https://github.com/o/r/releases/download/v1.9/app-1.9-x86_64.zip'], 'source_aarch64': ['https://github.com/o/r/releases/download/v1.9/app-1.9-aarch64.zip']}
        with patch.object(update, 'fetch', return_value=__import__('json').dumps([release]).encode()):
            with self.assertRaisesRegex(ValueError, 'aarch64'):
                update.github_release({'upstream': 'o/r'}, 'pkgver=1.9\n', info)

    def test_disabled_packages_never_fetch(self):
        with patch.object(update, 'fetch', side_effect=AssertionError('Network forbidden')):
            for name in ['honk-core', 'fastflowlm', 'fastflowlm-git', 'sherpa-onnx-bin', 'yukigram-desktop']:
                with self.assertRaisesRegex(ValueError, 'Disabled'):
                    update.packages(name)
            with self.assertRaisesRegex(ValueError, 'Unknown/removed'):
                update.packages('zulu-26-fx-bin')

    def test_unique_top_level_replacement(self):
        with self.assertRaisesRegex(ValueError, 'unique'):
            update.replace_scalar('pkgver=1\npkgver=2\n', 'pkgver', '3')
        self.assertEqual(update.replace_scalar('pkgver=1\npkgdesc="version 1"\n', 'pkgver', '2'), 'pkgver="2"\npkgdesc="version 1"\n')
