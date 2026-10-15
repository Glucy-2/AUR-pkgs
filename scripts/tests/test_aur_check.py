import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aur_check as check


class CheckBoundaryTests(unittest.TestCase):
    def test_disabled_creates_no_workspace_or_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / 'work'
            results = Path(directory) / 'results'
            with patch.object(check.core, 'prerequisites', side_effect=AssertionError('No execution')):
                with self.assertRaisesRegex(ValueError, 'disabled'):
                    check.check({'pkgbase': 'honk-core', 'enabled': False}, work, results)
            self.assertFalse(work.exists())
            self.assertFalse(results.exists())

    def test_initialization_failure_has_complete_nonpublishable_result(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / 'work'
            results = Path(directory) / 'results'
            with patch.object(check.core, 'prerequisites', side_effect=RuntimeError('Docker unavailable')):
                code = check.check({'pkgbase': 'wakatime', 'enabled': True}, work, results)
            result = json.loads((results / 'wakatime/result.json').read_text())
            self.assertEqual(code, 1)
            self.assertEqual(set(result), {'pkgbase', 'status', 'old_version', 'new_version',
                                          'base_github_sha', 'expected_aur_head', 'files', 'stage', 'message'})
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['stage'], 'initialization')
            self.assertEqual(result['files'], {})
            self.assertFalse((results / 'wakatime/files').exists())

    def test_candidate_replaces_only_authorized_unique_assignments(self):
        original = 'pkgver=1.0\npkgrel=3\npkgdesc="version 1.0"\n'
        detected = {'fields': {'pkgver': '1.1'}, 'upgrade': True}
        updated = check.candidate_recipe(original, detected, 'github-release')
        self.assertIn('pkgdesc="version 1.0"', updated)
        self.assertIn('pkgrel="1"', updated)
        with self.assertRaisesRegex(ValueError, 'unique'):
            check.candidate_recipe(original + 'pkgver=2\n', detected, 'github-release')
        with self.assertRaisesRegex(ValueError, 'unauthorized'):
            check.candidate_recipe(original, {'fields': {'url': 'evil'}, 'upgrade': True}, 'github-release')

    def test_intel_arrays_reject_ambiguous_assignments(self):
        digest = 'a' * 64
        detected = {'upgrade': True, 'fields': {
            'pkgver': '3.13', 'source': '("https://downloadmirror.intel.com/926327/mlc_v3.13.tgz")',
            'sha256sums': "('" + digest + "')"}}
        recipe = 'pkgver=3.12\npkgrel=1\nsource=("old")\nsha256sums=("old")\n'
        updated = check.candidate_recipe(recipe, detected, 'intel-mlc')
        self.assertIn(digest, updated)
        with self.assertRaisesRegex(ValueError, 'unique'):
            check.candidate_recipe(recipe + 'source=("second")\n', detected, 'intel-mlc')

    def test_vcs_resolves_recipe_remote_and_restores_moving_source(self):
        recipe = 'source=("git+git://host.containers.internal:19419/nali.git")\n'
        commit = 'a' * 40
        pinned = check.vcs_source(recipe, commit)
        self.assertEqual(check.vcs_source(pinned), recipe)
        advertisement = 'b' * 40 + '\trefs/remotes/origin/HEAD\n' + commit + '\tHEAD\n'
        with patch.object(check.core, 'run', return_value=advertisement):
            self.assertEqual(check.upstream_head(recipe), commit)

    def test_snapshot_rejects_symlinks_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'real').write_text('recipe')
            (root / 'PKGBUILD').symlink_to(root / 'real')
            with self.assertRaisesRegex(ValueError, 'regular'):
                check.snapshot(root, ['PKGBUILD'])
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                check.snapshot(root, ['../real'])
