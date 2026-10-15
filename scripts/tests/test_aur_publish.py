import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aur_publish as publisher
import aur_update as core

PKG = 'demo'
FILES = ['PKGBUILD', '.SRCINFO', 'demo.install']
IDENT = ['-c', 'user.name=Tester', '-c', 'user.email=t@example.org', '-c', 'commit.gpgsign=false']


def git(*args, cwd=None):
    return subprocess.run(['git', *args], cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def srcinfo(pkgver, pkgrel='1', pkgbase=PKG):
    return f'pkgbase = {pkgbase}\n\tpkgver = {pkgver}\n\tpkgrel = {pkgrel}\n\npkgname = {pkgbase}\n'


def recipe(pkgver):
    return {'PKGBUILD': f'pkgname={PKG}\npkgver={pkgver}\npkgrel=1\n', '.SRCINFO': srcinfo(pkgver), 'demo.install': 'post_install() { :; }\n'}


class PublishTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.old_root = core.ROOT
        core.ROOT = self.tmp / 'root'
        self.addCleanup(setattr, core, 'ROOT', self.old_root)
        (core.ROOT / '.automation').mkdir(parents=True)
        (core.ROOT / '.automation/packages.json').write_text(json.dumps([
            {'pkgbase': PKG, 'enabled': True, 'detector': 'github-release', 'upstream': 'x/y', 'files': FILES},
            {'pkgbase': 'other', 'enabled': True, 'detector': 'github-release', 'upstream': 'x/z', 'files': ['PKGBUILD', '.SRCINFO']},
        ]))
        os.environ.pop('GITHUB_STEP_SUMMARY', None)
        self.remote = self.tmp / 'aur.git'
        git('init', '--bare', '-b', 'master', str(self.remote))
        self.seed = self.tmp / 'seed'
        git('clone', '--quiet', str(self.remote), str(self.seed))
        self.commit_files(recipe('1.0'), 'initial')
        self.first = self.head()
        self.results = self.tmp / 'results'

    def commit_files(self, files, message):
        for name, text in files.items():
            (self.seed / name).write_text(text)
        git('add', '-A', cwd=self.seed)
        git(*IDENT, 'commit', '--quiet', '-m', message, cwd=self.seed)
        git('push', '--quiet', 'origin', 'HEAD:master', cwd=self.seed)

    def head(self):
        return git('--git-dir', str(self.remote), 'rev-parse', 'refs/heads/master')

    def count(self):
        return int(git('--git-dir', str(self.remote), 'rev-list', '--count', 'master'))

    def make_result(self, files=None, expected=None, pkgbase=PKG, status='ready', digests=None, extra=None):
        files = files or recipe('2.0')
        directory = self.results / PKG
        if directory.exists():
            import shutil
            shutil.rmtree(directory)
        (directory / 'files').mkdir(parents=True)
        for name, text in files.items():
            (directory / 'files' / name).write_text(text)
        recorded = {n: hashlib.sha256(t.encode()).hexdigest() for n, t in files.items()}
        recorded.update(digests or {})
        (directory / 'result.json').write_text(json.dumps(dict(
            pkgbase=pkgbase, status=status, old_version='1.0-1', new_version='2.0-1', base_github_sha='0' * 40,
            expected_aur_head=expected or self.first, files=recorded, stage='done', message='ok', **(extra or {}))))
        return directory

    def publish(self, dry_run=False):
        args = Namespace(results_dir=str(self.results), package=PKG, dry_run=dry_run, aur_remote_url=str(self.remote))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = publisher.publish(args)
        return code, out.getvalue(), err.getvalue()

    def test_publishes_on_top_of_history(self):
        self.make_result()
        code, out, _ = self.publish()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.count(), 2)
        self.assertEqual(git('--git-dir', str(self.remote), 'rev-parse', 'master~1'), self.first)
        self.assertEqual(git('--git-dir', str(self.remote), 'log', '-1', '--format=%s|%an|%ae', 'master'), 'Update demo to 2.0-1|Glucy2|glucy-2@outlook.com')
        self.assertEqual(git('--git-dir', str(self.remote), 'show', 'master:.SRCINFO') + '\n', srcinfo('2.0'))
        self.assertIn('pushed', out)

    def test_rerun_is_idempotent(self):
        self.make_result()
        self.assertEqual(self.publish()[0], 0)
        after = self.head()
        code, out, _ = self.publish()  # stale expected head, identical content
        self.assertEqual(code, 0, out)
        self.make_result(expected=after)
        self.assertEqual(self.publish()[0], 0)
        self.assertEqual(self.head(), after)
        self.assertEqual(self.count(), 2)

    def test_moved_head_different_content_is_conflict(self):
        self.commit_files({'PKGBUILD': 'pkgname=demo\npkgver=1.5\npkgrel=1\n'}, 'external')
        external = self.head()
        self.make_result()
        code, out, _ = self.publish()
        self.assertEqual(code, 1)
        self.assertIn('conflict', out)
        self.assertEqual(self.head(), external)

    def test_moved_head_identical_content_recovers(self):
        self.commit_files(recipe('2.0'), 'published elsewhere')
        moved = self.head()
        self.make_result()
        code, out, _ = self.publish()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.head(), moved)
        self.assertEqual(self.count(), 2)
        self.assertIn('unchanged', out)

    def test_dry_run_changes_nothing_and_prints_diff(self):
        self.make_result()
        code, out, _ = self.publish(dry_run=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.head(), self.first)
        self.assertIn('Update demo to 2.0-1', out)
        self.assertIn('+pkgver=2.0', out)
        self.assertIn('-pkgver=1.0', out)
        self.assertFalse((core.ROOT / '.automation/aur-state.json').exists())

    def assert_rejected(self, expected_text=None):
        code, out, err = self.publish()
        self.assertEqual(code, 1, out)
        self.assertIn('failed', out)
        self.assertEqual(self.head(), self.first)
        if expected_text:
            self.assertIn(expected_text, err)

    def test_extra_file_rejected(self):
        directory = self.make_result()
        (directory / 'files' / 'evil.sh').write_text('x')
        self.assert_rejected('whitelist')

    def test_missing_file_rejected(self):
        directory = self.make_result()
        (directory / 'files' / 'demo.install').unlink()
        self.assert_rejected('whitelist')

    def test_symlink_rejected(self):
        directory = self.make_result()
        target = self.tmp / 'outside'
        target.write_text(recipe('2.0')['demo.install'])
        (directory / 'files' / 'demo.install').unlink()
        (directory / 'files' / 'demo.install').symlink_to(target)
        self.assert_rejected()

    def test_hash_mismatch_rejected(self):
        self.make_result(digests={'PKGBUILD': '0' * 64})
        self.assert_rejected('SHA256 mismatch')

    def test_path_traversal_rejected(self):
        directory = self.make_result()
        result = json.loads((directory / 'result.json').read_text())
        result['files']['../evil'] = result['files'].pop('demo.install')
        (directory / 'result.json').write_text(json.dumps(result))
        self.assert_rejected('whitelist')

    def test_wrong_pkgbase_rejected(self):
        self.make_result(pkgbase='other')
        self.assert_rejected('does not match')

    def test_srcinfo_pkgbase_mismatch_rejected(self):
        files = recipe('2.0')
        files['.SRCINFO'] = srcinfo('2.0', pkgbase='other')
        self.make_result(files=files)
        self.assert_rejected('pkgbase')

    def test_failed_result_not_published(self):
        self.make_result(status='failed')
        self.assert_rejected('not ready')

    def test_step_summary_written(self):
        summary = self.tmp / 'summary.md'
        os.environ['GITHUB_STEP_SUMMARY'] = str(summary)
        self.addCleanup(os.environ.pop, 'GITHUB_STEP_SUMMARY', None)
        self.make_result()
        self.publish()
        self.assertIn('| demo | pushed |', summary.read_text())

    def test_check_unchanged_result_reported(self):
        self.make_result(status='unchanged')
        code, out, _ = self.publish()
        self.assertEqual(code, 0)
        self.assertIn('unchanged', out)
        self.assertEqual(self.head(), self.first)

    def test_missing_key_blocks(self):
        saved = os.environ.pop('AUR_SSH_KEY_FILE', None)
        if saved:
            self.addCleanup(os.environ.__setitem__, 'AUR_SSH_KEY_FILE', saved)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(publisher.Blocked):
                publisher.Ssh(tmp).get()


if __name__ == '__main__':
    unittest.main()
