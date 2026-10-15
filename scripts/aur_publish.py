"""Trusted AUR publication from validated check results.

Never executes PKGBUILD or artifact content; only whitelisted regular files are copied.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile

import aur_update as core

AUR_FINGERPRINT = 'SHA256:RFzBCUItH9LZS0cKB5UE6ceAYhBD5C8GeOBip8Z11+4'
GITHUB_FINGERPRINT = 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU'
GITHUB_HOST_LINE = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
GITHUB_PUSH_URL = 'git@github.com:Glucy-2/AUR-pkgs.git'
AUTHOR = ('Glucy2', 'glucy-2@outlook.com')
SAFE_NAME = re.compile(r'[A-Za-z0-9.][A-Za-z0-9._+-]*')
SHA1 = re.compile(r'[0-9a-f]{40}')
SHA256 = re.compile(r'[0-9a-f]{64}')
FAILING = {'failed', 'blocked-permission', 'conflict'}


class Blocked(Exception):
    pass


class Conflict(Exception):
    pass


def git(args, cwd=None, env=None, check=True):
    proc = subprocess.run(['git', *args], cwd=cwd, env=env, text=True, capture_output=True)
    if check and proc.returncode:
        detail = (proc.stderr.strip() or proc.stdout.strip() or f'exit {proc.returncode}')
        raise RuntimeError(f"git {args[0]} failed: {detail}")
    return proc


def base_env(extra=None):
    env = dict(os.environ)
    env['GIT_TERMINAL_PROMPT'] = '0'
    env.update(extra or {})
    return env


class Ssh:
    """Lazily builds the restricted GIT_SSH_COMMAND with verified host keys."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.env = None
        self.error = None

    def get(self):
        if self.env is not None:
            return self.env
        if self.error:
            raise self.error
        try:
            self.env = self._build()
        except Exception as exc:
            self.error = exc
            raise
        return self.env

    @staticmethod
    def _fingerprint(line):
        proc = subprocess.run(['ssh-keygen', '-lf', '-', '-E', 'sha256'], input=line + '\n', text=True, capture_output=True)
        match = re.search(r'SHA256:\S+', proc.stdout) if proc.returncode == 0 else None
        return match.group(0) if match else None

    def _build(self):
        key = os.environ.get('AUR_SSH_KEY_FILE')
        if not key:
            raise Blocked('AUR_SSH_KEY_FILE is not set; no SSH write key available')
        if not os.path.isfile(key):
            raise Blocked('AUR_SSH_KEY_FILE does not point to a readable key file')
        if self._fingerprint(GITHUB_HOST_LINE) != GITHUB_FINGERPRINT:
            raise RuntimeError('GitHub host key line does not match the official fingerprint')
        scan = subprocess.run(['ssh-keyscan', '-t', 'ed25519', 'aur.archlinux.org'], text=True, capture_output=True, timeout=60)
        aur_lines = [l for l in scan.stdout.splitlines() if l and not l.startswith('#')]
        aur_lines = [l for l in aur_lines if len(l.split()) >= 3 and l.split()[1] == 'ssh-ed25519']
        verified = [l for l in aur_lines if self._fingerprint(l) == AUR_FINGERPRINT]
        if not verified:
            raise RuntimeError('Could not obtain an AUR ed25519 host key matching the pinned fingerprint')
        known = self.tmp / 'known_hosts'
        known.write_text('\n'.join(verified[:1] + [GITHUB_HOST_LINE]) + '\n')
        command = ' '.join(['ssh', '-F', '/dev/null', '-i', shlex.quote(key), '-o', 'IdentitiesOnly=yes',
                            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + shlex.quote(str(known)),
                            '-o', 'HostKeyAlgorithms=ssh-ed25519'])
        return base_env({'GIT_SSH_COMMAND': command})


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f'Not a regular file: {path.name}')
        with os.fdopen(fd, 'rb') as handle:
            fd = None
            return handle.read()
    finally:
        if fd is not None:
            os.close(fd)


def load_candidate(row, results, override):
    """Validate one ready result; return (result, {name: bytes})."""
    name = row['pkgbase']
    if not row.get('enabled'):
        raise ValueError('Package is not enabled')
    whitelist = row['files']
    if len(set(whitelist)) != len(whitelist) or not all(SAFE_NAME.fullmatch(n) and n not in ('.', '..') for n in whitelist):
        raise ValueError('Registry whitelist contains unsafe or duplicate names')
    directory = results / name
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Result directory missing or not a plain directory')
    result_file = directory / 'result.json'
    result = json.loads(read_regular(result_file).decode())
    if not isinstance(result, dict):
        raise ValueError('Malformed result.json')
    if result.get('pkgbase') != name:
        raise ValueError(f"Result pkgbase {result.get('pkgbase')!r} does not match {name!r}")
    if result.get('status') != 'ready':
        raise ValueError(f"Result status is {result.get('status')!r}, not ready")
    if not isinstance(result.get('expected_aur_head'), str) or not SHA1.fullmatch(result['expected_aur_head']):
        raise ValueError('Invalid expected_aur_head')
    declared = result.get('files')
    if not isinstance(declared, dict) or set(declared) != set(whitelist):
        raise ValueError('Result files differ from the registry whitelist')
    files_dir = directory / 'files'
    if files_dir.is_symlink() or not files_dir.is_dir():
        raise ValueError('Result files directory missing or not a plain directory')
    present = {entry.name for entry in os.scandir(files_dir)}
    if present != set(whitelist):
        raise ValueError(f'Result files directory differs from whitelist: extra {sorted(present - set(whitelist))}, missing {sorted(set(whitelist) - present)}')
    content = {}
    for filename in whitelist:
        expected = declared[filename]
        if not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ValueError(f'Invalid recorded digest for {filename}')
        try:
            data = read_regular(files_dir / filename)
        except OSError as exc:
            raise ValueError(f'Unsafe or unreadable file {filename}: {exc.strerror or exc}')
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'SHA256 mismatch for {filename}')
        content[filename] = data
    if '.SRCINFO' not in content or 'PKGBUILD' not in content:
        raise ValueError('Candidate lacks PKGBUILD or .SRCINFO')
    info = core.metadata(content['.SRCINFO'].decode())
    if info.get('pkgbase', [None])[0] != name:
        raise ValueError('.SRCINFO pkgbase does not match')
    if 'pkgver' not in info or 'pkgrel' not in info:
        raise ValueError('.SRCINFO lacks pkgver/pkgrel')
    result['_version'] = f"{info['pkgver'][0]}-{info['pkgrel'][0]}"
    if not override:
        check_github_baseline(name, result)
    return result, content


def check_github_baseline(name, result):
    base = result.get('base_github_sha')
    if not isinstance(base, str) or not SHA1.fullmatch(base):
        raise ValueError('Invalid base_github_sha')
    state = json.loads((core.ROOT / '.automation/aur-state.json').read_text())
    if state.get(name) != result['expected_aur_head']:
        raise ValueError('expected_aur_head is stale versus .automation/aur-state.json; recheck required')
    if git(['cat-file', '-e', base + '^{commit}'], cwd=core.ROOT, check=False).returncode:
        raise Conflict('Check baseline commit is unknown to this checkout; recheck required')
    diff = git(['diff', '--quiet', base, 'HEAD', '--', name], cwd=core.ROOT, check=False)
    if diff.returncode == 1:
        raise Conflict('GitHub main changed this package since the check; recheck required')
    if diff.returncode:
        raise RuntimeError('Cannot compare GitHub baseline: ' + diff.stderr.strip())


def clone_files(clone, whitelist):
    found = {}
    for filename in whitelist:
        path = Path(clone) / filename
        try:
            found[filename] = read_regular(path)
        except (FileNotFoundError, OSError):
            found[filename] = None
    return found


def publish_one(row, results, args, ssh, tmp):
    name = row['pkgbase']
    override = args.aur_remote_url
    result, content = load_candidate(row, results, override)
    version = result['_version']
    expected = result['expected_aur_head']
    read_url = override or core.aur_url(name)
    clone = Path(tmp) / f'clone-{name}'
    git(['clone', '--quiet', '--branch', 'master', '--', read_url, str(clone)], env=base_env())
    head = git(['rev-parse', 'HEAD'], cwd=clone).stdout.strip()
    if head != expected:
        if clone_files(clone, row['files']) == content:
            return dict(status='unchanged', version=version, state=head, files=content,
                        message=f'Already published at {head[:12]}; state recovered')
        raise Conflict(f'AUR master moved ({expected[:12]} -> {head[:12]}) with different content; not overwriting')
    for filename, data in content.items():
        path = clone / filename
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            raise ValueError(f'AUR repository has a directory named {filename}')
        path.write_bytes(data)
    git(['add', '--', *row['files']], cwd=clone)
    if git(['diff', '--cached', '--quiet'], cwd=clone, check=False).returncode == 0:
        return dict(status='unchanged', version=version, state=head, files=content, message='AUR already matches candidate')
    if args.dry_run:
        print(f'--- {name}: proposed "Update {name} to {version}" on {head[:12]}')
        print(git(['diff', '--cached', '--no-color', '--no-ext-diff'], cwd=clone).stdout, end='')
        return dict(status='dry-run', version=version, message=f'Would commit Update {name} to {version}')
    try:
        env = None if override else ssh.get()
    except Blocked as exc:
        return dict(status='blocked-permission', version=version, message=str(exc))
    message = f'Update {name} to {version}'
    git(['-c', f'user.name={AUTHOR[0]}', '-c', f'user.email={AUTHOR[1]}', '-c', 'commit.gpgsign=false',
         'commit', '--quiet', '-m', message], cwd=clone)
    git(['fetch', '--quiet', 'origin', 'master'], cwd=clone, env=base_env())
    if git(['rev-parse', 'FETCH_HEAD'], cwd=clone).stdout.strip() != head:
        raise Conflict('AUR master moved during publication; not pushing')
    push_url = override or f'ssh://aur@aur.archlinux.org/{name}.git'
    if not override:
        git(['remote', 'set-url', '--push', 'origin', push_url], cwd=clone)
    push = git(['push', 'origin', 'HEAD:master'], cwd=clone, env=env or base_env(), check=False)
    if push.returncode:
        detail = push.stderr.strip()
        if re.search(r'permission denied|publickey|not allowed|access denied', detail, re.I):
            return dict(status='blocked-permission', version=version, message='AUR rejected the SSH key: ' + detail.splitlines()[-1])
        raise RuntimeError('git push failed: ' + detail)
    new = git(['rev-parse', 'HEAD'], cwd=clone).stdout.strip()
    remote = git(['ls-remote', push_url, 'refs/heads/master'], cwd=clone, env=env or base_env()).stdout.split()
    if not remote or remote[0] != new:
        raise RuntimeError('Remote master does not match pushed commit after push')
    return dict(status='pushed', version=version, state=remote[0], files=content, message=message)


def write_summary(rows):
    lines = ['| package | status | version | message |', '| --- | --- | --- | --- |']
    for row in rows:
        cells = [row['pkgbase'], row['status'], row.get('version') or '-', row.get('message') or '']
        lines.append('| ' + ' | '.join(str(c).replace('|', '\\|').replace('\n', ' ') for c in cells) + ' |')
    text = '\n'.join(lines) + '\n'
    print(text, end='')
    target = os.environ.get('GITHUB_STEP_SUMMARY')
    if target:
        with open(target, 'a') as handle:
            handle.write('## AUR publication\n\n' + text)


def write_back(outcomes, ssh):
    """Record state and recipes for successful/consistent packages; fast-forward push to GitHub main."""
    done = [o for o in outcomes if o['status'] in ('pushed', 'unchanged') and o.get('state')]
    if not done:
        return True
    state_path = core.ROOT / '.automation/aur-state.json'
    state = json.loads(state_path.read_text())
    changed = []
    for outcome in done:
        name = outcome['pkgbase']
        if state.get(name) != outcome['state']:
            state[name] = outcome['state']
        row = next(r for r in core.registry() if r['pkgbase'] == name)
        for filename, data in outcome['files'].items():
            path = core.ROOT / name / filename
            if not path.exists() or path.read_bytes() != data:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        changed += [f'{name}/{f}' for f in row['files']]
    rendered = json.dumps(state, indent=2) + '\n'
    if not state_path.exists() or state_path.read_text() != rendered:
        state_path.write_text(rendered)
    paths = ['.automation/aur-state.json'] + changed
    git(['add', '--', *paths], cwd=core.ROOT)
    if git(['diff', '--cached', '--quiet', '--', *paths], cwd=core.ROOT, check=False).returncode == 0:
        return True
    try:
        env = ssh.get()
    except Blocked as exc:
        print(f'blocked-permission: cannot write GitHub state: {exc}', file=sys.stderr)
        return False
    try:
        git(['-c', f'user.name={AUTHOR[0]}', '-c', f'user.email={AUTHOR[1]}', '-c', 'commit.gpgsign=false',
             'commit', '--quiet', '-m', 'Update AUR state and recipes [skip ci]', '--', *paths], cwd=core.ROOT)
        git(['push', GITHUB_PUSH_URL, 'HEAD:refs/heads/main'], cwd=core.ROOT, env=env)
    except Exception as exc:
        print(f'failed: GitHub write-back: {exc}', file=sys.stderr)
        return False
    return True


def publish(args):
    rows = core.packages(args.package)
    override = args.aur_remote_url
    if override and len(rows) != 1:
        raise ValueError('Test remote requires a single explicit package')
    results = Path(args.results_dir)
    outcomes = []
    with tempfile.TemporaryDirectory(prefix='aur-publish-') as tmp:
        ssh = Ssh(tmp)
        for row in rows:
            name = row['pkgbase']
            outcome = dict(pkgbase=name)
            try:
                result_file = results / name / 'result.json'
                status = None
                if result_file.is_file() and not result_file.is_symlink():
                    data = json.loads(result_file.read_text())
                    status = data.get('status') if isinstance(data, dict) and data.get('pkgbase') == name else None
                    if status == 'unchanged':
                        outcome.update(status='unchanged', version=data.get('new_version'), message=data.get('message') or 'No update')
                if 'status' not in outcome:
                    outcome.update(publish_one(row, results, args, ssh, tmp))
            except Conflict as exc:
                outcome.update(status='conflict', message=str(exc))
            except Exception as exc:
                outcome.update(status='failed', message=str(exc))
            print(f"{name}: {outcome['status']}: {outcome.get('message', '')}", file=sys.stderr)
            outcomes.append(outcome)
        ok = True
        if not args.dry_run and not override:
            # Only state/recipe-consistent outcomes with a recorded remote SHA are written back.
            ok = write_back([o for o in outcomes if o.get('files') is not None], ssh)
        write_summary(outcomes)
    return 0 if ok and not any(o['status'] in FAILING for o in outcomes) else 1
