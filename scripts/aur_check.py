"""Host-side orchestration; package code runs only in disposable Arch containers."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import aur_update as core


ENTRIES = {
    'ddns-go-bin': 'usr/bin/ddns-go', 'ecapture-bin': 'usr/bin/ecapture',
    'ifrextractor-rs': 'usr/bin/ifrextractor', 'ifrextractor-rs-bin': 'usr/bin/ifrextractor',
    'intel-mlc': 'usr/bin/mlc', 'nali-nt': 'usr/bin/nali-nt',
    'nali-nt-bin': 'usr/bin/nali-nt', 'nali-nt-git': 'usr/bin/nali-nt',
    'neo4j-community-bin': 'usr/bin/neo4j',
    'opencl-vanity-gpg': 'usr/bin/opencl_vanity_gpg',
    'opencl-vanity-gpg-bin': 'usr/bin/opencl_vanity_gpg', 'wakatime': 'usr/bin/wakatime',
}


def version(recipe, info=None):
    epoch = (info or {}).get('epoch', ['0'])[0]
    return (epoch + ':' if epoch != '0' else '') + core.scalar(recipe, 'pkgver') + '-' + core.scalar(recipe, 'pkgrel')


def reserve(path):
    if path.is_symlink():
        raise ValueError('Workspace must not be a symlink')
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or any(path.iterdir()):
        raise ValueError(f'Workspace must be fresh and empty: {path}')


def snapshot(directory, names):
    result = {}
    for name in names:
        if Path(name).is_absolute() or '..' in Path(name).parts or len(Path(name).parts) != 1:
            raise ValueError('Invalid registry whitelist path')
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'Whitelist file is not a regular file: {path}')
        result[name] = path.read_bytes()
    return result


def populate(directory, files):
    directory.mkdir(parents=True)
    for name, content in files.items():
        (directory / name).write_bytes(content)


def assignment(recipe, key, value):
    # Intel fields have one verified literal-array assignment, never shell input.
    pattern = r'^' + re.escape(key) + r'=\([^\n]*\)[ \t]*$'
    if len(re.findall(pattern, recipe, re.M)) != 1:
        raise ValueError(f'Expected unique single-line {key} array')
    return re.sub(pattern, lambda _: key + '=' + value, recipe, flags=re.M)


def candidate_recipe(recipe, detected, detector):
    fields = detected['fields']
    allowed = {'pkgver'}
    if detector == 'intel-mlc':
        allowed |= {'source', 'sha256sums'}
    elif detector == 'neo4j-community':
        allowed.add('_min_java_version')
    if set(fields) - allowed:
        raise ValueError('Detector returned unauthorized recipe fields')
    for key, value in fields.items():
        if key == 'source':
            if not re.fullmatch(r'\("https://downloadmirror\.intel\.com/[0-9]+/mlc_v[0-9.]+\.tgz"\)', value):
                raise ValueError('Invalid verified Intel source assignment')
            recipe = assignment(recipe, key, value)
        elif key == 'sha256sums':
            if not re.fullmatch(r"\('[0-9a-f]{64}'\)", value):
                raise ValueError('Invalid verified Intel SHA256 assignment')
            recipe = assignment(recipe, key, value)
        else:
            recipe = core.replace_scalar(recipe, key, value)
    if detected['upgrade']:
        recipe = core.replace_scalar(recipe, 'pkgrel', '1')
    return recipe


def moving_source(recipe):
    pattern = r'^source=\(["\'](git\+(?:https?|git)://[^"\'\s#]+)(?:#commit=[0-9a-f]{40})?["\']\)$'
    matches = list(re.finditer(pattern, recipe, re.M))
    if len(matches) != 1:
        raise ValueError('Expected unique moving Git source')
    return pattern, matches[0][1]


def vcs_source(recipe, commit=None):
    pattern, url = moving_source(recipe)
    if commit is not None and not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Invalid upstream commit')
    url += '#commit=' + commit if commit else ''
    return re.sub(pattern, lambda _: f'source=("{url}")', recipe, flags=re.M)


def upstream_head(recipe):
    _, source = moving_source(recipe)
    output = core.run(['git', 'ls-remote', source.removeprefix('git+'), 'HEAD'])
    heads = [parts[0] for line in output.splitlines() if len(parts := line.split()) == 2 and parts[1] == 'HEAD']
    if len(heads) != 1 or not re.fullmatch('[0-9a-f]{40}', heads[0]):
        raise ValueError('Cannot resolve upstream default branch HEAD')
    return heads[0]


class AttemptFailure(RuntimeError):
    def __init__(self, stage, message):
        super().__init__(message)
        self.stage = stage


def attempt(work, logs, row, files, mode, label):
    workspace = work / label
    populate(workspace / 'recipe', files)
    entry = ENTRIES[row['pkgbase']]
    command = ['docker', 'run', '--rm']
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'NO_PROXY', 'no_proxy'):
        command.extend(['-e', key + '='])
    # Bind immutable copies: checkout edits must not change a running Bash stream.
    with tempfile.TemporaryDirectory(prefix='aur-build-entry-') as directory:
        scripts = Path(directory)
        for filename in ('arch-package.sh', 'arch_verify.py'):
            shutil.copyfile(core.ROOT / 'scripts' / filename, scripts / filename)
        command.extend(['--mount', f'type=bind,src={workspace},dst=/work',
                        '--mount', f'type=bind,src={scripts / "arch-package.sh"},dst=/entry.sh,readonly',
                        '--mount', f'type=bind,src={scripts / "arch_verify.py"},dst=/verify.py,readonly',
                        'archlinux:base-devel', 'bash', '/entry.sh', mode, row['pkgbase'], '/' + entry])
        # Only empty proxy variables are passed; never host credentials or tokens.
        with (logs / (label + '.log')).open('w') as stream:
            process = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, text=True)
    output = workspace / 'output'
    stage_path = output / 'stage'
    stage = stage_path.read_text().strip() if stage_path.is_file() else 'initialization'
    if output.is_dir():
        for name in ('stage', 'facts.json'):
            if (output / name).is_file():
                shutil.copyfile(output / name, logs / (label + '-' + name))
    if process.returncode:
        return None, stage, workspace
    if stage != 'complete':
        raise AttemptFailure(stage, 'Container exited successfully without completing verification')
    if mode == 'metadata':
        return {}, stage, workspace
    try:
        facts = json.loads((output / 'facts.json').read_text())
        if facts.get('entry', '').lstrip('/') != entry or facts.get('arch') not in ('x86_64', 'any'):
            raise ValueError('Built package entry or architecture does not match')
        info = core.metadata((workspace / 'recipe/.SRCINFO').read_text())
        if facts.get('pkgname') not in info.get('pkgname', []):
            raise ValueError('Built package name does not match generated metadata')
        actual = version((workspace / 'recipe/PKGBUILD').read_text(), info)
        if facts.get('pkgver') != actual:
            raise ValueError('Built package version does not match recipe and metadata')
        return facts, stage, workspace
    except Exception as exc:
        raise AttemptFailure('package-inspection', str(exc)) from exc


def regenerated(work, logs, row, files, label):
    facts, stage, workspace = attempt(work, logs, row, files, 'metadata', label)
    if facts is None:
        raise AttemptFailure(stage, f'Publication metadata generation failed at {stage}')
    generated = snapshot(workspace / 'recipe', row['files'])
    if any(generated[name] != content for name, content in files.items() if name != '.SRCINFO'):
        raise ValueError('Metadata generation changed recipe or auxiliary files')
    return generated


def check(row, work_dir, result_dir):
    if not row.get('enabled') or row.get('detector') == 'disabled':
        raise ValueError(f"Package disabled: {row['pkgbase']}")
    name = row['pkgbase']
    if name not in ENTRIES:
        raise ValueError('Unknown maintained package')
    work = Path(work_dir).absolute()
    results = Path(result_dir).absolute()
    if work == results or work in results.parents or results in work.parents:
        raise ValueError('Work and result directories must be separate')
    reserve(results)
    package_result = results / name
    package_result.mkdir()
    logs = package_result / 'logs'
    logs.mkdir()
    result = dict(pkgbase=name, status='failed', old_version=None, new_version=None,
                  base_github_sha=None, expected_aur_head=None, files={},
                  stage='initialization', message='Check not completed')
    try:
        reserve(work)
        core.prerequisites()
        original = snapshot(core.ROOT / name, row['files'])
        recipe = original['PKGBUILD'].decode()
        original_info = core.metadata(original['.SRCINFO'].decode())
        result['old_version'] = result['new_version'] = version(recipe, original_info)
        result['base_github_sha'] = core.run(['git', 'rev-parse', 'HEAD'], cwd=core.ROOT)
        if not re.fullmatch('[0-9a-f]{40}', result['base_github_sha']):
            raise ValueError('Invalid GitHub baseline commit')
        state = json.loads((core.ROOT / '.automation/aur-state.json').read_text())
        expected = state.get(name)
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{40}', expected):
            raise ValueError('Missing valid bootstrapped AUR baseline')
        result['expected_aur_head'] = expected
        result['stage'] = 'detection'
        detected = core.inspect_package(row)
        (logs / 'detection.json').write_text(json.dumps(detected, indent=2) + '\n')
        proposed = dict(original)
        proposed['PKGBUILD'] = candidate_recipe(recipe, detected, row['detector']).encode()
        result['new_version'] = version(proposed['PKGBUILD'].decode(), original_info)
        result['stage'] = 'aur-baseline'
        aur = work / 'aur.git'
        core.run(['git', 'clone', '--bare', '--', core.aur_url(name), str(aur)])
        head = core.run(['git', 'rev-parse', 'refs/heads/master'], cwd=aur)
        aur_files = {}
        for filename in row['files']:
            try:
                tree = core.run(['git', 'ls-tree', head, '--', filename], cwd=aur)
                if not tree:
                    aur_files[filename] = None
                    continue
                if not tree.startswith(('100644 blob ', '100755 blob ')):
                    raise ValueError('AUR whitelist contains nonregular file')
                aur_files[filename] = subprocess.run(['git', 'show', head + ':' + filename], cwd=aur,
                                                     check=True, capture_output=True).stdout
            except subprocess.CalledProcessError:
                raise ValueError(f'Cannot read AUR baseline file {filename}')
        if aur_files.get('.SRCINFO') is None:
            raise ValueError('AUR baseline has no .SRCINFO')
        aur_info = core.metadata(aur_files['.SRCINFO'].decode())
        aur_version = (aur_info.get('epoch', ['0'])[0] + ':' if aur_info.get('epoch', ['0'])[0] != '0' else '') + aur_info['pkgver'][0] + '-' + aur_info['pkgrel'][0]
        if core.vercmp(aur_version, result['new_version']) > 0:
            raise ValueError('AUR version is newer; adopt and recheck its recipe before publication')
        result['stage'] = 'initialization'
        mode = 'refresh' if detected['upgrade'] else 'verify'
        aur_recipe = (aur_files.get('PKGBUILD') or b'').decode()
        fix_marker = {
            'nali-nt-bin': '${_pkgname}-${pkgver}-x86_64::',
            'opencl-vanity-gpg': 'cargo fetch --locked --target "$(rustc --print host-tuple)"',
            'ifrextractor-rs-bin': 'ifrextractor_${pkgver}_linux.zip',
        }.get(name)
        if not detected['upgrade'] and fix_marker and fix_marker in recipe and fix_marker not in aur_recipe:
            mode = 'refresh-stable'
        facts, stage, workspace = attempt(work, logs, row, proposed, mode, 'attempt-1')
        result['stage'] = stage
        vcs = row['detector'] == 'vcs-build-first'
        retry = False
        if facts is None:
            if not vcs or stage != 'build':
                raise ValueError(f'Isolated verification failed at {stage}; see attempt-1.log')
            retry = True
            commit = upstream_head(recipe)
            retry_files = dict(original)
            retry_files['PKGBUILD'] = vcs_source(recipe, commit).encode()
            facts, stage, workspace = attempt(work, logs, row, retry_files, 'verify', 'attempt-2')
            result['stage'] = stage
            if facts is None:
                if stage != 'build':
                    raise ValueError(f'VCS retry could not be evaluated: second attempt failed at {stage}, before compiling; see attempt-2.log')
                raise ValueError('Both VCS attempts failed to compile; changing pkgver cannot repair compilation')
            if facts.get('built_source_commit') != commit:
                raise ValueError('Second VCS attempt did not build the freshly resolved commit')
        generated = snapshot(workspace / 'recipe', row['files'])
        for filename in row['files']:
            if filename not in ('PKGBUILD', '.SRCINFO') and generated[filename] != original[filename]:
                raise ValueError('Build changed an auxiliary whitelist file')
        if vcs:
            from arch_verify import normalize_versions
            attempted_recipe = retry_files['PKGBUILD'] if retry else proposed['PKGBUILD']
            if normalize_versions(generated['PKGBUILD'].decode()) != normalize_versions(attempted_recipe.decode()):
                raise ValueError('VCS build modified recipe beyond expected version fields')
            publication = dict(original)
            if retry:
                built = generated['PKGBUILD'].decode()
                if core.vercmp(core.scalar(built, 'pkgver'), core.scalar(recipe, 'pkgver')) < 0:
                    raise ValueError('Retry computed a downgraded VCS version')
                if core.scalar(built, 'pkgver') != core.scalar(recipe, 'pkgver'):
                    publication['PKGBUILD'] = core.replace_scalar(core.replace_scalar(recipe, 'pkgver', core.scalar(built, 'pkgver')), 'pkgrel', '1').encode()
                unpinned = vcs_source(built)
                expected_recipe = vcs_source(publication['PKGBUILD'].decode())
                for key in ('pkgver', 'pkgrel'):
                    unpinned = core.replace_scalar(unpinned, key, core.scalar(unpinned, key))
                    expected_recipe = core.replace_scalar(expected_recipe, key, core.scalar(expected_recipe, key))
                if unpinned != expected_recipe:
                    raise ValueError('VCS build unexpectedly modified the recipe')
            publication = regenerated(work, logs, row, publication, 'publication-metadata')
        else:
            publication = generated
            from arch_verify import strip_checksums
            final_info = core.metadata(publication['.SRCINFO'].decode())
            if strip_checksums(proposed['PKGBUILD'].decode(), original_info) != strip_checksums(publication['PKGBUILD'].decode(), final_info):
                raise ValueError('Build modified candidate beyond checksum arrays')
            if mode == 'verify' and publication['PKGBUILD'] != proposed['PKGBUILD']:
                raise ValueError('Same-version verification modified the recipe')
            if detected.get('expected_sha256') and detected['upgrade']:
                info = core.metadata(publication['.SRCINFO'].decode())
                hashes = info.get('sha256sums', [])
                if not hashes or hashes[0].lower() != detected['expected_sha256'].lower():
                    raise ValueError('Generated source checksum disagrees with authoritative detector')
        result['new_version'] = version(publication['PKGBUILD'].decode(), core.metadata(publication['.SRCINFO'].decode()))
        if core.vercmp(aur_version, result['new_version']) > 0:
            raise ValueError('Validated publication would downgrade AUR')
        different = any(publication[filename] != aur_files[filename] for filename in row['files'])
        if head != expected and different:
            raise ValueError('AUR HEAD conflicts with bootstrapped baseline')
        # Recheck checkout bytes without executing any package code on the host.
        if snapshot(core.ROOT / name, row['files']) != original:
            raise ValueError('Checkout recipe changed while verification was running')
        result['stage'] = 'complete'
        recovery = head != expected and not different
        result['status'] = 'ready' if different or recovery else 'unchanged'
        result['message'] = ('Fully verified whitelist differs from AUR' if different else
                             'Fully verified; AUR content identical, ready to recover state' if recovery else
                             'Fully verified; AUR whitelist already identical')
        if vcs and not retry:
            result['message'] += '; first moving-source build succeeded, automatic version changes discarded'
        if result['status'] == 'ready':
            populate(package_result / 'files', publication)
            result['files'] = {filename: hashlib.sha256(content).hexdigest() for filename, content in publication.items()}
    except Exception as exc:
        result['message'] = str(exc)
        if isinstance(exc, AttemptFailure):
            result['stage'] = exc.stage
        result['status'] = 'failed'
        result['files'] = {}
        # Failed checks never expose a publication snapshot, including copy failures.
        if (package_result / 'files').exists():
            shutil.rmtree(package_result / 'files')
    (package_result / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 1 if result['status'] == 'failed' else 0
