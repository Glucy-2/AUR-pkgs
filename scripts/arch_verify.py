#!/usr/bin/env python3
"""Read-only recipe/package audits inside the disposable Arch build container."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tarfile
import urllib.parse

WORK = Path('/work')
RECIPE = WORK / 'recipe'
OUTPUT = WORK / 'output'
ALGORITHMS = {'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64,
              'sha384': 96, 'sha512': 128, 'b2': 128}
SUM_KEY = re.compile(r'^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[A-Za-z0-9_]+)?$')
SUM_ARRAY = re.compile(
    r'(?m)^[ \t]*(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[A-Za-z0-9_]+)?=\('
    r'''(?:\s|'(?:[0-9a-fA-F]+|SKIP)'|"(?:[0-9a-fA-F]+|SKIP)")*'''
    r'\)[ \t]*(?:#[^\n]*)?(?:\n|$)')


VCS_PACKAGES = {'nali-nt-git', 'mcping-git'}

def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def metadata(text):
    fields = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_]+) = ?(.*)', stripped)
        require(match is not None, f'Malformed metadata line: {line}')
        key, value = match.groups()
        fields.setdefault(key, []).append(value)
    return fields


def info(path):
    return metadata(Path(path).read_text())


def one(fields, key):
    values = fields.get(key, [])
    require(len(values) == 1, f'Expected unique metadata {key}')
    return values[0]


def version(fields):
    epoch = fields.get('epoch', ['0'])
    require(len(epoch) == 1 and epoch[0].isdigit(), 'Invalid epoch')
    prefix = f'{epoch[0]}:' if int(epoch[0]) else ''
    return prefix + one(fields, 'pkgver') + '-' + one(fields, 'pkgrel')


def compare(left, right):
    result = int(command(['vercmp', left, right]))
    require(result in (-1, 0, 1), 'Invalid vercmp result')
    return result


def recipe_files():
    files = {}
    for path in RECIPE.iterdir():
        require(not path.is_symlink() and path.is_file(), f'Non-regular recipe file: {path.name}')
        files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    require('PKGBUILD' in files and '.SRCINFO' in files, 'Recipe needs PKGBUILD and original .SRCINFO')
    return files


def snapshot(path):
    data = {'files': recipe_files(), 'pkgbuild': (RECIPE / 'PKGBUILD').read_text(),
            'srcinfo': (RECIPE / '.SRCINFO').read_text()}
    Path(path).write_text(json.dumps(data, indent=2) + '\n')


def load_snapshot(path):
    return json.loads(Path(path).read_text())


def audit_files(saved, allowed):
    current = recipe_files()
    require(current.keys() == saved['files'].keys(), 'Recipe file set changed during container execution')
    for name, digest in current.items():
        if name not in allowed:
            require(digest == saved['files'][name], f'Unexpected recipe rewrite: {name}')


def identity(fields, pkgbase):
    require(one(fields, 'pkgbase') == pkgbase, 'Generated pkgbase does not match requested package')
    require(fields.get('pkgname') == [pkgbase], 'Unexpected package name or split package')
    version(fields)
    arches = fields.get('arch', [])
    require(arches and len(set(arches)) == len(arches), 'Missing or duplicate declared architecture')
    require(all(re.fullmatch(r'[A-Za-z0-9_]+', arch) for arch in arches), 'Unsafe architecture')
    require(arches == ['any'] or ('any' not in arches and 'x86_64' in arches),
            'Recipe cannot be built for x86_64')


def source_groups(fields):
    return {key: values for key, values in fields.items() if key == 'source' or key.startswith('source_')}


def source_location(source):
    return source.split('::', 1)[-1]


def local_source(source):
    location = source_location(source)
    if '://' in location or re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', location):
        return None
    path = PurePosixPath(location)
    require(not path.is_absolute() and len(path.parts) == 1 and path.name not in ('.', '..'),
            f'Unsafe local source path: {location}')
    return path.name


def checksum_schema(pkgbase, fields):
    identity(fields, pkgbase)
    groups = source_groups(fields)
    require(groups, 'No declared source arrays')
    expected = {'sha512', 'b2'} if pkgbase == 'wakatime' else {'sha256'}
    sums = {}
    for key, values in fields.items():
        match = SUM_KEY.fullmatch(key)
        if not match:
            require('sums' not in key, f'Unknown checksum field: {key}')
            continue
        algorithm, suffix = match.groups()
        group = 'source' + (suffix or '')
        require(group in groups, f'Checksum array without sources: {key}')
        require(len(values) == len(groups[group]), f'Source/checksum count mismatch: {key}')
        require(algorithm in expected, f'Unexpected checksum algorithm: {key}')
        sums.setdefault(group, set()).add(algorithm)
        for source, digest in zip(groups[group], values):
            if digest == 'SKIP':
                require(pkgbase in VCS_PACKAGES and source_location(source).startswith('git+'),
                        f'Unapproved SKIP checksum: {source}')
            else:
                require(re.fullmatch(r'[0-9a-fA-F]{' + str(ALGORITHMS[algorithm]) + '}', digest),
                        f'Invalid {algorithm} checksum for {source}')
    for group, sources in groups.items():
        require(sources, f'Empty source array: {group}')
        if group != 'source':
            require(group[len('source_'):] in fields['arch'], f'Undeclared source architecture: {group}')
        require(sums.get(group) == expected, f'Missing original checksum algorithm(s): {group}')
        for source in sources:
            name = local_source(source)
            if name is not None:
                path = RECIPE / name
                require(path.is_file() and not path.is_symlink(), f'Missing regular local source: {name}')
    return groups


def checksum_fields(fields):
    return {key: [value.lower() for value in values] for key, values in fields.items() if SUM_KEY.fullmatch(key)}


def without_checksums(fields):
    return {key: values for key, values in fields.items() if not SUM_KEY.fullmatch(key)}


def strip_checksums(text, fields):
    stripped, count = SUM_ARRAY.subn('', text)
    require(count == len(checksum_fields(fields)), 'Checksum assignments are not unique literal top-level arrays')
    return stripped


def initial(pkgbase):
    saved = load_snapshot(OUTPUT / 'initial-files.json')
    audit_files(saved, {'.SRCINFO'})
    before = metadata(saved['srcinfo'])
    generated = info(OUTPUT / 'original.SRCINFO')
    identity(before, pkgbase)
    identity(generated, pkgbase)
    require(compare(version(generated), version(before)) >= 0, 'Candidate recipe version is older than original .SRCINFO')


def checksum_baseline(pkgbase):
    saved = load_snapshot(OUTPUT / 'initial-files.json')
    old = metadata(saved['srcinfo'])
    before = info(OUTPUT / 'original.SRCINFO')
    old_groups = checksum_schema(pkgbase, old)
    before_groups = checksum_schema(pkgbase, before)
    require({key: len(value) for key, value in old_groups.items()} ==
            {key: len(value) for key, value in before_groups.items()},
            'Candidate changed original source array shape')
    require(checksum_fields(old).keys() == checksum_fields(before).keys(),
            'Original checksum algorithm/architecture arrays changed')
    return saved, old, before, old_groups, before_groups


def checksum_audit(pkgbase, mode):
    saved, old, before, old_groups, before_groups = checksum_baseline(pkgbase)
    after = info(RECIPE / '.SRCINFO')
    after_groups = checksum_schema(pkgbase, after)
    require(before_groups == after_groups, 'Checksum refresh changed source arrays')
    require(checksum_fields(before).keys() == checksum_fields(after).keys(),
            'Original checksum algorithm/architecture arrays changed')
    require(without_checksums(before) == without_checksums(after), 'Checksum refresh changed other package metadata')
    audit_files(saved, {'PKGBUILD', '.SRCINFO'})
    current = (RECIPE / 'PKGBUILD').read_text()
    if mode in ('refresh', 'refresh-stable'):
        require(strip_checksums(saved['pkgbuild'], before) == strip_checksums(current, after),
                'updpkgsums rewrote recipe content beyond checksum arrays')
    else:
        require(saved['pkgbuild'] == current, 'Source verification rewrote PKGBUILD')
    # The original candidate metadata contains its old sums, not newly downloaded content.
    upgraded = compare(one(before, 'pkgver'), one(old, 'pkgver')) > 0
    if mode != 'refresh' or not upgraded:
        require(checksum_fields(before) == checksum_fields(after), 'Same-version checksum content changed')
    for group, sources in before_groups.items():
        suffix = group[len('source'):]
        for index, source in enumerate(sources):
            name = local_source(source)
            if name is None:
                continue
            require(name in saved['files'], f'Local source was not in the initial whitelist: {name}')
            for algorithm in ('sha512', 'b2') if pkgbase == 'wakatime' else ('sha256',):
                key = algorithm + 'sums' + suffix
                require(before[key][index].lower() == after[key][index].lower(),
                        f'Checksum of unchanged local source changed: {name}')
                for old_group, old_sources in old_groups.items():
                    for old_index, old_source in enumerate(old_sources):
                        if local_source(old_source) == name:
                            old_key = algorithm + 'sums' + old_group[len('source'):]
                            require(old[old_key][old_index].lower() == after[key][index].lower(),
                                    f'Candidate rewrote original checksum of local source: {name}')


def normalize_versions(text):
    for key in ('pkgver', 'pkgrel'):
        text, count = re.subn(r'^' + key + r'=.*$', key + '=<makepkg>', text, flags=re.M)
        require(count == 1, f'Expected unique top-level {key}')
    return text


def build_audit(pkgbase):
    saved = load_snapshot(OUTPUT / 'pre-build-files.json')
    audit_files(saved, {'PKGBUILD', '.SRCINFO'})
    current = (RECIPE / 'PKGBUILD').read_text()
    before = info(OUTPUT / 'pre-build.SRCINFO')
    after = info(RECIPE / '.SRCINFO')
    checksum_schema(pkgbase, after)
    if pkgbase not in VCS_PACKAGES:
        require(current == saved['pkgbuild'], 'Build unexpectedly rewrote PKGBUILD')
        require(before == after, 'Build unexpectedly changed package metadata')
        return
    require(normalize_versions(current) == normalize_versions(saved['pkgbuild']),
            'VCS build changed recipe beyond pkgver/pkgrel')
    require({key: values for key, values in before.items() if key not in ('pkgver', 'pkgrel')} ==
            {key: values for key, values in after.items() if key not in ('pkgver', 'pkgrel')},
            'VCS build changed metadata beyond pkgver/pkgrel')
    require(compare(one(after, 'pkgver'), one(before, 'pkgver')) >= 0, 'VCS pkgver moved backwards')
    if one(before, 'pkgver') != one(after, 'pkgver'):
        require(one(after, 'pkgrel') == '1', 'Changed VCS pkgver was not packaged with pkgrel=1')
    else:
        require(one(before, 'pkgrel') == one(after, 'pkgrel'), 'Unchanged VCS pkgver unexpectedly changed pkgrel')


def archive_path(name):
    while name.startswith('./'):
        name = name[2:]
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts, f'Unsafe package member: {name}')
    return str(path)


def read_archive(path):
    # libarchive supports every makepkg compression format; stream its uncompressed tar.
    process = subprocess.Popen(['bsdtar', '-cf', '-', '--format=pax', '@' + str(path)], stdout=subprocess.PIPE)
    members = {}
    pkginfo = None
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for member in archive:
                name = archive_path(member.name)
                if name == '.':
                    continue
                require(name not in members, f'Duplicate package member: {name}')
                members[name] = (member.type, member.mode, member.size, member.linkname)
                if name == '.PKGINFO':
                    require(member.isfile() and member.size <= 65536, 'Invalid package .PKGINFO')
                    pkginfo = metadata(archive.extractfile(member).read().decode())
        process.stdout.close()
        require(process.wait() == 0, f'Failed to read package archive: {path.name}')
    except BaseException:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
        process.wait()
        raise
    require(pkginfo is not None, f'Package has no .PKGINFO: {path.name}')
    return pkginfo, members


def inspect_entry(members, entry):
    name = entry.lstrip('/')
    seen = set()
    while True:
        require(name not in seen, f'Installed entry has a link cycle: {entry}')
        seen.add(name)
        require(name in members, f'Package is missing installed entry/target: {name}')
        kind, mode, size, link = members[name]
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            if kind == tarfile.LNKTYPE or link.startswith('/'):
                name = posixpath.normpath(link.lstrip('/'))
            else:
                name = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
            require(name != '..' and not name.startswith('../'), f'Installed entry escapes package: {entry}')
        else:
            require(kind in (tarfile.REGTYPE, tarfile.AREGTYPE) and size > 0 and mode & 0o111,
                    f'Installed entry is not a nonempty executable: {entry}')
            return


def built_commit(fields, pkgbase):
    sources = [source for values in source_groups(fields).values() for source in values
               if source_location(source).startswith('git+')]
    require(len(sources) == 1, 'Expected one VCS git source')
    source = sources[0]
    location = source_location(source)
    parsed = urllib.parse.urlsplit(location[len('git+'):])
    name = source.split('::', 1)[0] if '::' in source else Path(parsed.path).name.removesuffix('.git')
    require(re.fullmatch(r'[A-Za-z0-9._+-]+', name), 'Unsafe git cache name')
    reference = 'HEAD'
    if parsed.fragment:
        kind, separator, reference = parsed.fragment.partition('=')
        require(separator and kind in ('commit', 'branch', 'tag') and reference and not reference.startswith('-'),
                'Unsupported VCS source reference')
        if kind == 'branch':
            reference = 'refs/heads/' + reference
    cache = WORK / 'sources' / name
    base = ['git', '-c', 'safe.bareRepository=all', '-C', str(cache)]
    commit = command(base + ['rev-parse', '--verify', reference + '^{commit}'])
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'Invalid actual VCS commit')
    if pkgbase == 'nali-nt-git':
        # Only this recipe derives pkgver from `git describe`; others (date-based) are checked by makepkg itself.
        described = command(base + ['describe', '--long', '--tags', '--abbrev=7', '--match=v*', commit])
        generated_version = re.sub(r'([^-]*-g)', r'r\1', described.removeprefix('v')).replace('-', '.')
        require(generated_version == one(fields, 'pkgver'), 'Actual cached commit does not match packaged VCS pkgver')
    return commit


def inspect(pkgbase, entry):
    fields = info(RECIPE / '.SRCINFO')
    identity(fields, pkgbase)
    expected_version = version(fields)
    expected_arch = 'any' if fields['arch'] == ['any'] else 'x86_64'
    paths = [Path(line) for line in (OUTPUT / 'packagelist').read_text().splitlines() if line]
    require(paths and len(paths) == len(set(paths)), 'Empty or duplicate makepkg package list')
    inspected = set()
    for path in paths:
        require(path.parent == WORK / 'packages' and not path.is_symlink(), 'Package list escapes fresh PKGDEST')
        main_name = pkgbase + '-' + expected_version + '-' + expected_arch
        debug_name = pkgbase + '-debug-' + expected_version + '-' + expected_arch
        require(path.name.startswith(main_name + '.pkg.tar') or path.name.startswith(debug_name + '.pkg.tar'),
                f'Unexpected makepkg package filename: {path.name}')
        is_debug = path.name.startswith(debug_name + '.pkg.tar')
        if is_debug and not path.exists():
            print(f'No detached symbols; optional makepkg debug archive was not produced: {path.name}')
            continue
        require(path.is_file(), f'makepkg did not produce listed package: {path.name}')
        pkginfo, members = read_archive(path)
        require(one(pkginfo, 'pkgname') == (pkgbase + '-debug' if is_debug else pkgbase), 'Built package name mismatch')
        require(one(pkginfo, 'pkgbase') == pkgbase, 'Built package base mismatch')
        require(one(pkginfo, 'pkgver') == expected_version, 'Built package version/release mismatch')
        require(one(pkginfo, 'arch') == expected_arch, 'Built package architecture mismatch')
        if not is_debug:
            inspect_entry(members, entry)
            inspected.add(pkgbase)
        print(f'Inspected {path.name}: {one(pkginfo, "pkgname")} {expected_version} {expected_arch}')
    require(inspected == {pkgbase}, 'Main package was not inspected')
    require({path for path in (WORK / 'packages').iterdir()} == {path for path in paths if path.exists()},
            'Unexpected files in fresh PKGDEST')
    commit = built_commit(fields, pkgbase) if pkgbase in VCS_PACKAGES else None
    facts = {'pkgname': pkgbase, 'pkgver': expected_version, 'arch': expected_arch,
             'entry': entry, 'built_source_commit': commit}
    (OUTPUT / 'facts.json').write_text(json.dumps(facts, indent=2) + '\n')
    print(json.dumps(facts, sort_keys=True))


def failure_stage(code, path):
    log = Path(path).read_text(errors='replace')
    # These makepkg errors occur before an actual packaging attempt, never trigger VCS retry.
    if code in (2, 3, 8, 9, 10, 11, 13, 14, 15, 16):
        return 'initialization'
    if code in (4, 5, 7) or re.search(r'^==> (?:Extracting sources|Starting [^\n]*\(\)|Entering.*fakeroot)', log, re.M):
        return 'build'
    if code in (6, 17) or re.search(r'^==> (?:Retrieving sources|Validating source files)', log, re.M):
        return 'verify-source'
    return 'initialization'


def main():
    action, *args = sys.argv[1:]
    if action == 'snapshot':
        snapshot(*args)
    elif action == 'initial':
        initial(*args)
    elif action == 'unchanged':
        audit_files(load_snapshot(args[0]), {'.SRCINFO'})
    elif action == 'checksum-baseline':
        checksum_baseline(*args)
    elif action == 'architectures':
        fields = info(args[0])
        for arch in fields['arch']:
            print('x86_64' if arch == 'any' else arch)
    elif action == 'checksum-audit':
        checksum_audit(*args)
    elif action == 'build-audit':
        build_audit(*args)
    elif action == 'inspect':
        inspect(*args)
    elif action == 'failure-stage':
        print(failure_stage(int(args[0]), args[1]))
    else:
        raise ValueError(f'Unknown audit action: {action}')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'package audit failed: {exc}', file=sys.stderr)
        sys.exit(1)
