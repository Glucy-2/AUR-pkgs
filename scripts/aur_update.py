#!/usr/bin/env python3
"""Isolated AUR checks and explicitly trusted historical publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(args, cwd=None, **kwargs):
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def registry():
    return json.loads((ROOT / '.automation/packages.json').read_text())


def packages(name='all'):
    rows = registry()
    if name == 'all':
        return [r for r in rows if r['enabled']]
    row = next((r for r in rows if r['pkgbase'] == name), None)
    if row is None:
        raise ValueError(f'Unknown/removed package: {name}')
    if not row['enabled']:
        raise ValueError(f'Disabled draft package: {name}')
    return [row]


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if urllib.parse.urlparse(newurl).hostname != 'api.github.com':
            redirected.remove_header('Authorization')
        return redirected


def fetch(url):
    headers = {'User-Agent': 'curl/8.20.0', 'Accept': 'application/vnd.github+json' if urllib.parse.urlparse(url).hostname == 'api.github.com' else '*/*'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token and urllib.parse.urlparse(url).hostname == 'api.github.com':
        headers['Authorization'] = f'Bearer {token}'
    with urllib.request.build_opener(SafeRedirect()).open(urllib.request.Request(url, headers=headers), timeout=180) as response:
        return response.read()


def prerequisites():
    run(['docker', 'version'])
    run(['docker', 'image', 'inspect', 'archlinux:base-devel'])


def vercmp(left, right):
    command = ['vercmp', left, right] if shutil.which('vercmp') else ['docker', 'run', '--rm', '--network', 'none', '--read-only', 'archlinux:base-devel', 'vercmp', left, right]
    result = int(run(command))
    if result not in (-1, 0, 1):
        raise ValueError('Invalid Arch vercmp output')
    return result


def metadata(text):
    values = {}
    for line in text.splitlines():
        if ' = ' in line:
            key, value = line.strip().split(' = ', 1)
            values.setdefault(key, []).append(value)
    return values


def scalar(recipe, key):
    matches = re.findall(r'^' + re.escape(key) + r'=(.*)$', recipe, re.M)
    if len(matches) != 1:
        raise ValueError(f'Expected unique top-level {key}')
    return matches[0].strip().strip('\"\'')


def replace_scalar(recipe, key, value):
    if not re.fullmatch(r'[A-Za-z0-9.+_-]+', str(value)):
        raise ValueError(f'Unsafe {key} value')
    scalar(recipe, key)
    return re.sub(r'^' + re.escape(key) + r'=.*$', f'{key}="{value}"', recipe, flags=re.M)


def highest_release(releases, compare=vercmp):
    best = None
    for release in releases:
        tag = release.get('tag_name', '')
        if release.get('draft') or release.get('prerelease') or not re.fullmatch(r'v[0-9]+(?:\.[0-9]+)*', tag):
            continue
        if best is None or compare(tag[1:], best['tag_name'][1:]) > 0:
            best = release
    return best


def github_release(row, recipe, info):
    releases = []
    page = 1
    while True:
        batch = json.loads(fetch(f"https://api.github.com/repos/{row['upstream']}/releases?per_page=30&page={page}"))
        if not isinstance(batch, list):
            raise ValueError('Invalid GitHub release response')
        releases.extend(batch)
        if len(batch) < 30:
            break
        page += 1
    release = highest_release(releases)
    if release is None:
        return {'candidate_version': scalar(recipe, 'pkgver'), 'source': f"https://api.github.com/repos/{row['upstream']}/releases", 'fields': {}, 'message': 'No matching stable numeric release; unchanged'}
    version = release['tag_name'][1:]
    assets = {a['name'] for a in release.get('assets', [])}
    current = scalar(recipe, 'pkgver')
    required = []
    for key, sources in info.items():
        if key == 'source' or key.startswith('source_'):
            for source in sources:
                url = source.split('::')[-1]
                if '/releases/download/' in url:
                    required.append(urllib.parse.urlparse(url.replace(current, version)).path.rsplit('/', 1)[-1])
    missing = sorted(set(required) - assets)
    if missing:
        raise ValueError('Candidate release missing exact architecture assets: ' + ', '.join(missing))
    return {'candidate_version': version, 'source': release.get('html_url', f"https://github.com/{row['upstream']}/releases/tag/v{version}"), 'fields': {'pkgver': version}, 'message': 'Highest stable numeric release by Arch vercmp'}


def inspect_package(row):
    recipe = (ROOT / row['pkgbase'] / 'PKGBUILD').read_text()
    info = metadata((ROOT / row['pkgbase'] / '.SRCINFO').read_text())
    current = scalar(recipe, 'pkgver')
    detector = row['detector']
    if detector == 'github-release':
        detected = github_release(row, recipe, info)
    elif detector == 'intel-mlc':
        from detect_intel import detect
        detected = detect(recipe, fetch, vercmp)
    elif detector == 'neo4j-community':
        from detect_neo4j import detect
        detected = detect(recipe, fetch, vercmp)
    elif detector == 'vcs-build-first':
        detected = {'candidate_version': current, 'fields': {}, 'source': f"https://github.com/{row['upstream']}", 'message': 'Build existing moving source first; no commit-chasing update'}
    else:
        raise ValueError('Unsupported detector')
    detected.update(pkgbase=row['pkgbase'], current_version=current)
    detected['upgrade'] = vercmp(detected['candidate_version'], current) > 0
    if not detected['upgrade']:
        detected['candidate_version'] = current
        detected['fields'] = {}
    return detected


def aur_url(name):
    return f'https://aur.archlinux.org/{name}.git'


def remote_head(url):
    output = run(['git', 'ls-remote', url, 'refs/heads/master']).split()
    if len(output) != 2 or not re.fullmatch('[0-9a-f]{40}', output[0]):
        raise ValueError(f'Cannot resolve existing AUR master: {url}')
    return output[0]


def bootstrap_state():
    path = ROOT / '.automation/aur-state.json'
    state = json.loads(path.read_text()) if path.exists() else {}
    for row in packages():
        name = row['pkgbase']
        if name not in state:
            state[name] = remote_head(aur_url(name))
            path.write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps(state, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('matrix', 'inspect', 'check'):
        p = sub.add_parser(name)
        p.add_argument('--package', default='all', required=name != 'matrix')
        if name == 'check':
            p.add_argument('--work-dir', required=True)
            p.add_argument('--result-dir', required=True)
    sub.add_parser('bootstrap-state')
    p = sub.add_parser('publish')
    p.add_argument('--results-dir', required=True)
    p.add_argument('--package', default='all')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--aur-remote-url')
    args = parser.parse_args()
    try:
        if args.command == 'matrix':
            print(json.dumps([r['pkgbase'] for r in packages(args.package)]))
        elif args.command == 'inspect':
            rows = packages(args.package)
            prerequisites()
            for row in rows:
                print(json.dumps(inspect_package(row), indent=2))
        elif args.command == 'bootstrap-state':
            bootstrap_state()
        elif args.command == 'check':
            row, = packages(args.package)
            from aur_check import check
            return check(row, Path(args.work_dir), Path(args.result_dir))
        else:
            packages(args.package)
            if args.aur_remote_url and args.package == 'all':
                raise ValueError('Test remote requires a single explicit package')
            from aur_publish import publish
            return publish(args)
        return 0
    except Exception as exc:
        print(f'failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
