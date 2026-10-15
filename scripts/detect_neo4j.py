"""Authoritative Neo4j Community release and Debian dependency detection."""

import hashlib
import io
import re
import subprocess
import tarfile
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit


DEPLOYMENT_CENTER = "https://neo4j.com/deployment-center/"
_RELEASE = re.compile(r"[0-9]{4}\.(?:0[1-9]|1[0-2])\.[0-9]+\Z")
_DATA_ARCHIVES = {"data.tar.xz", "data.tar.zst", "data.tar.gz"}
_CONTROL_ARCHIVES = {"control.tar", "control.tar.xz", "control.tar.zst", "control.tar.gz"}
_CONTROL_LIMIT = 1024 * 1024


class _CommunityLinks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.versions = set()

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name not in {"href", "data-url"} or not value:
                continue
            link = urlsplit(urljoin(DEPLOYMENT_CENTER, value))
            if link.scheme != "https" or link.hostname not in {"neo4j.com", "go.neo4j.com"}:
                continue
            query = parse_qs(link.query, keep_blank_values=True)
            if query.get("edition") != ["community"]:
                continue
            versions = query.get("release", [])
            if len(versions) != 1:
                raise ValueError("Ambiguous Neo4j Community release query")
            if _RELEASE.fullmatch(versions[0]):
                self.versions.add(versions[0])


def community_versions(html):
    """Read only official Community download link queries, never display titles."""
    parser = _CommunityLinks()
    parser.feed(html)
    parser.close()
    if not parser.versions:
        raise ValueError("No YYYY.MM.patch Community release links in deployment center")
    return parser.versions


def _ar_members(deb):
    """Return member offsets, without copying the large data archive."""
    if not deb.startswith(b"!<arch>\n"):
        raise ValueError("Neo4j download is not a Debian ar archive")
    members = {}
    offset = 8
    while offset < len(deb):
        header = deb[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("Malformed Debian ar member header")
        try:
            name = header[:16].decode("ascii").strip().removesuffix("/")
            raw_size = header[48:58].decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("Non-ASCII Debian ar header") from exc
        if not re.fullmatch(r"[0-9]+", raw_size) or not name or name.startswith(("/", "#1/")):
            raise ValueError("Unsupported Debian ar member header")
        size = int(raw_size)
        start = offset + 60
        end = start + size
        if end > len(deb) or name in members:
            raise ValueError("Truncated or duplicate Debian ar member")
        members[name] = (start, end)
        offset = end + size % 2
        if offset > len(deb) or (size % 2 and deb[end:offset] != b"\n"):
            raise ValueError("Malformed Debian ar padding")
    binary = members.get("debian-binary")
    if binary is None or deb[binary[0]:binary[1]] != b"2.0\n":
        raise ValueError("Missing or unsupported Debian archive version")
    control = [name for name in members if name.startswith("control.tar")]
    data = [name for name in members if name.startswith("data.tar")]
    if len(control) != 1 or control[0] not in _CONTROL_ARCHIVES:
        raise ValueError("Expected one supported control.tar archive")
    if len(data) != 1 or data[0] not in _DATA_ARCHIVES:
        raise ValueError("Expected exactly one data.tar.{xz,zst,gz}")
    return members, control[0]


def _control_with_bsdtar(blob):
    # Read a single member to stdout; never extract network-controlled paths to disk.
    try:
        listing = subprocess.run(
            ["bsdtar", "-tf", "-"], input=blob, capture_output=True, check=True, timeout=60
        ).stdout.decode("utf-8").splitlines()
        controls = [name for name in listing if name in {"control", "./control"}]
        if len(controls) != 1:
            raise ValueError("Expected exactly one Debian control file")
        control = subprocess.run(
            ["bsdtar", "-xOf", "-", controls[0]],
            input=blob, capture_output=True, check=True, timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        raise RuntimeError("Unable to read control.tar.zst; working bsdtar is required") from exc
    if len(control) > _CONTROL_LIMIT:
        raise ValueError("Debian control file is too large")
    return control


def deb_control(deb):
    """Extract only the control file, supporting zstd via libarchive's bsdtar."""
    members, name = _ar_members(deb)
    start, end = members[name]
    blob = deb[start:end]
    try:
        archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except tarfile.ReadError as exc:
        if name != "control.tar.zst":
            raise ValueError("Unreadable Debian control archive") from exc
        return _control_with_bsdtar(blob).decode("utf-8")
    with archive:
        controls = [item for item in archive if item.name in {"control", "./control"}]
        if len(controls) != 1 or not controls[0].isfile():
            raise ValueError("Expected exactly one regular Debian control file")
        if controls[0].size > _CONTROL_LIMIT:
            raise ValueError("Debian control file is too large")
        with archive.extractfile(controls[0]) as stream:
            return stream.read().decode("utf-8")


def _control_fields(text):
    fields = {}
    previous = None
    for line in text.rstrip("\r\n").splitlines():
        if not line:
            raise ValueError("Multiple or empty Debian control paragraphs")
        if line[0].isspace():
            if previous is None:
                raise ValueError("Orphan Debian control continuation")
            fields[previous] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        name = name.lower()
        if not separator or not re.fullmatch(r"[a-z][a-z0-9-]*", name) or name in fields:
            raise ValueError("Malformed or duplicate Debian control field")
        fields[name] = value.strip()
        previous = name
    return fields


def _java_alternative(alternative):
    # Architecture qualifiers/restrictions or unknown Java providers are deliberately
    # rejected: translating these into an Arch minimum would otherwise guess.
    match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?:\s*\((>=)\s*([0-9]+)\))?", alternative)
    if match is None:
        raise ValueError("Ambiguous Java dependency: " + alternative)
    package, operator, lower_bound = match.groups()
    encoded = re.fullmatch(
        r"(?:java([0-9]+)-runtime(?:-headless)?|jdk-([0-9]+)|"
        r"openjdk-([0-9]+)-(?:jre|jdk)(?:-headless)?)", package
    )
    if encoded:
        if operator:
            raise ValueError("Version constraint on Java provider cannot be mapped to a major minimum")
        major = int(next(value for value in encoded.groups() if value is not None))
    elif package in {"java-runtime", "java-runtime-headless"} and operator == ">=":
        major = int(lower_bound)
    else:
        raise ValueError("Unresolved Java dependency: " + alternative)
    if major < 1:
        raise ValueError("Invalid Java major version")
    return major


def java_minimum(depends):
    """Map explicit Java-provider OR groups to their minimum, AND groups to maximum."""
    requirements = []
    for group in depends.split(","):
        alternatives = [item.strip() for item in group.split("|")]
        if not all(alternatives):
            raise ValueError("Malformed Debian Depends")
        if not any(re.search(r"\b(?:java|jdk|openjdk|default-jre|default-jdk)", item) for item in alternatives):
            continue
        requirements.append(min(_java_alternative(item) for item in alternatives))
    if not requirements:
        raise ValueError("Debian Depends contains no explicit Java minimum")
    return max(requirements)


def _sha256(text, filename):
    match = re.fullmatch(r"\s*([a-fA-F0-9]{64})(?:[ \t]+\*?([^\s]+))?\s*", text)
    if match is None or (match[2] is not None and match[2] not in {filename, "./" + filename}):
        raise ValueError("Missing, ambiguous or mismatched Neo4j SHA256 declaration")
    return match[1].lower()


def detect(recipe_text, fetch, vercmp):
    """Return an authoritative candidate; the caller decides whether it is an upgrade.

    fetch(url) must return bytes. Downloaded archives are held only for this call,
    with no cache or artifacts written into the checkout. Source and local-source
    arrays remain unchanged; the caller uses expected_sha256 for the remote source.
    """
    versions = community_versions(fetch(DEPLOYMENT_CENTER).decode("utf-8"))
    candidate = None
    for version in sorted(versions):
        if candidate is None:
            candidate = version
        else:
            comparison = vercmp(version, candidate)
            if comparison > 0:
                candidate = version
            elif comparison == 0 and version != candidate:
                raise ValueError("Distinct Neo4j release spellings compare equally")
    filename = "neo4j_" + candidate + "_all.deb"
    deb_url = "https://dist.neo4j.org/deb/" + filename
    expected = _sha256(fetch(deb_url + ".sha256").decode("ascii"), filename)
    deb = fetch(deb_url)
    if hashlib.sha256(deb).hexdigest() != expected:
        raise ValueError("Neo4j Debian archive SHA256 does not match its authoritative declaration")
    control = _control_fields(deb_control(deb))
    version = control.get("version", "")
    version = re.sub(r"^[0-9]+:", "", version).split("-", 1)[0]
    if control.get("package") != "neo4j" or control.get("architecture") != "all" or version != candidate:
        raise ValueError("Neo4j Debian package identity/version does not match Community release")
    java = java_minimum(control.get("depends", ""))
    return {
        "candidate_version": candidate,
        "source": DEPLOYMENT_CENTER,
        "fields": {"pkgver": candidate, "_min_java_version": str(java)},
        "expected_sha256": expected,
        "message": "Community release and Debian SHA256/control verified; minimum Java " + str(java),
    }
