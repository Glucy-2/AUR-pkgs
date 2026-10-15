"""Detect Intel MLC from the recipe's official article and its download block.

Network access and Arch version comparison are supplied by the caller. Returned
field values are complete Bash assignment right-hand sides, never executable
page content; only an upgrade supplies replacements.
"""

import hashlib
from html.parser import HTMLParser
import re
import shlex
from urllib.parse import urljoin, urlsplit, urlunsplit


_VERSION = r"[0-9]+(?:\.[0-9]+)*(?:[a-z])?"
_ARCHIVE_NAME = re.compile(r"mlc_v(" + _VERSION + r")\.tgz", re.I)
_MIRROR = re.compile(
    r"https://downloadmirror\.intel\.com/[0-9]+/mlc_v(" + _VERSION + r")\.tgz"
)
_SHA256 = re.compile(r"\bSHA\s*-?\s*256\s*:\s*([0-9a-fA-F]{64})\b", re.I)
_VOID = frozenset(
    "area base br col embed hr img input link meta param source track wbr".split()
)


def _assignment(recipe, name):
    matches = re.findall(r"^" + re.escape(name) + r"=(.*)$", recipe, re.M)
    if len(matches) != 1:
        raise ValueError(f"Intel recipe requires one top-level {name} assignment")
    return matches[0]


def _scalar(recipe, name):
    try:
        words = shlex.split(_assignment(recipe, name), comments=True)
    except ValueError as exc:
        raise ValueError(f"Malformed Intel recipe {name}") from exc
    if len(words) != 1 or any(c in words[0] for c in "$`\n\r"):
        raise ValueError(f"Intel recipe {name} must be a literal scalar")
    return words[0]


def _intel_url(url):
    parts = urlsplit(url)
    return (
        parts.scheme == "https"
        and parts.netloc in {"www.intel.com", "intel.com"}
        and not parts.username
        and not parts.password
    )


def _html(fetch, url):
    try:
        return fetch(url).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Intel page is not UTF-8: {url}") from exc


class _ArticleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.anchor = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            if self.anchor is not None:
                raise ValueError("Malformed nested Intel article anchors")
            values = dict(attrs)
            self.anchor = (values.get("href", ""), [])

    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor[1].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor is not None:
            href, text = self.anchor
            self.links.append((href, "".join(text)))
            self.anchor = None

    def download(self, article_url):
        if self.anchor is not None:
            raise ValueError("Unclosed Intel article anchor")
        links = {}
        for href, text in self.links:
            url = urljoin(article_url, href)
            parts = urlsplit(url)
            if not _intel_url(url) or not re.search(r"/download/[0-9]+/", parts.path):
                continue
            if not (
                "memory-latency-checker" in parts.path.lower()
                or re.search(r"\bmlc\b|memory\s+latency\s+checker", text, re.I)
                or _ARCHIVE_NAME.search(text)
            ):
                continue
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
            links.setdefault(url, set()).update(_ARCHIVE_NAME.findall(text))
        if len(links) != 1:
            raise ValueError("Intel article must link to one authoritative MLC download page")
        return next(iter(links.items()))


class _DownloadParser(HTMLParser):
    """Keep hashes scoped to Intel's download-hero, not page-wide text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks = []
        self.stack = []
        self.block = None
        self.mirrors = []
        self.versions = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "meta" and values.get("name", "").lower() == "downloadversion":
            self.versions.append(values.get("content", "").strip())
        classes = values.get("class", "").split()
        is_block = (
            values.get("data-component") == "download-hero"
            or "dc-page-available-downloads-hero" in classes
        )
        if is_block:
            if self.block is not None:
                raise ValueError("Nested Intel download blocks are ambiguous")
            self.block = {"urls": [], "text": []}
        if self.block is not None:
            if tag not in _VOID:
                self.stack.append(tag)
            if values.get("data-href") is not None:
                url = values["data-href"]
                if "mlc" in url.lower() or "downloadmirror.intel.com" in url.lower():
                    self.block["urls"].append(url)
        elif values.get("data-href") is not None:
            url = values["data-href"]
            if "mlc" in url.lower() or "downloadmirror.intel.com" in url.lower():
                raise ValueError("Intel mirror is outside its download block")
        if values.get("data-href") is not None:
            url = values["data-href"]
            if "mlc" in url.lower() or "downloadmirror.intel.com" in url.lower():
                self.mirrors.append(url)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.block is None or tag in _VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            raise ValueError("Malformed Intel download block nesting")
        self.stack.pop()
        if not self.stack:
            self.blocks.append(self.block)
            self.block = None

    def handle_data(self, data):
        if self.block is not None:
            self.block["text"].append(data)

    def download(self):
        if self.block is not None:
            raise ValueError("Unclosed Intel download block")
        if len(self.mirrors) != 1:
            raise ValueError("Intel download page must contain exactly one MLC mirror")
        url = self.mirrors[0]
        match = _MIRROR.fullmatch(url)
        if match is None:
            raise ValueError("Malformed Intel MLC mirror URL or archive filename")
        matching = [block for block in self.blocks if url in block["urls"]]
        if len(matching) != 1:
            raise ValueError("Intel MLC mirror must belong to one download block")
        text = " ".join(matching[0]["text"])
        hashes = _SHA256.findall(text)
        if len(hashes) != 1:
            raise ValueError("Intel MLC download block requires exactly one SHA256")
        version = match.group(1)
        filenames = _ARCHIVE_NAME.findall(text)
        if any(value != version for value in filenames):
            raise ValueError("Intel download label version disagrees with archive filename")
        if self.versions and (len(self.versions) != 1 or self.versions[0] != version):
            raise ValueError("Intel download metadata version disagrees with archive filename")
        return url, version, hashes[0].lower()


def detect(recipe_text, fetch, vercmp):
    """Return an authoritative candidate, failing closed on missing metadata.

    ``fetch(url)`` returns bytes; ``vercmp(left, right)`` returns -1, 0, or 1.
    The caller remains responsible for no-downgrade policy and pkgrel handling.
    """
    article_url = _scalar(recipe_text, "url")
    current = _scalar(recipe_text, "pkgver")
    _assignment(recipe_text, "source")
    _assignment(recipe_text, "sha256sums")
    if not _intel_url(article_url) or "/developer/articles/" not in urlsplit(article_url).path:
        raise ValueError("Intel recipe url must identify an official Intel article")
    if re.fullmatch(_VERSION, current) is None:
        raise ValueError("Intel recipe pkgver is not an MLC version")

    article = _ArticleParser()
    article.feed(_html(fetch, article_url))
    article.close()
    page_url, article_versions = article.download(article_url)
    page = _DownloadParser()
    page.feed(_html(fetch, page_url))
    page.close()
    archive_url, candidate, digest = page.download()
    if any(version != candidate for version in article_versions):
        raise ValueError("Intel article version disagrees with archive filename")
    actual = hashlib.sha256(fetch(archive_url)).hexdigest()
    if actual != digest:
        raise RuntimeError(f"Intel MLC SHA256 mismatch: expected {digest}, got {actual}")
    comparison = vercmp(candidate, current)
    if comparison not in (-1, 0, 1):
        raise ValueError("vercmp must return -1, 0, or 1")
    fields = {}
    if comparison > 0:
        fields = {
            "pkgver": candidate,
            "source": f'("{archive_url}")',
            "sha256sums": f"('{digest}')",
        }
    return {
        "candidate_version": candidate,
        "source": page_url,
        "fields": fields,
        "expected_sha256": digest,
        "message": f"Intel article/download block and archive SHA256 verified ({candidate})",
    }
