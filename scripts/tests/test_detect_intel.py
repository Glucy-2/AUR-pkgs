"""Byte-fixture tests for Intel's authoritative article/download contract."""

import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detect_intel import detect


ARTICLE_URL = (
    "https://www.intel.com/content/www/us/en/developer/articles/tool/"
    "intelr-memory-latency-checker.html"
)
DOWNLOAD_URL = (
    "https://www.intel.com/content/www/us/en/download/736633/"
    "intel-memory-latency-checker-intel-mlc.html"
)
MIRROR_URL = "https://downloadmirror.intel.com/926327/mlc_v3.13.tgz"
ARCHIVE = b"fixture archive bytes, never executed"
DIGEST = hashlib.sha256(ARCHIVE).hexdigest()
RECIPE = f'''pkgname=intel-mlc
pkgver=3.12
pkgrel=1
url="{ARTICLE_URL}"
source=("https://downloadmirror.intel.com/866182/mlc_v${{pkgver}}.tgz")
sha256sums=('{'0' * 64}')
'''
ARTICLE = (
    f'<html><head><title>Intel MLC v3.12</title></head><body>'
    f'<a href="{DOWNLOAD_URL}">mlc_v3.13.tgz</a></body></html>'
).encode()


def download_block(url=MIRROR_URL, digest=DIGEST, label="mlc_v3.13.tgz"):
    return (
        '<div class="dc-page-available-downloads-hero component" '
        'data-component="download-hero">'
        f'<div><button data-href="{url}"><span>{label}</span></button></div>'
        f'<div><ul><li>SHA256: {digest}</li></ul></div></div>'
    ).encode()


DOWNLOAD = (
    b'<html><head><meta name="DownloadVersion" content="3.13"></head><body>'
    + download_block()
    + b'</body></html>'
)


class IntelDetectorTests(unittest.TestCase):
    def detect_fixture(self, *, article=ARTICLE, page=DOWNLOAD, archive=ARCHIVE,
                       recipe=RECIPE, comparison=1):
        responses = {ARTICLE_URL: article, DOWNLOAD_URL: page, MIRROR_URL: archive}
        self.requests = []
        self.comparisons = []

        def fetch(url):
            self.requests.append(url)
            return responses[url]

        def vercmp(left, right):
            self.comparisons.append((left, right))
            return comparison

        return detect(recipe, fetch, vercmp)

    def test_authoritative_link_mirror_and_digest(self):
        result = self.detect_fixture()
        self.assertEqual(result["candidate_version"], "3.13")
        self.assertEqual(result["source"], DOWNLOAD_URL)
        self.assertEqual(result["expected_sha256"], DIGEST)
        self.assertEqual(result["fields"], {
            "pkgver": "3.13",
            "source": f'("{MIRROR_URL}")',
            "sha256sums": f"('{DIGEST}')",
        })
        self.assertEqual(self.requests, [ARTICLE_URL, DOWNLOAD_URL, MIRROR_URL])
        self.assertEqual(self.comparisons, [("3.13", "3.12")])

    def test_same_or_older_candidates_do_not_replace_fields(self):
        for comparison in (0, -1):
            with self.subTest(comparison=comparison):
                result = self.detect_fixture(comparison=comparison)
                self.assertEqual(result["candidate_version"], "3.13")
                self.assertEqual(result["fields"], {})
                self.assertEqual(result["expected_sha256"], DIGEST)

    def test_relative_article_link_and_nested_label(self):
        article = (
            b'<a href="/content/www/us/en/download/736633/'
            b'intel-memory-latency-checker-intel-mlc.html">'
            b'<span>mlc_v3.13.tgz</span></a>'
        )
        self.assertEqual(self.detect_fixture(article=article)["candidate_version"], "3.13")

    def test_repeated_same_article_link_is_not_another_candidate(self):
        self.assertEqual(self.detect_fixture(article=ARTICLE + ARTICLE)["source"], DOWNLOAD_URL)

    def test_uppercase_and_nested_sha_label(self):
        page = download_block(digest=DIGEST.upper()).replace(b"SHA256:", b"<b>SHA-256:</b>")
        self.assertEqual(self.detect_fixture(page=page)["expected_sha256"], DIGEST)

    def test_unrelated_download_block_hash_is_not_used(self):
        other = download_block().replace(
            f'<button data-href="{MIRROR_URL}">'.encode(), b'<button>'
        ).replace(DIGEST.encode(), b"a" * 64)
        self.assertEqual(self.detect_fixture(page=other + download_block())["expected_sha256"], DIGEST)

    def test_missing_or_unsafe_download_link(self):
        articles = [
            b'<p>No download</p>',
            ARTICLE.replace(b"https://www.intel.com", b"https://not-intel.example"),
            ARTICLE.replace(b"https://www.intel.com", b"http://www.intel.com"),
            ARTICLE.replace(b"/download/736633/", b"/download-center/736633/"),
        ]
        for article in articles:
            with self.subTest(article=article), self.assertRaises(ValueError):
                self.detect_fixture(article=article)
            self.assertEqual(self.requests, [ARTICLE_URL])

    def test_ambiguous_article_download_pages(self):
        article = ARTICLE + ARTICLE.replace(b"/736633/", b"/123456/")
        with self.assertRaisesRegex(ValueError, "one authoritative"):
            self.detect_fixture(article=article)

    def test_malformed_article_anchors(self):
        for article in (ARTICLE.replace(b'</a>', b''), ARTICLE.replace(b'mlc_v', b'<a>mlc_v')):
            with self.subTest(article=article), self.assertRaises(ValueError):
                self.detect_fixture(article=article)

    def test_missing_or_ambiguous_mirrors(self):
        for page in (b'<html></html>', download_block() + download_block(),
                     download_block() + download_block(url=MIRROR_URL.replace('/926327/', '/123456/'))):
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, "exactly one MLC mirror"):
                self.detect_fixture(page=page)
            self.assertEqual(self.requests, [ARTICLE_URL, DOWNLOAD_URL])

    def test_mirror_outside_download_block(self):
        page = f'<button data-href="{MIRROR_URL}"></button><p>SHA256: {DIGEST}</p>'.encode()
        with self.assertRaisesRegex(ValueError, "outside"):
            self.detect_fixture(page=page)

    def test_malformed_mirror_urls(self):
        urls = [
            MIRROR_URL.replace('https:', 'http:'),
            MIRROR_URL.replace('/926327/', '/not-a-number/'),
            MIRROR_URL.replace('.tgz', '.zip'),
            MIRROR_URL + '?download=1',
            MIRROR_URL.replace('downloadmirror.intel.com', 'downloadmirror.intel.com.example'),
            MIRROR_URL.replace('mlc_v3.13', 'mlc_vunknown'),
        ]
        for url in urls:
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "Malformed Intel MLC mirror"):
                self.detect_fixture(page=download_block(url=url))

    def test_missing_malformed_or_duplicate_sha256(self):
        pages = [
            download_block().replace(f'SHA256: {DIGEST}'.encode(), b'No hash'),
            download_block(digest='not-a-digest'),
            download_block(digest=DIGEST + '0'),
            download_block().replace(b'</ul>', f'<li>SHA256: {DIGEST}</li></ul>'.encode()),
        ]
        for page in pages:
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, "exactly one SHA256"):
                self.detect_fixture(page=page)

    def test_hash_must_belong_to_mirror_block(self):
        page = download_block().replace(f'<li>SHA256: {DIGEST}</li>'.encode(), b'')
        page += f'<p>SHA256: {DIGEST}</p>'.encode()
        with self.assertRaisesRegex(ValueError, "exactly one SHA256"):
            self.detect_fixture(page=page)

    def test_malformed_or_unclosed_download_block(self):
        for page in (download_block()[:-6], download_block().replace(b'</ul>', b'</span>')):
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, "Unclosed|Malformed"):
                self.detect_fixture(page=page)

    def test_nested_download_blocks_are_ambiguous(self):
        page = b'<div data-component="download-hero">' + download_block() + b'</div>'
        with self.assertRaisesRegex(ValueError, "Nested"):
            self.detect_fixture(page=page)

    def test_version_disagreement_rejected(self):
        fixtures = [
            {"article": ARTICLE.replace(b'mlc_v3.13', b'mlc_v3.12')},
            {"page": download_block(label='mlc_v3.12.tgz')},
            {"page": DOWNLOAD.replace(b'content="3.13"', b'content="3.12"')},
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture), self.assertRaisesRegex(ValueError, "version disagrees"):
                self.detect_fixture(**fixture)
            self.assertEqual(self.requests, [ARTICLE_URL, DOWNLOAD_URL])

    def test_archive_checksum_mismatch_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
            self.detect_fixture(archive=b'changed archive')
        self.assertEqual(self.requests, [ARTICLE_URL, DOWNLOAD_URL, MIRROR_URL])
        self.assertEqual(self.comparisons, [])

    def test_non_utf8_html_rejected(self):
        with self.assertRaisesRegex(ValueError, "not UTF-8"):
            self.detect_fixture(page=b'\xff')

    def test_missing_duplicate_or_nonliteral_recipe_fields(self):
        recipes = [
            RECIPE.replace('pkgver=3.12\n', ''),
            RECIPE + 'pkgver=3.12\n',
            RECIPE.replace(f'url="{ARTICLE_URL}"', 'url="$(printf unsafe)"'),
            RECIPE.replace(f'url="{ARTICLE_URL}"', 'url="https://example.com/developer/articles/mlc"'),
            RECIPE.replace('sha256sums=', '#sha256sums='),
        ]
        for recipe in recipes:
            with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                self.detect_fixture(recipe=recipe)
            self.assertEqual(self.requests, [])

    def test_fetch_failure_propagates(self):
        def fetch(_url):
            raise RuntimeError('HTTP 503')
        with self.assertRaisesRegex(RuntimeError, 'HTTP 503'):
            detect(RECIPE, fetch, lambda _left, _right: 1)

    def test_invalid_vercmp_result_rejected(self):
        with self.assertRaisesRegex(ValueError, "vercmp"):
            self.detect_fixture(comparison=2)


if __name__ == '__main__':
    unittest.main()
