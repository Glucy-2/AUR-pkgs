"""Boundary fixtures for authoritative Neo4j Community detection."""

import hashlib
import io
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import detect_neo4j as detector


def _ar_member(name, data):
    header = (
        name.ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
        + "100644".ljust(8) + str(len(data)).ljust(10) + "`\n"
    ).encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def _deb(depends, version="2026.09.0", data_names=("data.tar.xz",)):
    control = (
        "Package: neo4j\nVersion: 1:" + version + "\nArchitecture: all\nDepends: "
        + depends + "\nDescription: fixture\n continued description\n"
    ).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:xz") as archive:
        item = tarfile.TarInfo("./control")
        item.size = len(control)
        archive.addfile(item, io.BytesIO(control))
    return (
        b"!<arch>\n" + _ar_member("debian-binary", b"2.0\n")
        + _ar_member("control.tar.xz", out.getvalue())
        + b"".join(_ar_member(name, b"fixture payload") for name in data_names)
    )


def _numeric_compare(left, right):
    # Injected comparator fixture, not the production Arch version comparison.
    left = tuple(map(int, left.split(".")))
    right = tuple(map(int, right.split(".")))
    return (left > right) - (left < right)


class CommunityLinksTests(unittest.TestCase):
    def test_edition_and_version_filtering(self):
        html = '''
        <a href="https://go.neo4j.com/download-thanks.html?edition=community&amp;release=2026.09.0&amp;flavour=deb">download</a>
        <li data-url="https://go.neo4j.com/download-thanks.html?release=2026.10.2&edition=community&flavour=rpm"></li>
        <a href="/download/?edition=enterprise&release=2099.12.9"></a>
        <a href="/download/?edition=desktop&release=2099.12.8"></a>
        <a href="/download/?edition=community&release=5.26.32"></a>
        <a href="/download/?edition=community&release=2026.09.0-alpha"></a>
        <a href="/download/?edition=community&release=2026.13.0"></a>
        <a href="https://example.org/?edition=community&release=2099.12.7"></a>
        <script>var release = "2099.12.6";</script>
        '''
        self.assertEqual(detector.community_versions(html), {"2026.09.0", "2026.10.2"})

    def test_missing_community_release_fails(self):
        with self.assertRaises(ValueError):
            detector.community_versions('<a href="?edition=enterprise&release=2026.09.0"></a>')

    def test_duplicate_release_query_fails(self):
        with self.assertRaises(ValueError):
            detector.community_versions('<a href="?edition=community&release=2026.09.0&release=2026.10.0"></a>')


class JavaDependsTests(unittest.TestCase):
    def test_authoritative_alternatives_have_unambiguous_minimum(self):
        depends = (
            "daemon, adduser, psmisc, java25-runtime | jdk-25 | java21-runtime | jdk-21, "
            "cypher-shell (>= 1:2026.09.0), cypher-shell (<< 2:0.0.0)"
        )
        self.assertEqual(detector.java_minimum(depends), 21)

    def test_conjunction_uses_highest_required_minimum(self):
        self.assertEqual(detector.java_minimum("java21-runtime, java25-runtime | jdk-25"), 25)

    def test_explicit_generic_lower_bound(self):
        self.assertEqual(detector.java_minimum("java-runtime (>= 21), psmisc"), 21)

    def test_openjdk_providers(self):
        self.assertEqual(detector.java_minimum("openjdk-21-jre-headless | openjdk-25-jdk"), 21)

    def test_ambiguous_or_missing_java_is_rejected(self):
        cases = (
            "daemon, psmisc",
            "default-jre",
            "java-runtime",
            "java21-runtime | vendor-runtime",
            "java21-runtime | default-jre",
            "java-runtime (<< 26)",
            "java-runtime (>= 21.0.1)",
            "java-runtime (>> 21)",
            "java21-runtime [amd64]",
            "java21-runtime:any",
            "java21-runtime |",
            "java0-runtime",
        )
        for depends in cases:
            with self.subTest(depends=depends), self.assertRaises(ValueError):
                detector.java_minimum(depends)


class DetectTests(unittest.TestCase):
    def fixture_fetch(self, deb, html=None, checksum=None):
        html = html or '<li data-url="https://go.neo4j.com/download-thanks.html?edition=community&release=2026.09.0&flavour=deb"></li>'
        checksum = checksum or hashlib.sha256(deb).hexdigest()
        responses = {
            detector.DEPLOYMENT_CENTER: html.encode(),
            "https://dist.neo4j.org/deb/neo4j_2026.09.0_all.deb.sha256": checksum.encode(),
            "https://dist.neo4j.org/deb/neo4j_2026.09.0_all.deb": deb,
        }
        return responses.__getitem__

    def test_candidate_fields_and_authoritative_digest(self):
        deb = _deb("java25-runtime | java21-runtime")
        result = detector.detect("", self.fixture_fetch(deb), _numeric_compare)
        self.assertEqual(result["candidate_version"], "2026.09.0")
        self.assertEqual(result["fields"], {"pkgver": "2026.09.0", "_min_java_version": "21"})
        self.assertEqual(result["source"], detector.DEPLOYMENT_CENTER)
        self.assertEqual(result["expected_sha256"], hashlib.sha256(deb).hexdigest())

    def test_highest_release_selected_with_injected_vercmp(self):
        html = ''.join(
            '<a href="?edition=community&release=' + version + '"></a>'
            for version in ("2026.09.0", "2026.09.10", "2026.09.2")
        )
        deb = _deb("java21-runtime", version="2026.09.10")
        calls = []

        def compare(left, right):
            calls.append((left, right))
            return _numeric_compare(left, right)

        def fetch(url):
            if url == detector.DEPLOYMENT_CENTER:
                return html.encode()
            self.assertIn("neo4j_2026.09.10_all.deb", url)
            return hashlib.sha256(deb).hexdigest().encode() if url.endswith(".sha256") else deb

        result = detector.detect("", fetch, compare)
        self.assertEqual(result["candidate_version"], "2026.09.10")
        self.assertEqual(len(calls), 2)

    def test_digest_mismatch_fails(self):
        deb = _deb("java21-runtime")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            detector.detect("", self.fixture_fetch(deb, checksum="0" * 64), _numeric_compare)

    def test_control_version_mismatch_fails(self):
        deb = _deb("java21-runtime", version="2026.08.0")
        with self.assertRaisesRegex(ValueError, "identity/version"):
            detector.detect("", self.fixture_fetch(deb), _numeric_compare)

    def test_duplicate_depends_field_fails(self):
        with self.assertRaises(ValueError):
            detector._control_fields("Package: neo4j\nDepends: java21-runtime\nDepends: java25-runtime\n")

    def test_wrapped_depends_are_unfolded(self):
        fields = detector._control_fields("Depends: java25-runtime |\n java21-runtime, psmisc\n")
        self.assertEqual(detector.java_minimum(fields["depends"]), 21)

    def test_unique_supported_data_archive_required(self):
        for names in ((), ("data.tar.xz", "data.tar.zst"), ("data.tar.bz2",)):
            with self.subTest(names=names), self.assertRaises(ValueError):
                detector.deb_control(_deb("java21-runtime", data_names=names))
        for name in ("data.tar.xz", "data.tar.zst", "data.tar.gz"):
            with self.subTest(name=name):
                self.assertIn("Depends: java21-runtime", detector.deb_control(_deb("java21-runtime", data_names=(name,))))


if __name__ == "__main__":
    unittest.main()
