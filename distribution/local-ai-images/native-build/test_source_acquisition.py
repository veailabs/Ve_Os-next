import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parent / "llamacpp-context/scripts/acquire-sources.py"
spec = importlib.util.spec_from_file_location("ve_source_acquisition", SCRIPT)
acquire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acquire)


class SourceAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "work").mkdir()
        (self.root / "out").mkdir()
        self.acquisition = acquire.Acquisition(self.root / "work", self.root / "out")

    def test_unpinned_skip_source_cannot_be_reported_complete(self):
        with self.assertRaisesRegex(RuntimeError, "Unresolved original source identity"):
            acquire.source_integrity({"source": ["git+https://git.savannah.gnu.org/git/gnulib.git"], "b2sums": ["SKIP"]})

    def test_detached_signatures_and_exact_vcs_commits_are_not_blanket_rejected(self):
        acquire.source_integrity({"source": ["https://example.invalid/source.tar.gz", "https://example.invalid/source.tar.gz.sig", "git+https://example.invalid/source.git#commit=" + "a" * 40],
                                  "sha256sums": ["b" * 64, "SKIP", "SKIP"]})

    def test_verified_signed_coreutils_and_gitlink_sources_pass_integrity(self):
        sources = ["git+https://git.savannah.gnu.org/git/coreutils.git?signed#tag=v9.12",
                   "git+https://git.savannah.gnu.org/git/gnulib.git"]
        srcinfo = {"source": sources, "b2sums": ["SKIP", "SKIP"]}
        responses = [b"", acquire.COREUTILS_COMMIT.encode(), acquire.COREUTILS_TREE.encode(),
                     ("160000 commit " + acquire.GNULIB_COMMIT + "\tgnulib").encode(), acquire.GNULIB_TREE.encode(), b""]
        with patch.object(self.acquisition, "run", side_effect=responses) as run:
            resolved, proof = self.acquisition.resolve_sources("coreutils", srcinfo, self.root)
        acquire.source_integrity(srcinfo, resolved)
        self.assertEqual(set(resolved), set(sources))
        self.assertEqual(proof["commit"], acquire.GNULIB_COMMIT)
        self.assertEqual(run.call_args_list[0].args[0], ["makepkg", "--verifysource", "--noconfirm", "--nocolor"])
        self.assertTrue(all(call.kwargs["user"] for call in run.call_args_list))
        for index in (0, 1, 2, 3, 4, 5):
            failures = list(responses)
            failures[index] = RuntimeError("verification failed") if index in (0, 5) else b"changed identity"
            with self.subTest(check=index), patch.object(self.acquisition, "run", side_effect=failures), self.assertRaises(RuntimeError):
                self.acquisition.resolve_sources("coreutils", srcinfo, self.root)

    def test_source_checksum_coverage_and_arch_scope_are_enforced(self):
        for value in ({"source": ["source"]}, {"source": ["one", "two"], "sha256sums": ["a" * 64]},
                      {"source_x86_64": ["source"], "sha256sums_x86_64": ["SKIP"]}):
            with self.assertRaises(RuntimeError):
                acquire.source_integrity(value)

    def test_source_groups_keep_complete_members_and_verify_actual_bytes(self):
        content = b"complete compressed source bytes"
        path = self.root / "source.src.tar.gz"
        path.write_bytes(content)
        entry = self.acquisition.add(path, "packages/1.src.tar.gz")
        self.acquisition.finish_group()
        proof = self.acquisition.groups[0]
        archive = self.root / "out" / proof["name"]
        self.assertEqual(proof["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        with tarfile.open(archive) as stream:
            self.assertEqual(stream.extractfile(entry["path"]).read(), content)
        self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())

    def test_complete_component_larger_than_asset_cap_fails_without_splitting(self):
        path = self.root / "source"
        path.write_bytes(b"a" * 1024)
        with patch.object(acquire, "GROUP_LIMIT", 1024), self.assertRaisesRegex(RuntimeError, "complete source component"):
            self.acquisition.add(path, "packages/1.src.tar.gz")
        self.assertEqual(self.acquisition.entries, [])

    def test_sources_cannot_escape_or_be_symlinked_into_export(self):
        path = self.root / "source"
        path.write_bytes(b"source")
        linked = self.root / "linked"
        linked.symlink_to(path)
        for candidate, name in ((linked, "packages/1.src.tar.gz"), (path, "../outside")):
            with self.assertRaises(RuntimeError):
                self.acquisition.add(candidate, name)

    def test_archive_download_checks_bytes_hash_size_and_origin(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "https://archive.archlinux.org/packages/f/fixture/fixture.pkg.tar.zst"
        body = b"authentic fixture archive"
        with patch.object(acquire.urllib.request, "urlopen", return_value=Response(body)):
            self.acquisition.download(Response().geturl(), self.root / "download", len(body), hashlib.sha256(body).hexdigest())
        with patch.object(acquire.urllib.request, "urlopen", return_value=Response(body)), self.assertRaisesRegex(RuntimeError, "hash/size"):
            self.acquisition.download(Response().geturl(), self.root / "wrong", len(body), "0" * 64)
        with self.assertRaisesRegex(RuntimeError, "official archive"):
            self.acquisition.download("https://attacker.invalid/package", self.root / "outside", 1, "0" * 64)

    def test_package_signature_must_be_valid_and_trusted_not_merely_present(self):
        row = {"name": "fixture", "url": "https://archive.archlinux.org/package", "bytes": 1, "sha256": "a" * 64, "pgp_signature_base64": "YQ=="}
        for status in (b"[GNUPG:] VALIDSIG fingerprint\n", b"[GNUPG:] VALIDSIG fingerprint\n[GNUPG:] TRUST_FULLY\n[GNUPG:] REVKEYSIG fingerprint\n"):
            with patch.object(self.acquisition, "download"), patch.object(self.acquisition, "run", return_value=status), self.assertRaises(RuntimeError):
                self.acquisition.package(row, self.root / "out")

    def test_actual_catalog_has_old_and_current_versions_with_independent_hashes(self):
        catalog = json.loads(SCRIPT.parent.parent.joinpath("metadata/source-package-archives.json").read_text())
        coreutils = [row for row in catalog["packages"] if row["name"] == "coreutils"]
        self.assertGreater(len(coreutils), 1)
        self.assertEqual(len({row["version"] for row in coreutils}), len(coreutils))
        self.assertEqual(len({row["sha256"] for row in coreutils}), len(coreutils))


if __name__ == "__main__":
    unittest.main()
