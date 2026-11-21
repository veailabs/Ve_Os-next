import gzip
import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch

import arch_packages as packages
from native_profile import PROFILE, QualificationError


IDENTITY = {"name": "fixture-runtime", "version": "2:1.0-3", "base": "fixture", "architecture": "x86_64"}
RECIPE = b"pkgbase=fixture\npkgname=(fixture-runtime)\npkgver=1.0\npkgrel=3\nepoch=2\n"


def metadata():
    return {".PKGINFO": b"pkgname = fixture-runtime\npkgbase = fixture\npkgver = 2:1.0-3\narch = x86_64\nlicense = MIT\nlicense = BSD-2-Clause\n",
            ".BUILDINFO": ("format = 2\npkgname = fixture-runtime\npkgbase = fixture\npkgver = 2:1.0-3\npkgarch = x86_64\npkgbuild_sha256sum = " + hashlib.sha256(RECIPE).hexdigest() + "\ninstalled = gcc-1.0-1-x86_64\ninstalled = glibc-1.0-1-x86_64\n").encode(),
            ".MTREE": gzip.compress(b"#mtree\n./usr/bin/fixture type=file\n", mtime=0)}


def archive_bytes(files=None, extra=()):
    files = {**metadata(), "usr/bin/fixture": b"executable bytes"} if files is None else files
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for path, content in files.items():
            member = tarfile.TarInfo(path)
            member.mode = 0o755 if path == "usr/bin/fixture" else 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for member in extra:
            archive.addfile(member)
    return io.BytesIO(stream.getvalue())


class ArchPackageTests(unittest.TestCase):
    def test_actual_metadata_binds_original_recipe_without_executing_it(self):
        observed = packages.read_package_tar(archive_bytes())
        result = packages.metadata_binding(observed["metadata"], IDENTITY, RECIPE)
        self.assertTrue(result["recipe_bound"])
        self.assertEqual(result["licenses"], ["MIT", "BSD-2-Clause"])
        self.assertEqual(len(result["build_environment"]), 2)
        self.assertEqual(observed["files"]["usr/bin/fixture"]["sha256"], hashlib.sha256(b"executable bytes").hexdigest())

    def test_candidate_recipe_hash_is_not_a_producer_binding(self):
        with self.assertRaisesRegex(QualificationError, "actual producer BUILDINFO"):
            packages.metadata_binding(metadata(), IDENTITY, RECIPE + b"\n")
        result = packages.metadata_binding(metadata(), IDENTITY)
        self.assertFalse(result["recipe_bound"])

    def test_package_base_epoch_architecture_and_buildinfo_must_agree(self):
        for key, bad in (("base", "other"), ("version", "1.0-3"), ("architecture", "any")):
            with self.subTest(key=key), self.assertRaises(QualificationError):
                packages.metadata_binding(metadata(), {**IDENTITY, key: bad}, RECIPE)
        raw = metadata()
        raw[".BUILDINFO"] = raw[".BUILDINFO"].replace(b"fixture-runtime", b"other-runtime")
        with self.assertRaises(QualificationError):
            packages.metadata_binding(raw, IDENTITY, RECIPE)

    def test_absent_metadata_is_never_replaced_by_placeholder(self):
        for name in packages.METADATA_NAMES:
            raw = metadata()
            del raw[name]
            with self.assertRaisesRegex(QualificationError, "authentic package producer metadata"):
                packages.read_package_tar(archive_bytes(raw))

    def test_metadata_symlink_duplicate_and_traversal_fail(self):
        linked = tarfile.TarInfo(".BUILDINFO")
        linked.type = tarfile.SYMTYPE
        linked.linkname = "/host-secret"
        raw = metadata()
        del raw[".BUILDINFO"]
        duplicate = tarfile.TarInfo(".PKGINFO")
        for files, extra in ((raw, [linked]), (metadata(), [duplicate]), ({**metadata(), "../outside": b"bad"}, [])):
            with self.assertRaises(QualificationError):
                packages.read_package_tar(archive_bytes(files, extra))

    def test_duplicate_singular_field_and_wrong_build_format_fail(self):
        for suffix in (b"pkgname = duplicate\n", b"format = 2\n"):
            raw = metadata()
            raw[".BUILDINFO"] += suffix
            with self.assertRaises(QualificationError):
                packages.metadata_binding(raw, IDENTITY)
        raw = metadata()
        raw[".BUILDINFO"] = raw[".BUILDINFO"].replace(b"format = 2", b"format = 99")
        with self.assertRaises(QualificationError):
            packages.metadata_binding(raw, IDENTITY)

    def test_decompression_and_metadata_limits_fail(self):
        with patch.dict(PROFILE, {"disk_growth_bytes": 512}), self.assertRaises(QualificationError):
            packages.read_package_tar(archive_bytes())
        raw = metadata()
        raw[".MTREE"] = gzip.compress(b"#mtree\n" + b"x" * 8192)
        with patch.dict(PROFILE, {"document_bytes": 1024}), self.assertRaises(QualificationError):
            packages.metadata_binding(raw, IDENTITY)

    def test_same_mtree_is_not_proof_actual_image_bytes_match(self):
        archive = packages.read_package_tar(archive_bytes())
        original = archive["files"]["usr/bin/fixture"]
        actual = {"usr/bin/fixture": {**original, "sha256": "0" * 64}}
        result = packages.compare_package_files(archive, ["usr/bin/fixture"], actual)
        self.assertFalse(result["all_owned_paths_match"])
        self.assertEqual(result["differences"][0]["fields"], ["sha256"])

    def test_ownership_absence_type_mode_and_symlink_changes_are_explicit(self):
        archive = packages.read_package_tar(archive_bytes())
        original = archive["files"]["usr/bin/fixture"]
        for actual in ({}, {"usr/bin/fixture": {**original, "mode": 0o777}}, {"usr/bin/fixture": {"kind": "symlink", "target": "/other"}}):
            self.assertFalse(packages.compare_package_files(archive, ["usr/bin/fixture"], actual)["all_owned_paths_match"])
        with self.assertRaises(QualificationError):
            packages.compare_package_files(archive, ["usr/bin/invented"], {})

    def test_matching_hardlink_contents_and_metadata_are_compared(self):
        linked = tarfile.TarInfo("usr/bin/alias")
        linked.type = tarfile.LNKTYPE
        linked.linkname = "usr/bin/fixture"
        linked.mode = 0o755
        archive = packages.read_package_tar(archive_bytes(extra=[linked]))
        actual = dict(archive["files"])
        actual["usr/bin/alias"] = {**actual["usr/bin/alias"], "kind": "file"}
        result = packages.compare_package_files(archive, ["usr/bin/fixture", "usr/bin/alias"], actual)
        self.assertTrue(result["all_owned_paths_match"])

    def test_untrusted_install_script_is_observed_as_bytes_only(self):
        raw = {**metadata(), ".INSTALL": b"touch /outside\n"}
        observed = packages.read_package_tar(archive_bytes(raw))
        self.assertEqual(observed["files"][".INSTALL"]["sha256"], hashlib.sha256(raw[".INSTALL"]).hexdigest())


if __name__ == "__main__":
    unittest.main()
