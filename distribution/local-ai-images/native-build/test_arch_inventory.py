import gzip
import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch

import arch_inventory as arch
from native_profile import PROFILE, QualificationError


def layer(files, extra=(), pax_headers=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.pax_headers = (pax_headers or {}).get(name, {})
            archive.addfile(member, io.BytesIO(data))
        for member in extra:
            archive.addfile(member)
    raw = output.getvalue()
    compressed = gzip.compress(raw, mtime=0)
    return "sha256:" + hashlib.sha256(compressed).hexdigest(), "sha256:" + hashlib.sha256(raw).hexdigest(), io.BytesIO(compressed)


def package(name="fixture", version="1-1", payload=b"first"):
    root = arch.PACKAGE_ROOT + name + "-" + version + "/"
    return {root + "desc": ("%NAME%\n" + name + "\n\n%VERSION%\n" + version + "\n\n%BASE%\n" + name + "\n\n%ARCH%\nx86_64\n\n").encode(),
            root + "files": b"%FILES%\nusr/bin/fixture\n\n", root + "mtree": gzip.compress(b"#mtree\n./usr/bin/fixture type=file\n", mtime=0),
            "usr/bin/fixture": payload}


class ArchLayerTests(unittest.TestCase):
    def test_actual_layer_metadata_is_observed_without_extracting(self):
        report = arch.observe_layers([layer(package())])
        self.assertEqual(len(report["physical_packages"]), 1)
        self.assertEqual(report["final_packages"][0]["version"], "1-1")
        self.assertEqual(report["filesystem"]["usr/bin/fixture"]["sha256"], hashlib.sha256(b"first").hexdigest())
        self.assertEqual(set(report["final_packages"][0]["metadata"]), {"desc", "files", "mtree"})

    def test_security_attributes_cannot_hide_behind_unchanged_executable_bytes(self):
        for key in ("SCHILY.xattr.security.capability", "SCHILY.xattr.security.selinux", "SCHILY.acl.access",
                    "LIBARCHIVE.xattr.security.capability", "SCHILY.fflags", "unknown.security.attribute"):
            with self.subTest(attribute=key), self.assertRaisesRegex(QualificationError, "Unsupported archive extended attributes"):
                arch.observe_layers([layer(package(), pax_headers={"usr/bin/fixture": {key: "added privilege"}})])
        report = arch.observe_layers([layer(package(), pax_headers={"usr/bin/fixture": {"mtime": "123.25"}})])
        self.assertEqual(report["filesystem"]["usr/bin/fixture"]["sha256"], hashlib.sha256(b"first").hexdigest())

    def test_upgrade_preserves_distributed_old_source_identity(self):
        upgrade = package(version="2-1", payload=b"second")
        upgrade[arch.PACKAGE_ROOT + ".wh.fixture-1-1"] = b""
        report = arch.observe_layers([layer(package()), layer(upgrade)])
        self.assertEqual({item["version"] for item in report["physical_packages"]}, {"1-1", "2-1"})
        self.assertEqual([item["version"] for item in report["final_packages"]], ["2-1"])
        old = report["physical_files"][0]["entries"]["usr/bin/fixture"]
        self.assertEqual(old["sha256"], hashlib.sha256(b"first").hexdigest())

    def test_opaque_whiteout_does_not_erase_lower_layer_source_union(self):
        upgrade = {arch.PACKAGE_ROOT + ".wh..wh..opq": b"", **package(version="2-1")}
        report = arch.observe_layers([layer(package()), layer(upgrade)])
        self.assertEqual(len(report["physical_packages"]), 2)
        self.assertEqual(len(report["final_packages"]), 1)

    def test_missing_authentic_files_never_becomes_empty_placeholder(self):
        files = package()
        del files[arch.PACKAGE_ROOT + "fixture-1-1/files"]
        with self.assertRaisesRegex(QualificationError, "missing authentic files"):
            arch.observe_layers([layer(files)])

    def test_genuine_empty_metapackage_file_inventory_is_distinct_from_missing(self):
        files = package()
        files[arch.PACKAGE_ROOT + "fixture-1-1/files"] = b"%FILES%\n\n"
        report = arch.observe_layers([layer(files)])
        self.assertEqual(len(report["final_packages"]), 1)

    def test_wrong_diff_id_and_blob_identity_are_rejected(self):
        digest, diff_id, stream = layer(package())
        with self.assertRaisesRegex(QualificationError, "Compressed"):
            arch.observe_layers([("sha256:" + "0" * 64, diff_id, stream)])
        digest, diff_id, stream = layer(package())
        with self.assertRaisesRegex(QualificationError, "diff ID"):
            arch.observe_layers([(digest, "sha256:" + "0" * 64, stream)])

    def test_duplicate_paths_and_traversal_fail(self):
        duplicate = tarfile.TarInfo("usr/bin/fixture")
        for files, extra in (({**package(), "../outside": b"bad"}, ()), (package(), (duplicate,))):
            with self.assertRaises(QualificationError):
                arch.observe_layers([layer(files, extra)])

    def test_package_evidence_cannot_be_symlinked(self):
        files = package()
        path = arch.PACKAGE_ROOT + "fixture-1-1/files"
        del files[path]
        linked = tarfile.TarInfo(path)
        linked.type = tarfile.SYMTYPE
        linked.linkname = "/outside"
        with self.assertRaises(QualificationError):
            arch.observe_layers([layer(files, [linked])])

    def test_writes_through_symlink_ancestors_are_rejected(self):
        link = tarfile.TarInfo("etc")
        link.type = tarfile.SYMTYPE
        link.linkname = "/outside"
        with self.assertRaisesRegex(QualificationError, "non-directory"):
            arch.observe_layers([layer(package(), [link]), layer({"etc/evil": b"bad"})])

    def test_existing_hardlink_keeps_its_original_inode_content_after_target_replacement(self):
        link = tarfile.TarInfo("usr/bin/alias")
        link.type = tarfile.LNKTYPE
        link.linkname = "usr/bin/fixture"
        report = arch.observe_layers([layer(package(), [link]), layer({"usr/bin/fixture": b"replacement"})])
        self.assertEqual(report["filesystem"]["usr/bin/alias"]["sha256"], hashlib.sha256(b"first").hexdigest())

    def test_layer_expansion_and_evidence_caps_fail_instead_of_truncation(self):
        sample = layer(package(payload=b"x" * 8192))
        with patch.dict(PROFILE, {"disk_growth_bytes": 4096}), self.assertRaises(QualificationError):
            arch.observe_layers([sample])
        with patch.dict(PROFILE, {"metadata_bytes": 1}), self.assertRaises(QualificationError):
            arch.observe_layers([layer(package())])

    def test_invalid_or_repeated_package_identity_fields_fail(self):
        raw = package()[arch.PACKAGE_ROOT + "fixture-1-1/desc"]
        for content in (raw + b"%NAME%\nother\n\n", raw.replace(b"x86_64", b"aarch64"), raw.replace(b"%BASE%\nfixture\n\n", b"")):
            with self.assertRaises(QualificationError):
                arch.package_identity(content)

    def test_nonzero_hidden_data_after_tar_end_is_rejected(self):
        _, _, compressed = layer(package())
        raw = gzip.decompress(compressed.getvalue()) + b"hidden"
        packed = gzip.compress(raw, mtime=0)
        with self.assertRaisesRegex(QualificationError, "after image tar end"):
            arch.observe_layers([("sha256:" + hashlib.sha256(packed).hexdigest(), "sha256:" + hashlib.sha256(raw).hexdigest(), io.BytesIO(packed))])


if __name__ == "__main__":
    unittest.main()
