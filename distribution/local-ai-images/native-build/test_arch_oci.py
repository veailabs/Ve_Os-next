import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import arch_oci
from native_profile import QualificationError
from test_arch_inventory import layer, package


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def descriptor(data, kind):
    return {"digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data), "mediaType": kind}


class ArchOciTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "image.oci.tar"
        self.context = "a" * 64

    def image(self, bad_diff=False, extra=None):
        digest, diff, blob = layer(package())
        raw_layer = blob.getvalue()
        config = encoded({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "0" * 64 if bad_diff else diff]},
                          "config": {"Labels": {"org.opencontainers.image.revision": "sha256:" + self.context,
                                                "org.opencontainers.image.source": "urn:ve-os:local-source:sha256:" + self.context}}})
        manifest = encoded({"schemaVersion": 2, "mediaType": arch_oci.publisher.MANIFEST,
                            "config": descriptor(config, arch_oci.publisher.CONFIG), "layers": [descriptor(raw_layer, arch_oci.publisher.LAYER)]})
        files = {"oci-layout": encoded({"imageLayoutVersion": "1.0.0"}), "index.json": encoded({"schemaVersion": 2, "manifests": [descriptor(manifest, arch_oci.publisher.MANIFEST)]})}
        files.update({"blobs/sha256/" + hashlib.sha256(data).hexdigest(): data for data in (config, manifest, raw_layer)})
        with tarfile.open(self.path, "w") as archive:
            for path, content in files.items():
                member = tarfile.TarInfo(path)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            if extra:
                archive.addfile(extra)

    def test_real_outer_graph_produces_observed_arch_inventory(self):
        self.image()
        result = arch_oci.image_inventory(self.path, self.context)
        self.assertEqual(result["source"]["archive_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(result["inventory"]["final_packages"][0]["base"], "fixture")

    def test_unchanged_publisher_graph_check_alone_cannot_certify_diff_ids(self):
        self.image(bad_diff=True)
        with self.assertRaisesRegex(QualificationError, "diff ID"):
            arch_oci.image_inventory(self.path, self.context)

    def test_real_graph_check_preserves_source_context_validation(self):
        self.image()
        with self.assertRaisesRegex(ValueError, "source revision"):
            arch_oci.image_inventory(self.path, "b" * 64)

    def test_outer_links_traversal_and_duplicates_fail_before_observation(self):
        for path in ("../escape", "index.json", "unexpected"):
            self.image(extra=tarfile.TarInfo(path))
            with self.assertRaises(QualificationError):
                arch_oci.image_inventory(self.path, self.context)

    def test_hardlinked_output_is_rejected(self):
        self.image()
        self.path.with_name("alias").hardlink_to(self.path)
        with self.assertRaises(QualificationError):
            arch_oci.image_inventory(self.path, self.context)


if __name__ == "__main__":
    unittest.main()
