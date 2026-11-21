import gzip
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import unittest

from native_profile import QualificationError
import native_sources as sources


def component(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    data = gzip.compress(raw.getvalue(), mtime=0)
    return io.BytesIO(data), {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class NativeSourceTests(unittest.TestCase):
    def test_real_complete_archive_recipe_hash_is_checked(self):
        recipe = b"pkgname=fixture\n"
        stream, entry = component({"fixture/PKGBUILD": recipe, "fixture/source.c": b"int main(void) {}\n"})
        sources.inspect_component(stream, entry, time.monotonic() + 10, recipe_path="fixture/PKGBUILD", recipe_hash=hashlib.sha256(recipe).hexdigest())

    def test_recipe_omission_or_changed_source_archive_is_rejected(self):
        for files in ({"fixture/source": b"only payload"}, {"fixture/PKGBUILD": b"changed"}):
            stream, entry = component(files)
            with self.assertRaises(QualificationError):
                sources.inspect_component(stream, entry, time.monotonic() + 10, recipe_path="fixture/PKGBUILD", recipe_hash="a" * 64)

    def test_matching_recipe_cannot_hide_an_omitted_declared_source(self):
        recipe = b"pkgname=fixture\n"
        stream, entry = component({"fixture/PKGBUILD": recipe})
        with self.assertRaisesRegex(QualificationError, "omitted a declared source"):
            sources.inspect_component(stream, entry, time.monotonic() + 10, recipe_path="fixture/PKGBUILD",
                                      recipe_hash=hashlib.sha256(recipe).hexdigest(), required_members=["fixture/original.tar.gz"])

    def test_source_component_traversal_hash_and_deadline_are_enforced(self):
        stream, entry = component({"../outside": b"bad"})
        with self.assertRaises(QualificationError):
            sources.inspect_component(stream, entry, time.monotonic() + 10)
        stream, entry = component({"safe": b"source"})
        with self.assertRaises(QualificationError):
            sources.inspect_component(stream, {**entry, "sha256": "0" * 64}, time.monotonic() + 10)
        stream, entry = component({"safe": b"source"})
        with self.assertRaises(QualificationError):
            sources.inspect_component(stream, entry, time.monotonic() - 1)

    def test_git_source_tree_matches_real_git_archive_including_modes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*arguments):
                return subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True).stdout
            git("init", "--quiet")
            (root / "a").mkdir()
            (root / "a/file").write_text("source\n")
            (root / "a/file-two").write_text("other\n")
            (root / "a.b").write_text("sort boundary\n")
            (root / "a/command").write_text("#!/bin/sh\nexit 0\n")
            (root / "a/command").chmod(0o755)
            (root / "link").symlink_to("a/file")
            git("add", ".")
            tree = git("write-tree").decode().strip()
            raw = git("archive", "--format=tar.gz", tree)
            entry = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            sources.inspect_component(io.BytesIO(raw), entry, time.monotonic() + 10, tree=tree)
            with self.assertRaisesRegex(QualificationError, "tree differs"):
                sources.inspect_component(io.BytesIO(raw), entry, time.monotonic() + 10, tree="0" * 40)

    def test_git_directory_conflicts_are_rejected(self):
        with self.assertRaises(QualificationError):
            sources.git_tree({"directory": ("100644", "a" * 40), "directory/file": ("100644", "b" * 40)})


if __name__ == "__main__":
    unittest.main()
