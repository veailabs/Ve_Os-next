import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tarfile
import time
from urllib.parse import quote, urlparse
import urllib.request


GIB = 1024 ** 3
DOCUMENT_LIMIT = 4 * 1024 ** 2
SOURCE_LIMIT = 4 * GIB
GROUP_LIMIT = GIB
BASE_SOURCE = "d9f7a01562208910488140c54ffe402c3e7a231e"
LLAMA_SOURCE = "6f311d7ad63dce97a3ad1deaafb7cc044bb8c26c"
LLAMA_TREE = "4f4e5909f01bb09924a9005dc3c94705aff0f9b1"
COREUTILS_COMMIT = "c0f8514d989184921d9b12a4d103a7b23abc5af8"
COREUTILS_TREE = "a6bdb4d2e19672e3ef377c4d14213ae10d774a03"
GNULIB_COMMIT = "106e9b2384d08a1696fcbd40cbab52237943f208"
GNULIB_TREE = "63974be080d5aabd280801f327f49977bde164ce"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fields(raw):
    result = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        require(separator and re.fullmatch(r"[a-z][a-z0-9_]*", key), "Invalid package/source metadata assignment")
        result.setdefault(key, []).append(value)
    return result


def one(values, key):
    require(len(values.get(key, [])) == 1, "Missing or ambiguous metadata field: " + key)
    return values[key][0]


def source_integrity(srcinfo, resolved=()):
    gaps = []
    for scope in ("", "_x86_64"):
        sources = srcinfo.get("source" + scope, [])
        sums = [srcinfo[name + scope] for name in ("sha256sums", "sha512sums", "b2sums", "sha384sums", "sha224sums", "sha1sums", "md5sums") if name + scope in srcinfo]
        require(not sources or sums, "Source array has no supported integrity evidence")
        require(all(len(values) == len(sources) for values in sums), "Source and checksum counts differ")
        for index, source in enumerate(sources):
            if any(values[index] != "SKIP" for values in sums):
                continue
            endpoint = source.split("::", 1)[-1]
            if endpoint.endswith((".sig", ".sign", ".asc")):
                continue
            if endpoint.startswith("git+") and re.search(r"#commit=[0-9a-f]{40}$", endpoint):
                continue
            if source in resolved:
                continue
            gaps.append(source)
    require(not gaps, "Unresolved original source identity for SKIP entry: " + ", ".join(gaps))


class Acquisition:
    def __init__(self, root, output, timeout=9000):
        self.root = root
        self.output = output
        self.deadline = time.monotonic() + timeout
        self.sequence = 0
        self.group = None
        self.group_bytes = 0
        self.total_bytes = 0
        self.groups = []
        self.entries = []

    def remaining(self):
        seconds = self.deadline - time.monotonic()
        require(seconds > 0, "Source acquisition deadline exceeded")
        return seconds

    def run(self, argv, cwd=None, user=False):
        self.sequence += 1
        log = self.root / ("command-" + str(self.sequence) + ".log")
        if user:
            argv = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                    "env", "-u", "GNULIB_SRCDIR", "-u", "GNULIB_REVISION", "-u", "GNULIB_REFDIR",
                    "HOME=" + str(cwd), "GNUPGHOME=" + str(cwd / "gnupg"),
                    "SRCDEST=" + str(cwd / "sources"), "SRCPKGDEST=" + str(cwd / "archives"), "SRCEXT=.src.tar.gz", "LC_ALL=C", *argv]
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            observed = 0
            with log.open("xb") as stream, selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    for key, _ in selector.select(timeout=min(0.2, self.remaining())):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        observed += len(block)
                        require(observed <= DOCUMENT_LIMIT, "Source subprocess log exceeds metadata limit")
                        stream.write(block)
            returncode = process.wait(timeout=self.remaining())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()
        content = log.read_bytes()
        log.unlink()
        require(returncode == 0, "Source subprocess failed: " + argv[0] + " (exit " + str(returncode) + "): " + content[-4096:].decode(errors="replace"))
        return content

    def download(self, url, path, size, digest):
        parsed = urlparse(url)
        require(parsed.scheme == "https" and parsed.hostname == "archive.archlinux.org" and not parsed.username and not parsed.password, "Package archive URL is not the official archive")
        request = urllib.request.Request(url, headers={"User-Agent": "Ve-OS-source-acquisition/1"})
        actual = 0
        value = hashlib.sha256()
        with urllib.request.urlopen(request, timeout=min(30, self.remaining())) as response, path.open("xb") as stream:
            require(urlparse(response.geturl()).scheme == "https" and urlparse(response.geturl()).hostname == parsed.hostname, "Unexpected archive redirect")
            while block := response.read(65536):
                self.remaining()
                actual += len(block)
                require(actual <= size <= GIB, "Original package archive exceeds retained size")
                value.update(block)
                stream.write(block)
        require(actual == size and value.hexdigest() == digest, "Original package archive hash/size differs")

    def api(self, url):
        require(url.startswith("https://gitlab.archlinux.org/api/v4/"), "Unexpected packaging API")
        request = urllib.request.Request(url, headers={"User-Agent": "Ve-OS-source-acquisition/1"})
        with urllib.request.urlopen(request, timeout=min(30, self.remaining())) as response:
            require(response.geturl().startswith("https://gitlab.archlinux.org/api/v4/"), "Unexpected packaging API redirect")
            raw = response.read(DOCUMENT_LIMIT + 1)
        require(len(raw) <= DOCUMENT_LIMIT, "Packaging metadata exceeds limit")
        return json.loads(raw)

    def add(self, path, name):
        require(re.fullmatch(r"[a-z0-9._/-]+", name) and ".." not in name.split("/"), "Invalid source bundle member")
        require(path.is_file() and not path.is_symlink(), "Source output is not a regular file")
        size = path.stat().st_size
        entry_bytes = 512 + ((size + 511) // 512) * 512
        require(0 < size and entry_bytes + 10240 <= GROUP_LIMIT, "A complete source component exceeds the per-asset limit")
        if self.group is None or self.group_bytes + entry_bytes + 10240 > GROUP_LIMIT:
            self.finish_group()
            filename = "llamacpp-source-packages-" + str(len(self.groups) + 1).zfill(2) + ".tar"
            self.group = tarfile.open(self.output / filename, "w", format=tarfile.USTAR_FORMAT)
            self.group_bytes = 0
        entry = {"path": name, "bytes": size, "sha256": sha(path), "archive": Path(self.group.name).name}
        member = tarfile.TarInfo(name)
        member.size = size
        member.mode = 0o644
        with path.open("rb") as stream:
            self.group.addfile(member, stream)
        self.group_bytes += entry_bytes
        self.total_bytes += entry_bytes
        require(self.total_bytes + 10240 * (len(self.groups) + 1) <= SOURCE_LIMIT, "Complete sources exceed approved aggregate limit")
        self.entries.append(entry)
        return entry

    def finish_group(self):
        if self.group is not None:
            path = Path(self.group.name)
            self.group.close()
            require(path.stat().st_size <= GROUP_LIMIT, "Source group exceeds asset limit")
            self.groups.append({"name": path.name, "bytes": path.stat().st_size, "sha256": sha(path)})
            self.group = None

    def package(self, row, metadata):
        archive = self.root / "package.pkg.tar.zst"
        signature = self.root / "package.sig"
        self.download(row["url"], archive, row["bytes"], row["sha256"])
        signature.write_bytes(base64.b64decode(row["pgp_signature_base64"], validate=True))
        status = self.run(["gpg", "--batch", "--homedir", "/etc/pacman.d/gnupg", "--no-auto-key-retrieve", "--status-fd", "1", "--verify", str(signature), str(archive)]).decode()
        codes = [line.split()[1] for line in status.splitlines() if line.startswith("[GNUPG:] ") and len(line.split()) > 1]
        require("VALIDSIG" in codes and any(code in codes for code in ("TRUST_FULLY", "TRUST_ULTIMATE")), "Package signature lacks a fully trusted Arch key")
        require(not set(codes) & {"BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG", "EXPSIG", "KEYEXPIRED", "SIGEXPIRED"}, "Package signature is invalid, revoked or expired")
        raw = {}
        for name in (".PKGINFO", ".BUILDINFO", ".MTREE"):
            raw[name] = self.run(["bsdtar", "-xOf", str(archive), name])
            (metadata / name).write_bytes(raw[name])
        package, build = fields(raw[".PKGINFO"]), fields(raw[".BUILDINFO"])
        for name, key in (("name", "pkgname"), ("base", "pkgbase"), ("version", "pkgver")):
            require(one(package, key) == row[name] == one(build, key), "Original archive producer identity differs: " + row["name"])
        require(one(package, "arch") == row["architecture"] == one(build, "pkgarch") and one(build, "format") == "2", "Original archive architecture or BUILDINFO format differs")
        recipe_hash = one(build, "pkgbuild_sha256sum")
        require(re.fullmatch(r"[0-9a-f]{64}", recipe_hash), "Original BUILDINFO has invalid recipe hash")
        inventory = self.root / "package-files.json.gz"
        files = {}
        decoder = subprocess.Popen(["zstd", "--decompress", "--stdout", "--", str(archive)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            expanded = 0
            with tarfile.open(fileobj=decoder.stdout, mode="r|") as contents:
                for member in contents:
                    self.remaining()
                    path = member.name.removeprefix("./").rstrip("/")
                    require(path and not path.startswith("/") and ".." not in path.split("/") and path not in files and len(files) < 500000, "Unsafe or excessive original package file inventory")
                    expanded += member.size
                    require(expanded <= 8 * GIB and not member.issparse(), "Original package expansion exceeds bound")
                    entry = {"path": path, "mode": member.mode, "uid": member.uid, "gid": member.gid}
                    if member.isfile():
                        value = hashlib.sha256()
                        with contents.extractfile(member) as data:
                            while block := data.read(65536):
                                self.remaining()
                                value.update(block)
                        entry.update(kind="file", sha256=value.hexdigest())
                    elif member.isdir():
                        entry["kind"] = "directory"
                    elif member.issym():
                        entry.update(kind="symlink", target=member.linkname)
                    elif member.islnk():
                        entry.update(kind="hardlink", target=member.linkname.removeprefix("./"))
                    else:
                        require(False, "Unsupported original package object")
                    files[path] = entry
            require(decoder.wait(timeout=min(30, self.remaining())) == 0, "Original package decompression failed")
        finally:
            if decoder.poll() is None:
                decoder.kill()
                decoder.wait(timeout=10)
            decoder.stdout.close()
        for path, entry in files.items():
            if entry["kind"] == "hardlink":
                target, visited = entry["target"], {path}
                while True:
                    require(target in files and target not in visited, "Original package has missing or cyclic hardlink")
                    visited.add(target)
                    linked = files[target]
                    if linked["kind"] == "file" or "sha256" in linked:
                        entry["sha256"] = linked["sha256"]
                        break
                    require(linked["kind"] == "hardlink", "Original package hardlink is not a file")
                    target = linked["target"]
        with gzip.open(inventory, "wb") as output:
            for path in sorted(files):
                output.write(json.dumps(files[path], sort_keys=True).encode() + b"\n")
        inventory_entry = self.add(inventory, "package-files/" + row["sha256"] + ".json.gz")
        inventory.unlink()
        proof = {"identity": {key: row[key] for key in ("name", "version", "base", "architecture")}, "archive_sha256": row["sha256"],
                 "archive_bytes": row["bytes"], "pkgbuild_sha256": recipe_hash, "signature_status": status,
                 "metadata": {name: hashlib.sha256(content).hexdigest() for name, content in raw.items()}, "file_inventory": inventory_entry}
        archive.unlink()
        signature.unlink()
        return proof

    def recipe(self, base, version, expected_hash, slot):
        project = quote("archlinux/packaging/packages/" + base, safe="")
        tag = version.replace(":", "-", 1).replace("~", ".")
        record = self.api("https://gitlab.archlinux.org/api/v4/projects/" + project + "/repository/tags/" + quote(tag, safe=""))
        commit = record.get("commit", {}).get("id", "")
        require(re.fullmatch(r"[0-9a-f]{40}", commit), "Official packaging tag has no exact commit: " + base)
        work = self.root / ("recipe-" + str(slot))
        work.mkdir()
        self.run(["git", "init", "--quiet", str(work)])
        self.run(["git", "-C", str(work), "fetch", "--quiet", "--depth=1", "https://gitlab.archlinux.org/archlinux/packaging/packages/" + base + ".git", commit])
        self.run(["git", "-C", str(work), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
        require(self.run(["git", "-C", str(work), "rev-parse", "HEAD"]).decode().strip() == commit, "Fetched packaging commit differs")
        require(sha(work / "PKGBUILD") == expected_hash, "Official packaging recipe differs from actual producer BUILDINFO: " + base + " " + version)
        tree = self.run(["git", "-C", str(work), "ls-tree", "-r", "HEAD"])
        require(not any(line.startswith(b"160000 ") for line in tree.splitlines()), "Packaging recipe has unresolved Git submodule sources")
        recipe_archive = self.root / "recipe.tar.gz"
        self.run(["git", "-C", str(work), "archive", "--format=tar.gz", "--output=" + str(recipe_archive), "HEAD"])
        recipe_entry = self.add(recipe_archive, "recipes/" + str(slot) + ".tar.gz")
        recipe_archive.unlink()
        shutil.rmtree(work / ".git")
        work.chmod(0o1777)
        for name in ("gnupg", "sources", "archives"):
            directory = work / name
            directory.mkdir(mode=0o700)
            os.chown(directory, 65534, 65534)
        probe = "import os,json; from pathlib import Path; s=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line); print(json.dumps({'uid':os.getuid(),'euid':os.geteuid(),'groups':os.getgroups(),'status':{k:s[k].strip() for k in ['NoNewPrivs','CapEff','CapPrm','CapInh','CapBnd','CapAmb']}}))"
        user_proof = json.loads(self.run(["python", "-c", probe], cwd=work, user=True))
        require(user_proof["uid"] == user_proof["euid"] == 65534 and user_proof["groups"] == [] and user_proof["status"]["NoNewPrivs"] == "1"
                and all(int(value, 16) == 0 for key, value in user_proof["status"].items() if key.startswith("Cap")), "Actual source subprocess retained privileges")
        srcinfo_raw = self.run(["makepkg", "--printsrcinfo"], cwd=work, user=True)
        srcinfo = fields(srcinfo_raw)
        require(one(srcinfo, "pkgbase") == base, "Resolved source base differs")
        resolved = (one(srcinfo, "epoch") + ":" if srcinfo.get("epoch", ["0"]) != ["0"] else "") + one(srcinfo, "pkgver") + "-" + one(srcinfo, "pkgrel")
        require(resolved == version, "Resolved source version differs from original producer")
        declared_sources = [value for key, values in srcinfo.items() if key == "source" or key.startswith("source_") for value in values]
        filenames = self.run(["bash", "-c", 'source /usr/share/makepkg/util/source.sh; for value; do get_filename "$value"; done', "ve-source-filenames", *declared_sources], cwd=work, user=True).decode().splitlines()
        require(len(filenames) == len(declared_sources) and all(name and "/" not in name and name not in {".", ".."} for name in filenames), "Unresolved source archive member names")
        for fingerprint in srcinfo.get("validpgpkeys", []):
            require(re.fullmatch(r"[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", fingerprint), "Invalid complete source signing fingerprint")
            self.run(["gpg", "--batch", "--keyserver", "hkps://keyserver.ubuntu.com", "--recv-keys", fingerprint], cwd=work, user=True)
        resolved = []
        vcs_proof = None
        gnulib_source = "git+https://git.savannah.gnu.org/git/gnulib.git"
        if base == "coreutils" and gnulib_source in srcinfo.get("source", []):
            require("git+https://git.savannah.gnu.org/git/coreutils.git?signed#tag=v9.12" in srcinfo["source"], "Unpinned gnulib has no reviewed parent source")
            self.run(["makepkg", "--verifysource", "--noconfirm", "--nocolor"], cwd=work, user=True)
            core = work / "sources/coreutils"
            gnulib = work / "sources/gnulib"
            require(self.run(["git", "--git-dir=" + str(core), "rev-parse", "v9.12^{commit}"], cwd=work, user=True).decode().strip() == COREUTILS_COMMIT, "Coreutils tag resolved to a different commit")
            require(self.run(["git", "--git-dir=" + str(core), "rev-parse", "v9.12^{tree}"], cwd=work, user=True).decode().strip() == COREUTILS_TREE, "Coreutils source tree differs")
            link = self.run(["git", "--git-dir=" + str(core), "ls-tree", "v9.12", "gnulib"], cwd=work, user=True).decode().strip()
            require(link == "160000 commit " + GNULIB_COMMIT + "\tgnulib", "Coreutils gnulib gitlink differs")
            require(self.run(["git", "--git-dir=" + str(gnulib), "rev-parse", GNULIB_COMMIT + "^{tree}"], cwd=work, user=True).decode().strip() == GNULIB_TREE, "Original gnulib commit is unavailable or differs")
            self.run(["git", "--git-dir=" + str(gnulib), "fsck", "--full", "--strict"], cwd=work, user=True)
            resolved.append(gnulib_source)
            vcs_proof = {"parent_commit": COREUTILS_COMMIT, "parent_tree": COREUTILS_TREE, "gitlink": "gnulib", "commit": GNULIB_COMMIT, "tree": GNULIB_TREE}
        source_integrity(srcinfo, resolved)
        self.run(["makepkg", "--allsource", "--noconfirm", "--nocolor"], cwd=work, user=True)
        outputs = list((work / "archives").glob("*.src.tar.gz"))
        require(len(outputs) == 1 and not outputs[0].is_symlink(), "Source producer did not create one complete archive")
        with tarfile.open(outputs[0], "r:gz") as archive:
            members = list(archive)
            matches = [member for member in members if member.name == base + "/PKGBUILD"]
            require(len(matches) == 1 and matches[0].isfile() and matches[0].size <= DOCUMENT_LIMIT, "Complete source archive lacks its original recipe")
            require(hashlib.sha256(archive.extractfile(matches[0]).read()).hexdigest() == expected_hash, "Source archive changed producer recipe")
            names = {member.name.rstrip("/") for member in members}
            require(all(base + "/" + name in names or any(path.startswith(base + "/" + name + "/") for path in names) for name in filenames), "Complete source archive omitted a declared source")
        if vcs_proof:
            unpack = work / "source-verification"
            unpack.mkdir()
            os.chown(unpack, 65534, 65534)
            self.run(["bsdtar", "-xf", str(outputs[0]), "-C", str(unpack), "coreutils/gnulib"], cwd=work, user=True)
            bundled = unpack / "coreutils/gnulib"
            require(bundled.resolve().is_relative_to(unpack.resolve()), "Bundled gnulib escapes its source archive")
            require(self.run(["git", "--git-dir=" + str(bundled), "rev-parse", GNULIB_COMMIT + "^{tree}"], cwd=work, user=True).decode().strip() == GNULIB_TREE, "Complete source archive omits the original gnulib commit")
            self.run(["git", "--git-dir=" + str(bundled), "fsck", "--full", "--strict"], cwd=work, user=True)
            shutil.rmtree(unpack)
        source_entry = self.add(outputs[0], "packages/" + str(slot) + ".src.tar.gz")
        result = {"base": base, "version": version, "packaging_commit": commit, "pkgbuild_sha256": expected_hash,
                  "srcinfo": srcinfo_raw.decode(), "source_members": sorted(set(filenames)), "recipe": recipe_entry, "source": source_entry, "vcs_source_binding": vcs_proof, "source_process": user_proof}
        shutil.rmtree(work)
        return result

    def upstream(self, name, url, commit, expected_tree=None):
        work = self.root / name
        self.run(["git", "init", "--quiet", str(work)])
        self.run(["git", "-C", str(work), "fetch", "--quiet", "--depth=1", url, commit])
        self.run(["git", "-C", str(work), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
        actual = self.run(["git", "-C", str(work), "rev-parse", "HEAD"]).decode().strip()
        commit_object = self.run(["git", "-C", str(work), "cat-file", "commit", "HEAD"]).decode()
        tree = self.run(["git", "-C", str(work), "rev-parse", "HEAD^{tree}"]).decode().strip()
        require(actual == commit and (expected_tree is None or tree == expected_tree), "Upstream source identity differs")
        listing = self.run(["git", "-C", str(work), "ls-tree", "-r", "HEAD"])
        require(not any(line.startswith(b"160000 ") for line in listing.splitlines()), "Upstream has unresolved Git submodule sources")
        path = self.root / (name + ".tar.gz")
        self.run(["git", "-C", str(work), "archive", "--format=tar.gz", "--output=" + str(path), "HEAD"])
        entry = self.add(path, "upstream/" + name + ".tar.gz")
        path.unlink()
        if name == "llama.cpp":
            shutil.move(work, "/src")
        else:
            shutil.rmtree(work)
        return {"name": name, "repository": url, "commit": commit, "tree": tree, "commit_object": commit_object, "source": entry}


def main():
    require(os.geteuid() == 0 and Path("/locks/metadata/source-package-archives.json").is_file(), "Source acquisition runs only in the fixed native container stage")
    require(not any(name in os.environ for name in ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "SSH_AUTH_SOCK")), "Credential-bearing source environment is forbidden")
    root, output = Path("/ve-source-work"), Path("/ve-source-export")
    root.mkdir(mode=0o755)
    output.mkdir(mode=0o700)
    metadata = output / "metadata"
    metadata.mkdir()
    acquisition = Acquisition(root, output)
    catalog = json.loads(Path("/locks/metadata/source-package-archives.json").read_text())
    proofs, recipes, groups = [], [], {}
    try:
        for row in catalog["packages"]:
            print("Verifying original package: " + row["name"] + " " + row["version"], flush=True)
            directory = metadata / row["sha256"]
            directory.mkdir()
            proof = acquisition.package(row, directory)
            proofs.append(proof)
            key = row["base"], row["version"], proof["pkgbuild_sha256"]
            groups.setdefault(key, []).append(row["name"])
        for slot, (base, version, recipe_hash) in enumerate(sorted(groups), 1):
            print("Acquiring complete source: " + base + " " + version, flush=True)
            result = acquisition.recipe(base, version, recipe_hash, slot)
            result["binary_packages"] = groups[(base, version, recipe_hash)]
            recipes.append(result)
        upstream = [acquisition.upstream("llama.cpp", "https://github.com/ggml-org/llama.cpp", LLAMA_SOURCE, LLAMA_TREE),
                    acquisition.upstream("archlinux-docker", "https://gitlab.archlinux.org/archlinux/archlinux-docker.git", BASE_SOURCE)]
        acquisition.finish_group()
        receipt = {"schema_version": 1, "status": "acquired-and-verified-before-compilation", "catalog_sha256": sha(Path("/locks/metadata/source-package-archives.json")),
                   "packages": proofs, "recipes": recipes, "upstream": upstream, "source_archives": acquisition.groups}
        encoded = json.dumps(receipt, sort_keys=True, indent=2).encode() + b"\n"
        require(len(encoded) <= DOCUMENT_LIMIT, "Source receipt exceeds metadata limit")
        (output / "acquisition.json").write_bytes(encoded)
    except Exception as error:
        (output / "failure.json").write_text(json.dumps({"status": "incomplete", "reason": str(error), "verified_packages": len(proofs), "verified_recipes": len(recipes)}) + "\n")
        raise
    finally:
        acquisition.finish_group()


if __name__ == "__main__":
    main()
