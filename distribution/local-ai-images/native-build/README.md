# Native llama.cpp build and draft export

This component implements the first native x64 llama.cpp build/export profile on the standard public `ubuntu-24.04` runner. It produces an owner-gated draft release only after real native isolation, complete corresponding-source acquisition, runtime commands, image/source correspondence and immutable export checks pass. It does not publish a registry image or qualify GPU inference. The existing registry publisher remains unchanged and still needs separate reviewed Arch source support before public promotion.

The implementation is locally testable. No successful hosted native build, complete native source acquisition or release export is asserted by those tests. A missing producer recipe, unexplained distributed file, unavailable platform feature, exhausted resource limit or failed source verification stops the attempt. It does not remove a feature or bypass a check to obtain a pass.

## Execution and approval

`local-ai-runner-qualification.yml` measures standard x64 and ARM runners sequentially, then runs the x64 isolation smoke. It is contents-read-only and compiles no engine. ARM inventory cannot qualify the x64 profile. The qualification workflow disables Python bytecode writes, matching build/export and CI, so its tests leave the hash-locked build context unchanged.

`local-ai-native-build.yml` first checks the already-existing destination in a contents-read-only job. The protected build/export job then requires the owner review in environment `ve-os-image-build-export`, ID `28071521718`. The non-secret repository variable `VE_OS_IMAGE_BUILD_EXPORT_ENVIRONMENT_ID` must match that actual ID. Repository ID `1465654995`, public visibility, protected master at the dispatched SHA, owner reviewer `214956837`, protected-branch-only deployment and disabled admin bypass are verified before allocation and again before upload. Missing configuration fails preflight; the workflow does not create an unprotected environment.

The build/export job has `contents:write` for its whole lifetime, as explicitly approved. Only the final uploader step receives the temporary token in its process environment. Checkout disables persistent credentials. Build processes receive a constructed environment with private HOME, cache, container storage and temporary directories; no workflow credentials, host sockets or host credential mounts are passed to containers. This process isolation does not turn the whole-job permission into a narrower GitHub permission. No PAT, AWS resource, paid/larger runner, Actions artifact or Actions cache is added.

The fixed sequence is:

1. Verify destination, actual runner identity and resource admission.
2. Allocate the bounded filesystem and prove native cgroup, namespace and rootless UID enforcement with the exact pinned base image.
3. Build the source stage and acquire verified complete source archives before compilation.
4. Validate source archive bytes, original producer bindings and upstream Git trees on the host, inside the bounded native service. Bind the pass to the same run, attempt, reviewed source SHA, context hash and exact source image ID.
5. Compile without network from that verified image. Assemble the runtime from its exact compiled image ID and pinned runtime packages.
6. Run actual `llama-server --version` and `llama-bench --help`, save the layered OCI archive, and verify its actual package/file/source correspondence.
7. Stop owned processes, move the allowlisted export into a root-owned read-only directory, and rehash every frozen descriptor.
8. Create the owned nonlatest draft prerelease, upload complete source assets and ordered image ranges, and read back every byte before reporting success. Cleanup runs on success or failure.

A draft export is still unreviewed output. Promotion remains separate. Existing or partially uploaded draft assets are retained on conflict or failure; the exporter does not clobber, delete or publish them.

## Resource envelope

`native_profile.py` fixes llama.cpp b12521, commit `6f311d7ad63dce97a3ad1deaafb7cc044bb8c26c`, source tree `4f4e5909f01bb09924a9005dc3c94705aff0f9b1`, the retained Arch base digest and the 2026/11/19 package snapshot. Vulkan, all CPU variants and runtime backends remain enabled. Compiler and shader concurrency remain one.

Admission requires 10 GiB free and 8 GiB available build memory plus a 2 GiB host reserve. The builder has an enforced 8 GiB memory limit and zero build swap. A fully preallocated ext4 loop filesystem bounds all build, store, cache, temporary and export writes. Its size is the approved 8 GiB growth ceiling minus actual allocated checkout/Git bytes, 16 MiB host evidence and a 16 MiB margin. Formatting disables discard. The native child verifies the actual loop/mount identity and cgroup limits. Unrelated host writes are monitored against a 2 GiB free floor; polling is not a filesystem reservation for those unrelated writes.

Trusted setup uses sudo only for the fixed owned loop, mount, build-directory ownership and final immutable freeze. Untrusted build execution remains rootless, receives no added capability or privileged mode, and uses separate namespaces. Package-source recipes additionally run as UID/GID 65534 with supplementary groups cleared, all capability sets empty and no-new-privileges enabled; actual `/proc` state is checked. No fetched PKGBUILD executes on the host.

The preparation build envelope is 260 minutes, final validation is bounded to 25 minutes, upload/readback to 35 minutes, and the job to 330 minutes. Logs are bounded plain files, not replayed as workflow commands. Cancellation or overflow stops the owned service. Cleanup refuses a changed loop/mount or an active process and uses ordinary unmount, never forced or lazy unmount. Failed cleanup is a failure; the disposable runner remains the final teardown boundary.

Exports are limited to 3 GiB OCI, 4 GiB complete source including context/evidence archives, 16 MiB metadata, 1 GiB per asset and 16 assets. Image parts are ranges of one archive, avoiding another full image-sized set of files. A source component larger than one asset is rejected rather than split into incomplete source archives. Upload and readback each have at most two attempts and conservative per-direction 15 GiB/combined 30 GiB body budgets. These are ceilings, not claims that the build fits them.

Optional SDK reclamation defaults to false and removes only `/usr/share/dotnet`, `/usr/share/swift` and x64 `/usr/local/lib/android` on the dedicated ephemeral runner. Symlinks, noncanonical paths and mounted/nested-mounted paths are rejected. Actual reclaimed bytes are measured; no assumed SDK size is used for admission.

## Source and image proof

`llamacpp-inputs.json` binds every context file by size and SHA-256. Staging rejects additional, changed, linked or special files. Context tar bytes are deterministic, and image source labels use the existing publisher's context-hash convention. Reviewed Git SHA/run provenance remains separate.

`metadata/source-package-archives.json` contains exact official archive routes, sizes, hashes and detached signatures for the conservative base/build/runtime union: 228 binary versions across 202 package-base versions. Those are acquisition identities, not an assertion that all payloads have already been verified. The source stage downloads and verifies each archive, requires a valid fully trusted Arch signature, captures actual `.PKGINFO`, `.BUILDINFO`, `.MTREE` and file hashes, and binds the exact PKGBUILD bytes to the producer hash in `.BUILDINFO`. An official version tag alone is insufficient.

Fetched recipes run `makepkg --allsource` without integrity bypasses inside the tokenless container. Original recipe trees, local patches, complete source archives, original notices and metadata are retained. The source checker accepts independently proven signature/commit routes rather than treating every literal `SKIP` identically. Unresolved source identities still fail.

The coreutils gnulib exception is specific: verified coreutils v9.12 selects gitlink `106e9b2384d08a1696fcbd40cbab52237943f208`, tree `63974be080d5aabd280801f327f49977bde164ce`. Acquisition verifies the original source checksums/signatures, parent commit/tree/gitlink, gnulib object closure and that the completed source archive contains the selected Git commit. GNULIB source/revision/refdir overrides are cleared. The GNU translation tarball and local patch remain in the complete source archive; a tar-only gnulib replacement is not substituted for the required Git store.

The exact llama.cpp and Arch base-construction source commits are exported. Host validation reconstructs upstream Git tree identities from the actual archived source files, modes and symlinks and verifies their pinned commit objects. Package evidence is parsed as bytes; recipes are never sourced on the host.

`arch_oci.py` reuses the unchanged publisher's OCI graph, blob, platform and label checks. `arch_inventory.py` verifies uncompressed layer digests, preserves original pacman metadata and the physical lower-layer package/version union, and applies whiteouts separately to the final filesystem. Old distributed bytes retain their source obligations after an upgrade or removal.

`native_image.py` compares actual layer file hashes, types, ownership, permissions and links with the authenticated original package inventories. Package-owned directories receive the same type, owner, group and mode comparison, including later-layer changes. Unowned directories are accepted only as root-owned mode-0755 parents of explicitly verified generated files. Unsupported PAX attributes, including capabilities, extended attributes, ACLs and file flags, fail archive validation rather than disappearing from the inventory. Matching mtree metadata alone is insufficient. Compiled outputs are checked against the actual captured installation inventory; copied notices are checked against the verified upstream source. Reviewed context and specifically named generated evidence are accounted for. Unexplained modified or unowned paths block export and are reported for a concrete follow-up; there is no generic exemption for arbitrary files in an evidence directory.

The recipe retains compiler commands, dependency/link records, generated Vulkan build evidence, installed ELF dynamic dependencies, the upstream tree and source archive. Bundled vendor source preserves inline notices missed by a filename-only licence scan. Conservative package-source inclusion avoids inventing static-link exclusions before actual linkage is proven.

## Verification

Run the full local gates:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 distribution/local-ai-images/native-build/check.py
PYTHONDONTWRITEBYTECODE=1 python3 distribution/local-ai-images/check.py
actionlint .github/workflows/test.yml .github/workflows/local-ai-runner-qualification.yml .github/workflows/local-ai-native-build.yml
shellcheck distribution/local-ai-images/native-build/llamacpp-context/scripts/*.sh
```

The tests exercise real small package/OCI/source archives, real Git tree reconstruction, byte mutation and missing-source failures, cgroup/volume boundaries, deadlines/cancellation, network-disabled compilation commands, immutable staging and the actual HTTP upload method with a recording connection. Freeze tests perform real rename/chmod and final descriptor/hash verification. On non-root hosts only ownership is modeled; running those tests as Linux root exercises actual ownership transfer from UID 65534 to root. Unit fixtures do not prove a hosted filesystem allocation or live GitHub transport. They allocate no loop filesystem, run no large build and upload nothing. The metadata validator also passed all 25 privately retained older-base package producer bindings; that check does not assert signature trust or image-file correspondence. Actual standard-runner qualification and same-attempt native source/build/export checks remain required.

The existing publisher CI job is unchanged. The added native job feeds the existing required `ci-ok`; no branch protection is weakened.

Primary references: [GitHub runner image installers](https://github.com/actions/runner-images/tree/main/images/ubuntu/scripts/build), [Podman build](https://docs.podman.io/en/latest/markdown/podman-build.1.html), [Podman save](https://docs.podman.io/en/latest/markdown/podman-save.1.html), [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html), [setpriv](https://man7.org/linux/man-pages/man1/setpriv.1.html), [ALPM BUILDINFO](https://alpm.archlinux.page/specifications/BUILDINFO.5.html), [ALPM PKGINFO](https://alpm.archlinux.page/specifications/PKGINFO.5.html), [makepkg](https://man.archlinux.org/man/makepkg.8.en), [GitHub releases](https://docs.github.com/en/rest/releases/releases), [GitHub release assets](https://docs.github.com/en/rest/releases/assets).
