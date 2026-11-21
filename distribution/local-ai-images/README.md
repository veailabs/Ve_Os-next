# Local AI image publication

This directory holds reviewed source snapshots and local build evidence for the Ve local AI runtime images. `publish.py` validates actual OCI archives and publishes an allowlisted image through the protected GitHub workflow. It does not build images, change runtime catalog references, make packages public or claim GPU inference passed.

The current TensorFold image was built and checked locally. Its source snapshot, exact OCI identity, component notices and runtime evidence live in `tensorfold/`. The large OCI archive remains a separate release artifact. `release.json` records the actual uploaded OCI/source asset IDs and their independently downloaded byte hashes. Publication remains gated on review, protected-master merge, release publication and verified repository visibility. A runtime without a reviewed release record fails before network access. The other seven runtime names are allowlisted for future reviewed records; this does not claim their images exist.

## Publication boundary

`.github/workflows/local-ai-images.yml` runs only by manual dispatch on protected `master`, for repository ID `1465654995`. The current name is `veailabs/Ve_Os-next`; the approved canonical rename is `veailabs/Ve_Os`, with the same immutable repository ID. Standard hosted execution is disabled while the repository is private, avoiding unverified private-runner charges. A source/publication audit must precede making the repository and release assets public.

The workflow uses environment `ve-os-image-publication`, ID `28014484873`. The helper verifies its actual GitHub metadata: protected branches required, exactly one required-reviewer rule containing only owner user ID `214956837`, and `can_admins_bypass=false`. The coordinator independently created/read back those settings. The helper also checks that the current master commit remains the dispatched SHA and that the checkout matches it. No branch, pull-request or user-supplied URL is accepted as publication input.

Only `contents:read` and `packages:write` are granted to the publication job. GitHub's short-lived workflow token reaches `gh` through its environment and the registry login through standard input; it is never supplied in an argument or written into the source. Registry auth lives in a temporary private directory and is removed on success or failure, with workflow cleanup as an additional boundary. No PAT, AWS secret or additional cloud resource is used.

Each `release.json` must be added through review after its source commit, release and assets actually exist. It has exactly these fields:

| Field | Required value |
|---|---|
| `schema_version` | Integer `1` |
| `repository_id` | Integer `1465654995` |
| `runtime` | The matching allowlisted directory name |
| `source_commit` | Actual 40-hex commit containing this exact `context.tar`, already an ancestor of master |
| `release_id` | Actual positive GitHub release ID |
| `release_tag` | The actual release tag; slash-free and at most 128 characters |
| `assets` | Ordered array of actual image asset records with `id`, `name`, `bytes`, `sha256` |
| `source_manifest_sha256` | SHA-256 of the completed checked-in `source-delivery.json` |
| `source_assets` | Actual source-bundle asset records with `id`, `name`, `bytes`, `sha256`, matching that manifest |

The image assets concatenate to the exact archive length and SHA-256 recorded in `source.json`; individual assets must be smaller than 2 GiB. The helper fetches only GitHub release-asset API endpoints derived from the current verified repository and those IDs. It checks the real release/tag/draft state, uploaded asset names/sizes and available GitHub asset digests. A replacement asset cannot pass the reviewed byte hashes. Do not fill this record with placeholder IDs or guessed URLs.

Source delivery is also mandatory. `source-delivery.json` must have schema version 1 and status `complete`, cover every unique installed Debian source package/version pair plus every `Built-Using` and `Static-Built-Using` component, list corresponding files with safe bundle-relative paths/byte counts/SHA-256 values, include the TensorFold/JPEG/WebP upstream sources, and describe actual built source bundles. The helper binds this manifest to the reviewed record and verifies the real source assets by streaming their complete bytes before publishing the image. An empty source bundle list or metadata-only draft fails closed. The source producer must verify bundle contents against that manifest before review. The helper also reads the actual OCI image’s installed package database and verifies the full source identity union against the stored inventory. Copyright files alone do not satisfy this gate.

When release assets refer to a feature-branch source commit, merge normally so that commit remains an ancestor of master. Squash/rebase merging would invalidate that source_commit reference; do not substitute a guessed commit after merging.

Before uploading, the validator checks the complete archive hash, rejects unsafe/duplicate tar members and duplicate JSON keys, hashes every OCI blob, validates every descriptor size, rejects external or unreferenced blobs, and binds the image manifest/config/platform/source labels to the reviewed source record. Only a single-platform OCI image with gzip layers is currently supported. Inputs outside that contract require an explicit reviewed extension.

The destination is derived from the runtime under `ghcr.io/veailabs/ve-os-local-ai/`. This is a planned namespace, not a claim that packages have been published. The first registry write addresses the exact image digest, so it cannot replace a different image under a tag. A tag containing the complete digest is then created only after an existing-tag check. An existing tag must already match; registry errors other than explicit missing-name/manifest responses stop the workflow. `skopeo copy --preserve-digests` fails if the transport cannot retain the reviewed digest. The helper checks the authenticated registry manifest and actual GitHub package owner, container identity, repository ID/name and public visibility, then downloads anonymously with an empty auth file and explicit `--src-no-creds` and validates every returned blob and image identity again.

GitHub package visibility is separate from repository visibility. An authorized package admin must make the actual package public before anonymous verification can pass; the workflow cannot assume this from a public repository. A first publication may therefore upload successfully and stop at anonymous access. After the actual package visibility is corrected, rerunning verifies the existing digest rather than replacing it. The documented Packages REST API has no package-visibility update endpoint; do not invent one or add a PAT to bypass this boundary. See [GitHub package access and visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility) and [Packages REST API](https://docs.github.com/en/rest/packages/packages).

GHCR image storage/bandwidth are currently free, while Actions artifacts, caches and private/larger runners have separate billing rules. This workflow uses a standard public runner, retains no Actions artifact/cache, and requires space for three archive-sized copies plus 1 GiB before downloading. Larger images still need measured runner capacity; this gate does not qualify them automatically. See [Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages) and [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

## Local verification

Run `python3 distribution/local-ai-images/check.py` for the complete local gate: malformed archive/record/workflow tests and hashes of every actual source snapshot and any present release records. `test/shell.d/local-ai-images-test.sh` includes these checks in the normal shell suite. Validate the real original archive with `python3 distribution/local-ai-images/publish.py validate tensorfold /path/to/tensorfold-arm64.oci.tar`. This checks bytes and source identity without registry access or credentials.

The runtime catalog stays unchanged until an actual public exact-digest pull succeeds, followed by its native engine/package gates and signing. Preserved historical measurements do not qualify a new image; supported hardware inference and matching model/artifact measurements remain separate requirements.
