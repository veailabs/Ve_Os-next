# TensorFold 1.2.10 ARM image

`context.tar` is the exact normalized local source snapshot used for the completed image build. It contains the Containerfile, pinned Debian snapshot configuration/metadata, upstream provenance and MIT packaging notice. Its SHA-256 is `3a5b014e9fc97c2f9f07f91059e9cce6e6cb993eb2d46e6969251a890826ce29`. The image labels identify that content snapshot explicitly; they do not claim it was already a public Ve Git commit when built.

`source.json` records the actual 582,902,784-byte OCI archive hash, image manifest/config digests and platform. The image manifest is `sha256:4a7e7d91307d0dbb086f0e875ad94e908b30c9edda9bc0fd63a35cd54223939b`. Its archive SHA-256 is `49075a69fb3d58cbf6361bec9bbc934c3e96158a77242068a5e5ae35ef9f4b16`. These describe a real local artifact, not a published registry image.

`licenses.json` records retained license/notice hashes from the actual root filesystem. The image includes TensorFold's complete license directory, codec notices and NVIDIA cuBLAS EULA; upstream copyright names remain authentic. `debian-source-map.tsv` maps all 103 installed Debian binaries to their source package versions. These records accompany, and do not replace, the actual notices in the source/image.

`runtime-checks.json` and `engine-contract-check.json` record successful version/help/server-help, path/environment, shared-library, license and CLI-contract checks. The actual image reports `tensorfold-native 1.2.10` and exposes all nine options used by the current engine. Those checks ran with a read-only root, networking disabled and no GPU devices or model weights. Logs referenced by the runtime record are retained with the private build evidence until release evidence publication; the record does not claim they are present in this directory.

All 18 OCI blob hashes and descriptor sizes were verified. GPU inference, a loaded model server, vision outputs and live authentication behavior were not tested. Registry publication and public pull verification are still pending, so the current runtime catalog is intentionally unchanged. A reviewed `release.json` may be added only after the actual release assets exist.

Corresponding-source bundle production is a separate release prerequisite. No source-delivery or release-asset record is fabricated here; the publisher rejects missing/incomplete records until actual matching source bundles are built, verified and attached.
