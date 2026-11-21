# Ve OS

Ve OS distribution development is in progress. This repository starts with the protected local AI image publication component. The full desktop, installer, package repository and VM release are being completed under [workspace task638](https://github.com/veailabs/ve-core-workspace/issues/638).

The current component validates reviewed image sources and immutable release inputs, publishes an exact OCI digest through a protected workflow, and verifies an anonymous pull. It uses a temporary GitHub token. It does not claim that an OS release or GPU inference has been verified.

Read [the publication documentation](distribution/local-ai-images/README.md) for trust boundaries, source delivery, local checks and the required GitHub environment. Publication bootstrap work is tracked in [task664](https://github.com/veailabs/ve-core-workspace/issues/664).

Merged changes are recorded in [the changelog](CHANGELOG.md).

```sh
python3 distribution/local-ai-images/check.py
```

Image source contexts retain their original licences and component attribution. Ve packaging does not transfer ownership of included third-party software.
