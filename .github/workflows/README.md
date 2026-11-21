# Workflows

`test.yml` runs the complete local AI publication component gate and reports `ci-ok`. This bootstrap gate does not claim to test a full operating system.

`local-ai-images.yml` manually publishes reviewed images only from the approved public repository and protected master branch. It requires the protected publication environment and verifies exact image digests before and after transfer.
