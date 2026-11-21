# Exact package inputs

`core.db` and `extra.db` are the retained 2026/11/19 official Arch snapshot databases, checked by `snapshot.sha256`. `source-package-archives.json` binds original archive routes, sizes, hashes and detached signatures for the conservative base/build/runtime source union, including the 25 older base package versions recovered from the official 2026/11/08 database. These are exact acquisition identities; actual archive, signature and producer-source verification happens in the native source stage before compilation.
