#!/bin/bash
set -euo pipefail
cache=${1:?}
evidence=${2:?}
mkdir -p "$evidence"
shopt -s nullglob
archives=("$cache"/*.pkg.tar.zst)
(( ${#archives[@]} > 0 ))
for archive in "${archives[@]}"; do
  [[ -f "$archive" && ! -L "$archive" ]]
  digest=$(sha256sum "$archive")
  digest=${digest%% *}
  destination="$evidence/$digest"
  mkdir "$destination"
  printf '%s\n' "${archive##*/}" > "$destination/archive-filename"
  wc -c < "$archive" > "$destination/archive-bytes"
  for metadata in .PKGINFO .BUILDINFO .MTREE; do
    bsdtar -xOf "$archive" "$metadata" > "$destination/$metadata"
    [[ -s "$destination/$metadata" ]]
  done
  if [[ -f "$archive.sig" ]]; then
    cp "$archive.sig" "$destination/archive.sig"
  fi
done
