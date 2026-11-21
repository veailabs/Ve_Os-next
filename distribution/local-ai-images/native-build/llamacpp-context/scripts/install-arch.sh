#!/bin/bash
set -euo pipefail
stage=${1:?}
case "$stage" in
  build) roots=(base-devel cmake git vulkan-headers vulkan-icd-loader shaderc spirv-headers) ;;
  runtime) roots=(vulkan-icd-loader vulkan-intel curl gcc-libs) ;;
  *) exit 1 ;;
esac
cd /locks
sha256sum --check snapshot.sha256
install -m644 pacman.conf /etc/pacman.conf
install -Dm644 metadata/core.db /var/lib/pacman/sync/core.db
install -Dm644 metadata/extra.db /var/lib/pacman/sync/extra.db
declare -A locked=()
while read -r name version; do locked[$name]=$version; done <"$stage.versions"
pacman -Sup --noconfirm --print-format '%n %v' "${roots[@]}" > /tmp/ve-arch-plan
while read -r name version; do
  [[ ${locked[$name]-} == "$version" ]]
done < /tmp/ve-arch-plan
pacman -Su --noconfirm --needed "${roots[@]}"
mkdir -p /usr/share/ve-os-local-ai
pacman -Q > "/usr/share/ve-os-local-ai/arch-$stage-installed.txt"
while read -r name version; do
  [[ ${locked[$name]-} == "$version" ]]
done < "/usr/share/ve-os-local-ai/arch-$stage-installed.txt"
cp /tmp/ve-arch-plan "/usr/share/ve-os-local-ai/arch-$stage-transaction.txt"
bash /locks/scripts/capture-packages.sh /var/cache/pacman/pkg "/usr/share/ve-os-local-ai/arch-$stage-package-evidence"
pacman -Scc --noconfirm
