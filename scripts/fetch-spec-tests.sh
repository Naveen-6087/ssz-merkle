#!/usr/bin/env bash
# Fetches the ssz_generic reference tests from the consensus-specs v1.6.1 release.
set -euo pipefail

VERSION="v1.6.1"
URL="https://github.com/ethereum/consensus-specs/releases/download/${VERSION}/general.tar.gz"
SHA256="87898ba7a3fa16bc66b08c88b4ccab008833a517a7602cf421c6ce79734e07e9"

SUITES=(
  uints:66
  boolean:6
  bitvector:85
  bitlist:494
  basic_vector:1157
  basic_progressive_list:887
  progressive_bitlist:703
  containers:701
  progressive_containers:525
)

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:-$root/testdata/consensus-spec-tests}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "downloading consensus-specs ${VERSION} general tests (~170 MB)..."
curl -fsSL --retry 3 -o "$work/general.tar.gz" "$URL"
echo "${SHA256}  $work/general.tar.gz" | sha256sum -c --quiet -

members=()
for entry in "${SUITES[@]}"; do
  members+=("tests/general/phase0/ssz_generic/${entry%%:*}")
done
tar -xzf "$work/general.tar.gz" -C "$work" "${members[@]}"

mkdir -p "$dest/ssz_generic"
for entry in "${SUITES[@]}"; do
  suite="${entry%%:*}"
  want="${entry##*:}"
  src="$work/tests/general/phase0/ssz_generic/$suite"
  got="$(find "$src" -mindepth 2 -maxdepth 2 -type d | wc -l | tr -d ' ')"
  if [[ "$got" != "$want" ]]; then
    echo "error: $suite has $got cases, expected $want" >&2
    exit 1
  fi
  rm -rf "${dest:?}/ssz_generic/$suite"
  cp -R "$src" "$dest/ssz_generic/$suite"
  echo "  $suite: $got cases"
done
echo "done: $dest"
