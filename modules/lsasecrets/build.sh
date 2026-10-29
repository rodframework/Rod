#!/bin/sh
# Builds the lsasecrets plugin's Linux artifact into the package tree.
# rod mod publish packs plugin/lsasecrets-linux-amd64 as the package's
# execution half, so this script runs before a release publish; the
# binary is build output and nothing under plugin/ is committed.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate="$here/../../src/implant/rust/modules/lsasecrets"

(cd "$crate" && cargo build --release)
mkdir -p "$here/plugin"
cp "$crate/target/release/rod-module-lsasecrets" "$here/plugin/lsasecrets-linux-amd64"
echo "artifact: $here/plugin/lsasecrets-linux-amd64"
