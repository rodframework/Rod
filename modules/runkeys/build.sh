#!/bin/sh
# Builds the runkeys plugin's Linux artifact into the package tree.
# rod mod publish packs plugin/runkeys-linux-amd64 as the package's
# execution half, so this script runs before a release publish; the
# binary is build output and nothing under plugin/ is committed.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate="$here/../../src/implant/rust/modules/runkeys"

(cd "$crate" && cargo build --release)
mkdir -p "$here/plugin"
cp "$crate/target/release/rod-module-runkeys" "$here/plugin/runkeys-linux-amd64"
echo "artifact: $here/plugin/runkeys-linux-amd64"
