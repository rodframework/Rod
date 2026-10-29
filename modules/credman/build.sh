#!/bin/sh
# Builds the credman plugin's Linux artifact into the package tree.
# rod mod publish packs plugin/credman-linux-amd64 as the package's
# execution half, so this script runs before a release publish; the
# binary is build output and nothing under plugin/ is committed.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate="$here/../../src/implant/rust/modules/credman"

(cd "$crate" && cargo build --release)
mkdir -p "$here/plugin"
cp "$crate/target/release/rod-module-credman" "$here/plugin/credman-linux-amd64"
echo "artifact: $here/plugin/credman-linux-amd64"
