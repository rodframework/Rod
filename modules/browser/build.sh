#!/bin/sh
# Builds the browser plugin's Linux artifact into the package tree.
# rod mod publish packs plugin/browser-linux-amd64 as the package's
# execution half, so this script runs before a release publish; the
# binary is build output and nothing under plugin/ is committed.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate="$here/../../src/implant/rust/modules/browser"

(cd "$crate" && cargo build --release)
mkdir -p "$here/plugin"
cp "$crate/target/release/rod-module-browser" "$here/plugin/browser-linux-amd64"
echo "artifact: $here/plugin/browser-linux-amd64"
