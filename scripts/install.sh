#!/usr/bin/env bash
# Rod teamserver one-command installer (docs/operations/teamserver.md, the
# One-command install section). Downloads a GitHub release's self-contained
# teamserver and its payload build source onto this host, lays out the install
# tree the runbook documents, installs the systemd unit, and starts the
# service. The deployed host needs neither the .NET SDK nor the runtime --
# only PostgreSQL reachability when durability is wanted, and the Rust
# toolchain for payload builds.
#
# Usage:
#   sudo bash install.sh [version]     # version defaults to the latest release
#
# Rerunning with a newer version upgrades in place: every operator-written
# file survives (appsettings.Production.json, runtime settings, the secret
# env file, the state and data directories); only the release trees swap.
#
# Rehearsal knobs (used by the install-path rehearsal, not part of the
# supported surface): ROD_REHEARSAL=1 skips the root check, the service user,
# chown, and systemd, and redirects the state/etc/unit paths under ROD_PREFIX;
# ROD_ASSET_BASE overrides the download origin (default: the GitHub releases
# URL); ROD_PREFIX overrides the install root (default /opt/rod).
set -euo pipefail

repo="rodframework/Rod"
prefix="${ROD_PREFIX:-/opt/rod}"
service="rod-teamserver"
user="rod"
group="rod"
base_url="${ROD_ASSET_BASE:-https://github.com/${repo}/releases}"
version="${1:-latest}"
keep_files="appsettings.Production.json runtime-settings.json runtime-build-settings.json"

rehearsal="${ROD_REHEARSAL:-0}"
if [ "$rehearsal" = "1" ]; then
    state_dir="$prefix/var/lib/rod"
    etc_dir="$prefix/etc/rod"
    unit_file="$prefix/${service}.service"
else
    state_dir="/var/lib/${user}"
    etc_dir="/etc/rod"
    unit_file="/etc/systemd/system/${service}.service"
fi
data_dir="$state_dir/data"

die() {
    echo "install: $*" >&2
    exit 1
}

[ "$(uname -m)" = "x86_64" ] \
    || die "this host is $(uname -m); the release ships linux-x64 binaries only"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
if [ "$rehearsal" != "1" ]; then
    [ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
fi

# Resolve "latest" to a concrete tag through GitHub's stable redirect; an
# explicit version is normalized to its v-prefixed tag. Only the first
# hop is followed: that hop lands on the tag-named download URL
# (.../releases/download/<tag>/<asset>), while following every hop ends
# on the asset CDN's signed URL, which carries no tag to extract.
if [ "$version" = "latest" ]; then
    location="$(curl -fsI -o /dev/null -w '%{redirect_url}' \
        "$base_url/latest/download/rod-teamserver-linux-x64.tar.gz")"
    case "$location" in
        */download/*) tag="${location#*/download/}"; tag="${tag%%/*}" ;;
        *) tag="" ;;
    esac
    [ -n "$tag" ] || die "could not resolve the latest release tag from $base_url"
else
    case "$version" in
        v*) tag="$version" ;;
        *) tag="v$version" ;;
    esac
fi

download() {
    curl -fSL --retry 3 -o "$2" "$base_url/download/$tag/$1"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "Installing Rod $tag from $base_url"

# Service user and directories (the service user's home is where the
# DataProtection key ring lands -- see the runbook's backup trio).
if [ "$rehearsal" != "1" ]; then
    getent passwd "$user" >/dev/null 2>&1 \
        || useradd -r -d "$state_dir" -M -s /usr/sbin/nologin "$user"
fi
mkdir -p "$state_dir" "$data_dir" "$etc_dir/pki" "$prefix"
if [ "$rehearsal" != "1" ]; then
    chown "$user:$group" "$state_dir" "$data_dir"
fi

# Stop the running service before touching its tree; the restart at the end
# brings the new version up.
was_active=0
if [ "$rehearsal" != "1" ] && systemctl is-active --quiet "$service"; then
    was_active=1
    systemctl stop "$service"
fi

download rod-teamserver-linux-x64.tar.gz "$work/teamserver.tar.gz"
download rod-src.tar.gz "$work/src.tar.gz"

# Swap the teamserver tree atomically, carrying the operator-written files
# across so an upgrade never loses configuration.
new="$prefix/teamserver.new"
old="$prefix/teamserver.old"
rm -rf "$new" "$old"
mkdir -p "$new"
tar -xzf "$work/teamserver.tar.gz" -C "$new"
for name in $keep_files; do
    if [ -f "$prefix/teamserver/$name" ]; then
        cp -p "$prefix/teamserver/$name" "$new/$name"
    fi
done
[ -d "$prefix/teamserver" ] && mv "$prefix/teamserver" "$old"
mv "$new" "$prefix/teamserver"
rm -rf "$old"

# The payload build source: the minimal deployed tree (implant crate plus
# wire protos, crates vendored by the release workflow), replaced wholesale
# on upgrade -- it carries no operator-written state.
rm -rf "$prefix/src.new" "$prefix/src.old"
mkdir -p "$prefix/src.new"
tar -xzf "$work/src.tar.gz" -C "$prefix/src.new"
[ -d "$prefix/src" ] && mv "$prefix/src" "$prefix/src.old"
mv "$prefix/src.new" "$prefix/src"
rm -rf "$prefix/src.old"

if [ "$rehearsal" != "1" ]; then
    chown -R "$user:$group" "$prefix"
fi

# Non-secret install-shape configuration, generated once (an upgrade keeps
# whatever the operator has edited). Secrets never live here -- they ride the
# env file below.
if [ ! -f "$prefix/teamserver/appsettings.Production.json" ]; then
    cat > "$prefix/teamserver/appsettings.Production.json" <<EOF
{
  // Generated by scripts/install.sh; non-secret install-shape configuration.
  // Secrets ride $etc_dir/teamserver.env, never this file.
  "Build": {
    "RustSourceDirectory": "$prefix/src/src/implant/rust"
  },
  "Audit": {
    "DataDirectory": "$data_dir"
  }
  // The production engagement CA replaces the built-in dev CA once
  // provisioned; uncomment when ca.crt/ca.key are in place:
  // "Pki": {
  //   "CaCertificatePath": "$etc_dir/pki/ca.crt",
  //   "CaPrivateKeyPath": "$etc_dir/pki/ca.key"
  // }
}
EOF
fi

# The secret env file, generated once with everything commented: uncommenting
# nothing boots the ephemeral posture (in-memory state, a generated admin
# password printed once per boot in the journal); filling it in is the
# production posture.
if [ ! -f "$etc_dir/teamserver.env" ]; then
    touch "$etc_dir/teamserver.env"
    cat > "$etc_dir/teamserver.env" <<EOF
# Rod teamserver secrets (systemd EnvironmentFile). Generated by
# scripts/install.sh; uncomment and fill what this deployment uses.
#
# Operators__Initial__Handle=lead
# Operators__Initial__Password=<yours>
# ConnectionStrings__Postgres=Host=localhost;Port=5432;Database=rod;Username=rod;Password=<yours>
# Pki__CaPrivateKeyPassphrase=<only if the CA key is encrypted>
EOF
    if [ "$rehearsal" != "1" ]; then
        chown "root:$group" "$etc_dir/teamserver.env"
        chmod 640 "$etc_dir/teamserver.env"
    fi
fi

# The supervisor unit (the runbook's shape), generated once so an operator's
# edits survive upgrades.
if [ ! -f "$unit_file" ]; then
    cat > "$unit_file" <<EOF
[Unit]
Description=Rod teamserver (C2 kernel)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=$user
Group=$group
Environment=ASPNETCORE_ENVIRONMENT=Production
EnvironmentFile=$etc_dir/teamserver.env
ExecStart=$prefix/teamserver/Rod.TeamServer
WorkingDirectory=$prefix/teamserver
StateDirectory=rod
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$state_dir

[Install]
WantedBy=multi-user.target
EOF
fi

if [ "$rehearsal" != "1" ]; then
    systemctl daemon-reload
    systemctl enable "$service" >/dev/null
    # restart covers both a fresh install (starts the inactive unit) and an
    # upgrade (the stop above took the old version down before the swap).
    systemctl restart "$service"
fi

echo "Installed Rod $tag:"
echo "  teamserver:  $prefix/teamserver"
echo "  build source: $prefix/src (RustBuildUnit compiles payloads from it)"
echo "  state:       $state_dir"
echo "  secrets:     $etc_dir/teamserver.env"
echo "  unit:        $unit_file"
if [ "$rehearsal" = "1" ]; then
    exit 0
fi
echo
echo "The service is running the ephemeral posture until the env file is"
echo "filled: the first admin's generated password is in the journal --"
echo "  journalctl -u $service -b --no-pager | grep -m1 'generated password'"
echo "Then, per the runbook (docs/operations/teamserver.md):"
echo "  - set ConnectionStrings__Postgres and apply the schema once from a"
echo "    checkout (dotnet ef database update) for durable state"
echo "  - provision the engagement CA into $etc_dir/pki and uncomment Pki"
echo "  - payload builds need the Rust toolchain (cargo, rustc, cross"
echo "    targets) on PATH for the service user"
