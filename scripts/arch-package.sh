#!/usr/bin/env bash
# Run only in a disposable official Arch container; /work is the sole writable mount.
set -Eeuo pipefail
umask 022
export LC_ALL=C

mkdir -p /work/output
printf '%s\n' initialization > /work/output/stage
owner_uid=$(stat -c '%u' /work)
owner_gid=$(stat -c '%g' /work)
hand_back() {
    local status=$?
    trap - EXIT
    # Container root is the host user under rootless Podman; preserve that mapping.
    if ! chown -R -- "$owner_uid:$owner_gid" /work; then
        printf '%s\n' 'Failed to return disposable workspace ownership' >&2
        (( status != 0 )) || status=1
    fi
    exit "$status"
}
trap hand_back EXIT

if (( $# != 3 )); then
    printf '%s\n' 'Usage: bash /entry.sh refresh|refresh-stable|verify|metadata PKGBASE EXPECTED_ENTRY' >&2
    exit 2
fi
mode=$1
pkgbase=$2
entry=$3
case "$mode" in refresh|refresh-stable|verify|metadata) ;; *) exit 2 ;; esac
case "$pkgbase" in
    ddns-go-bin) required_entry=/usr/bin/ddns-go ;;
    ecapture-bin) required_entry=/usr/bin/ecapture ;;
    ifrextractor-rs|ifrextractor-rs-bin) required_entry=/usr/bin/ifrextractor ;;
    intel-mlc) required_entry=/usr/bin/mlc ;;
    nali-nt|nali-nt-bin|nali-nt-git) required_entry=/usr/bin/nali-nt ;;
    neo4j-community-bin) required_entry=/usr/bin/neo4j ;;
    opencl-vanity-gpg|opencl-vanity-gpg-bin) required_entry=/usr/bin/opencl_vanity_gpg ;;
    wakatime) required_entry=/usr/bin/wakatime ;;
    *) printf 'Unknown or disabled package: %s\n' "$pkgbase" >&2; exit 2 ;;
esac
[[ "$entry" == "$required_entry" && -f /verify.py && -d /work/recipe && ! -L /work/recipe ]]
[[ $EUID == 0 ]] || { printf '%s\n' 'Container initialization requires container root' >&2; exit 2; }
# A caller must reserve a new workspace for each attempt; never reuse source caches.
for directory in build sources packages; do
    if [[ -e "/work/$directory" || -L "/work/$directory" ]]; then
        printf 'Workspace directory already exists: %s\n' "$directory" >&2
        exit 2
    fi
done

# Use Arch's official geographical mirror, not the image's stale mirror ordering.
printf '%s\n' 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist
# Mirror throughput can dip below pacman's default low-speed limit; retry transient failures.
sed -i 's/^#\?\s*DisableDownloadTimeout.*//; /^\[options\]/a DisableDownloadTimeout' /etc/pacman.conf
retry() {
    local attempt
    for attempt in 1 2 3 4; do
        "$@" && return 0
        printf 'Attempt %s failed: %s\n' "$attempt" "$*" >&2
        sleep $((attempt * 5))
    done
    return 1
}
retry pacman -Syu --noconfirm
retry pacman -S --needed --noconfirm git pacman-contrib python sudo
useradd --create-home --shell /bin/bash builder
printf '%s\n' 'builder ALL=(root) NOPASSWD: /usr/bin/pacman' > /etc/sudoers.d/aur-builder
chmod 0440 /etc/sudoers.d/aur-builder
visudo -cf /etc/sudoers.d/aur-builder
mkdir -p /work/build /work/sources /work/packages
chown -R builder:builder /work

as_builder() {
    runuser -u builder -- env HOME=/home/builder LC_ALL=C MAKEFLAGS=-j2 "$@"
}
stage() {
    printf '%s\n' "$1" > /work/output/stage
}
make_config() {
    local arch=$1 name=$2 config
    config="/work/output/makepkg-$name.conf"
    cp /etc/makepkg.conf "$config"
    printf '\nCARCH=%q\nBUILDDIR=%q\nSRCDEST=%q\nPKGDEST=%q\nLOGDEST=%q\nMAKEFLAGS=%q\n' \
        "$arch" "/work/build/$name" /work/sources /work/packages /work/output -j2 >> "$config"
    mkdir -p "/work/build/$name"
    chown builder:builder "$config" "/work/build/$name"
}
verify_arches() {
    local arch
    while IFS= read -r arch; do
        make_config "$arch" "verify-$arch"
        as_builder makepkg --config "/work/output/makepkg-verify-$arch.conf" --verifysource --noconfirm
    done < /work/output/architectures
}

cd /work/recipe
as_builder python /verify.py snapshot /work/output/initial-files.json
make_config x86_64 checksum
as_builder makepkg --config /work/output/makepkg-checksum.conf --printsrcinfo > /work/output/original.SRCINFO
as_builder python /verify.py initial "$pkgbase"
if [[ "$mode" == metadata ]]; then
    cp /work/output/original.SRCINFO /work/recipe/.SRCINFO
    as_builder python /verify.py unchanged /work/output/initial-files.json
    stage complete
    exit 0
fi

stage checksum
as_builder python /verify.py checksum-baseline "$pkgbase"
as_builder python /verify.py architectures /work/output/original.SRCINFO > /work/output/architectures
if [[ "$mode" == refresh-stable ]]; then
    # A same-version recipe repair may regenerate sums, but may not hide changed downloads.
    stage verify-source
    verify_arches
fi
if [[ "$mode" == refresh || "$mode" == refresh-stable ]]; then
    stage checksum
    mkdir -p /work/build/checksum/tmp
    chown builder:builder /work/build/checksum/tmp
    as_builder env MAKEPKG_CONF=/work/output/makepkg-checksum.conf TMPDIR=/work/build/checksum/tmp updpkgsums --nocolor
fi
as_builder makepkg --config /work/output/makepkg-checksum.conf --printsrcinfo > /work/recipe/.SRCINFO
as_builder python /verify.py checksum-audit "$pkgbase" "$mode"
stage verify-source
verify_arches
# Source verification may execute top-level PKGBUILD code; audit it too.
as_builder python /verify.py checksum-audit "$pkgbase" "$mode"
as_builder python /verify.py snapshot /work/output/pre-build-files.json
cp /work/recipe/.SRCINFO /work/output/pre-build.SRCINFO
make_config x86_64 x86_64

stage build
set +e
as_builder makepkg --config /work/output/makepkg-x86_64.conf \
    --syncdeps --noconfirm --cleanbuild --clean 2>&1 | tee /work/output/build.log
statuses=("${PIPESTATUS[@]}")
set -e
if (( statuses[0] != 0 )); then
    failure_stage=$(as_builder python /verify.py failure-stage "${statuses[0]}" /work/output/build.log)
    stage "$failure_stage"
    exit "${statuses[0]}"
fi
stage package-inspection
(( statuses[1] == 0 )) || exit "${statuses[1]}"
as_builder makepkg --config /work/output/makepkg-x86_64.conf --printsrcinfo > /work/recipe/.SRCINFO
as_builder python /verify.py build-audit "$pkgbase"
as_builder makepkg --config /work/output/makepkg-x86_64.conf --packagelist > /work/output/packagelist
as_builder python /verify.py inspect "$pkgbase" "$entry"
# Do not let even metadata/package-list evaluation silently rewrite recipe files.
as_builder python /verify.py build-audit "$pkgbase"
stage complete
