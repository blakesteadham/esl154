#!/usr/bin/env bash
# aur-atomic-arch-check.sh
# Checks an Arch/CachyOS system for indicators of the June 2026 "Atomic Arch"
# AUR supply-chain attack (Sonatype-2026-003775).
#
# Run as your normal user first. Re-run with sudo for the eBPF + root FS checks.
#
# IoCs covered:
#   - AUR (foreign) packages installed/updated on or after 2026-06-10
#   - npm packages: atomic-lockfile, js-digest
#   - "deps" infostealer binary, eBPF artifacts (scales.bpf)
#   - npm commands injected into pacman .INSTALL hooks of foreign packages
#   - cached PKGBUILDs (yay/paru clones) containing npm install lines

set -u
CUTOFF="2026-06-10"
RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; NC=$'\e[0m'
FINDINGS=0

flag()  { FINDINGS=$((FINDINGS+1)); echo "${RED}[!] $*${NC}"; }
warn()  { echo "${YEL}[?] $*${NC}"; }
ok()    { echo "${GRN}[ok]${NC} $*"; }

echo "=== Atomic Arch AUR compromise check — $(date) ==="
echo

# ------------------------------------------------------------------
echo "--- 1. Foreign (AUR) packages installed/updated since $CUTOFF ---"
CUTOFF_EPOCH=$(date -d "$CUTOFF" +%s)
RECENT_PKGS=()
while read -r pkg; do
    idate=$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/^Install Date/{print $2}')
    [ -z "$idate" ] && continue
    iepoch=$(date -d "$idate" +%s 2>/dev/null) || continue
    if [ "$iepoch" -ge "$CUTOFF_EPOCH" ]; then
        RECENT_PKGS+=("$pkg")
        warn "AUR package installed/updated since cutoff: $pkg ($idate)"
    fi
done < <(pacman -Qqm)
if [ ${#RECENT_PKGS[@]} -eq 0 ]; then
    ok "No foreign packages installed/updated since $CUTOFF"
else
    echo "    -> Review these against the aur-general thread / CachyOS forum list."
fi
echo

# ------------------------------------------------------------------
echo "--- 2. Malicious npm packages (atomic-lockfile, js-digest) ---"
NPM_HITS=$(find /home /root /usr/lib/node_modules /usr/local/lib/node_modules /tmp /var/tmp \
    -maxdepth 6 \( -path '*node_modules/atomic-lockfile*' -o -path '*node_modules/js-digest*' \) \
    -print 2>/dev/null)
if [ -n "$NPM_HITS" ]; then
    flag "Malicious npm package found on disk:"
    echo "$NPM_HITS"
else
    ok "No atomic-lockfile / js-digest found in common node_modules locations"
fi

# npm cache check (covers installs that were later cleaned up)
for cache in /home/*/.npm /root/.npm; do
    [ -d "$cache" ] || continue
    HITS=$(grep -rls -e atomic-lockfile -e js-digest "$cache/_cacache/index-v5" 2>/dev/null)
    if [ -n "$HITS" ]; then
        flag "npm cache in $cache references atomic-lockfile/js-digest (package was fetched at some point)"
    fi
done
echo

# ------------------------------------------------------------------
echo "--- 3. 'deps' stealer binary and eBPF rootkit artifacts ---"
DEPS_HITS=$(find /tmp /var/tmp /usr/local/bin /home -maxdepth 4 -type f -name 'deps' 2>/dev/null)
[ -n "$DEPS_HITS" ] && flag "Suspicious 'deps' binary: $DEPS_HITS" || ok "No 'deps' binary in common drop locations"

BPF_HITS=$(find / -xdev -name 'scales.bpf*' 2>/dev/null)
[ -n "$BPF_HITS" ] && flag "eBPF rootkit artifact found: $BPF_HITS" || ok "No scales.bpf artifacts found"

if [ "$(id -u)" -eq 0 ]; then
    if command -v bpftool >/dev/null 2>&1; then
        echo "Loaded eBPF programs (review for anything unexpected):"
        bpftool prog show 2>/dev/null | sed 's/^/    /'
    else
        warn "bpftool not installed — install 'bpf' package and re-run as root for eBPF inspection"
    fi
else
    warn "Not root — re-run with sudo to inspect loaded eBPF programs"
fi
echo

# ------------------------------------------------------------------
echo "--- 4. npm commands injected into pacman install hooks (foreign pkgs) ---"
HOOK_FLAGGED=0
while read -r pkg; do
    inst="/var/lib/pacman/local/$(pacman -Q "$pkg" | tr ' ' '-')/install"
    if [ -f "$inst" ] && grep -qE '\bnpm (install|i)\b' "$inst"; then
        flag "Foreign package '$pkg' has an .INSTALL hook running npm: $inst"
        HOOK_FLAGGED=1
    fi
done < <(pacman -Qqm)
[ "$HOOK_FLAGGED" -eq 0 ] && ok "No npm commands in install hooks of foreign packages"
echo

# ------------------------------------------------------------------
echo "--- 5. Cached AUR build dirs (yay/paru) with npm in PKGBUILD/.install ---"
CACHE_FLAGGED=0
for dir in /home/*/.cache/yay /home/*/.cache/paru/clone; do
    [ -d "$dir" ] || continue
    while read -r f; do
        if grep -qE '\bnpm (install|i)\b.*\b(atomic-lockfile|js-digest|yargs)\b' "$f" 2>/dev/null \
           || { grep -qE '\bnpm (install|i)\b' "$f" 2>/dev/null && ! grep -qiE 'node|electron|js|npm' <<<"$(dirname "$f")"; }; then
            flag "Suspicious npm command in cached build file: $f"
            CACHE_FLAGGED=1
        fi
    done < <(find "$dir" -maxdepth 2 \( -name PKGBUILD -o -name '*.install' \) 2>/dev/null)
done
[ "$CACHE_FLAGGED" -eq 0 ] && ok "No suspicious npm commands in cached AUR build files"
echo

# ------------------------------------------------------------------
echo "=== Summary ==="
if [ "$FINDINGS" -gt 0 ]; then
    echo "${RED}$FINDINGS finding(s) flagged above.${NC}"
    echo "If any confirmed: disconnect from network, rotate ALL credentials"
    echo "(SSH keys, GitHub/npm tokens, browser passwords, Docker/cloud auth),"
    echo "and treat the system as compromised — eBPF rootkit can hide from"
    echo "userspace tools, so reinstall is the safe path if it ran as root."
else
    echo "${GRN}No indicators found.${NC} Still cross-check section 1 packages against"
    echo "the official list: https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/"
    echo "and the CachyOS thread: https://discuss.cachyos.org/t/31040"
fi
