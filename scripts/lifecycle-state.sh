# shellcheck shell=bash
# The state checks of scripts/systemd-lifecycle.sh (sourced): what must
# survive a package upgrade and rollback unchanged. Tested by
# scripts/test-lifecycle-state.sh.

seg_hash() { # file [partial] -> sha256 of the whole file, or of its first 4 KiB
    if [[ ${2:-} == partial ]]; then
        head -c 4096 "$1" | sha256sum | cut -d' ' -f1
    else
        sha256sum <"$1" | cut -d' ' -f1
    fi
}

# state_snapshot BLACKBOX_DIR FILE... -> stdout, one "sha256 path [partial]"
# line per FILE and per black-box segment (seg-*.rbb) in BLACKBOX_DIR.
# FILEs and every segment but the newest are hashed in full: a sealed
# segment must stay byte for byte the same. The newest segment may still
# grow once agentd starts again, so only its first 4 KiB are recorded.
state_snapshot() {
    local dir="$1" f segs i n
    shift
    for f in "$@"; do
        printf '%s %s\n' "$(seg_hash "$f")" "$f"
    done
    mapfile -t segs < <(find "$dir" -name 'seg-*.rbb' | LC_ALL=C sort)
    n=${#segs[@]}
    for ((i = 0; i < n; i++)); do
        if ((i == n - 1)); then
            printf '%s %s partial\n' "$(seg_hash "${segs[i]}" partial)" "${segs[i]}"
        else
            printf '%s %s\n' "$(seg_hash "${segs[i]}")" "${segs[i]}"
        fi
    done
}

# state_changed SNAPSHOT_FILE -> stdout: " path (why)" for every file the
# snapshot recorded that is now missing or different (empty: unchanged).
# Files added since (a new segment) are not changes.
state_changed() {
    local want path mode
    while read -r want path mode; do
        if [[ ! -f $path ]]; then
            printf ' %s (missing)' "$path"
        elif [[ "$(seg_hash "$path" "$mode")" != "$want" ]]; then
            if [[ -n $mode ]]; then
                printf ' %s (first 4 KiB changed)' "$path"
            else
                printf ' %s (changed)' "$path"
            fi
        fi
    done <"$1"
}
