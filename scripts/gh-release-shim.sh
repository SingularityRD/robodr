#!/usr/bin/env bash
# Local stand-in for the `gh` sub-commands release.yml uses, for
# scripts/release-dry-run.sh ONLY (it is put on PATH as `gh` inside the dry
# run; never install it as gh). A "release" is a directory
# $GH_SHIM_ROOT/<tag>/ with assets/ and meta (draft, prerelease, latest,
# title, notes); nothing leaves the machine.
#
#   gh release create TAG --repo R --draft [--verify-tag] [--prerelease] --title T --notes-file F
#   gh release upload TAG --repo R [--clobber] FILE...
#   gh release download TAG --repo R -D DIR
#   gh release view TAG --repo R --json body --jq .body
#   gh release edit TAG --repo R [--notes-file F] [--draft=false] [--latest=true|false]
#   gh api -X GET repos/R/actions/workflows/ci.yml/runs -f head_sha=SHA -f per_page=N
#       (the CI gate, scripts/release-gate.py): one completed run of event
#       push for SHA, with conclusion $GH_SHIM_CI_CONCLUSION (default
#       success; the dry run's guard test sets failure).
#
# --verify-tag: the dry run does not create a git tag (by design); the shim
# checks instead that GITHUB_SHA is a commit of the dry-run repository.
# Exit: 0 ok, 1 refused (as gh would), 2 usage.
set -euo pipefail

die() { echo "gh(shim): $2" >&2; exit "$1"; }
[[ -n "${GH_SHIM_ROOT:-}" ]] || die 2 "GH_SHIM_ROOT is not set (only scripts/release-dry-run.sh uses this shim)"

if [[ "${1:-}" == api ]]; then
    shift
    path="" sha=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
        -X) shift 2 ;;
        -f) case "$2" in head_sha=*) sha="${2#head_sha=}" ;; esac; shift 2 ;;
        -*) die 2 "api: option $1 is not emulated" ;;
        *) path="$1"; shift ;;
        esac
    done
    [[ "$path" =~ ^repos/[^/]+/[^/]+/actions/workflows/ci\.yml/runs$ ]] || die 2 "api: only the ci.yml runs endpoint is emulated, got $path"
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die 2 "api: head_sha missing"
    printf '{"total_count":1,"workflow_runs":[{"head_sha":"%s","event":"push","status":"completed","conclusion":"%s","run_number":1,"html_url":"local://dry-run"}]}\n' \
        "$sha" "${GH_SHIM_CI_CONCLUSION:-success}"
    exit 0
fi

[[ "${1:-}" == release ]] || die 2 "only 'gh release' and the CI 'gh api' call are emulated, got: $*"
shift
cmd="${1:-}"
shift || true
tag="${1:-}"
shift || true
[[ -n "$tag" && "$tag" != -* ]] || die 2 "$cmd: tag missing"
rel="$GH_SHIM_ROOT/$tag"
repo=""
draft="" pre=0 title="" notes="" clobber=0 dest="" verify=0 latest="" json="" jq=""
files=()
while [[ $# -gt 0 ]]; do
    case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --draft) draft=1; shift ;;
    --draft=false) draft=0; shift ;;
    --draft=true) draft=1; shift ;;
    --latest=true) latest=1; shift ;;
    --latest=false) latest=0; shift ;;
    --prerelease) pre=1; shift ;;
    --verify-tag) verify=1; shift ;;
    --title) title="$2"; shift 2 ;;
    --notes-file) notes="$2"; shift 2 ;;
    --clobber) clobber=1; shift ;;
    --json) json="$2"; shift 2 ;;
    --jq) jq="$2"; shift 2 ;;
    -D) dest="$2"; shift 2 ;;
    -*) die 2 "$cmd: option $1 is not emulated" ;;
    *) files+=("$1"); shift ;;
    esac
done
[[ -n "$repo" ]] || die 2 "$cmd: --repo missing"

case "$cmd" in
create)
    [[ ! -e "$rel" ]] || die 1 "release $tag already exists"
    if [[ "$verify" == 1 ]]; then
        git -C "${GH_SHIM_GIT:?}" cat-file -e "${GITHUB_SHA:?}^{commit}" ||
            die 1 "--verify-tag: commit $GITHUB_SHA not in the dry-run repository"
    fi
    [[ -s "$notes" ]] || die 1 "notes file $notes empty"
    mkdir -p "$rel/assets"
    cp "$notes" "$rel/notes.md"
    printf 'tag=%s\nrepo=%s\ndraft=%s\nprerelease=%s\nlatest=\ntitle=%s\n' "$tag" "$repo" "${draft:-0}" "$pre" "$title" >"$rel/meta"
    echo "gh(shim): draft release $tag created (prerelease=$pre, title '$title')" >&2
    ;;
upload)
    [[ -d "$rel/assets" ]] || die 1 "release $tag not found"
    [[ ${#files[@]} -gt 0 ]] || die 2 "upload: no files"
    for f in "${files[@]}"; do
        [[ -f "$f" ]] || die 1 "upload: $f is not a file"
        b="$(basename "$f")"
        if [[ -e "$rel/assets/$b" && "$clobber" != 1 ]]; then
            die 1 "upload: asset $b already exists (no --clobber)"
        fi
        cp "$f" "$rel/assets/$b"
        echo "gh(shim): uploaded $b" >&2
    done
    ;;
download)
    [[ -d "$rel/assets" ]] || die 1 "release $tag not found"
    [[ -n "$dest" ]] || die 2 "download: -D missing"
    mkdir -p "$dest"
    for f in "$rel/assets"/*; do
        [[ -e "$dest/$(basename "$f")" ]] && die 1 "download: $(basename "$f") exists in $dest"
        cp "$f" "$dest/"
    done
    ;;
view)
    [[ -f "$rel/meta" ]] || die 1 "release $tag not found"
    [[ "$json" == body && "$jq" == .body ]] || die 2 "view: only --json body --jq .body is emulated"
    cat "$rel/notes.md"
    ;;
edit)
    [[ -f "$rel/meta" ]] || die 1 "release $tag not found"
    [[ -z "$notes" ]] || { [[ -s "$notes" ]] || die 1 "notes file $notes empty"; cp "$notes" "$rel/notes.md"; }
    if [[ "$draft" == 0 ]]; then
        sed -i 's/^draft=.*/draft=0/' "$rel/meta"
        echo "gh(shim): release $tag published (draft=false)" >&2
    elif [[ -n "$draft" ]]; then
        die 2 "edit: only --draft=false is emulated"
    fi
    [[ -z "$latest" ]] || sed -i "s/^latest=.*/latest=$latest/" "$rel/meta"
    ;;
*) die 2 "gh release $cmd is not emulated" ;;
esac
