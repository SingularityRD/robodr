# shellcheck shell=bash
# Sourced by build-deb.sh and build-rpm.sh (not run on its own).
#
# check_release_maintainer VALUE VARIABLE TOOL
#
# In a release build (ROBODR_RELEASE=1; release.yml sets it and takes the
# value from the repository variable ROBODR_MAINTAINER) the package
# maintainer / packager must be "Name <address>" with a real address: not
# the development default (robodr-maintainers@invalid) and no other
# reserved placeholder domain (.invalid, example.*, localhost: RFC 2606).
# Exits 2 otherwise. Outside a release it does nothing, so development and
# CI builds keep the placeholder.
check_release_maintainer() {
    if [[ "${ROBODR_RELEASE:-0}" != 1 ]]; then
        return 0
    fi
    local v="$1" addr re='^[^<>]*[^<> ] <([^<> ]+@[^<> ]+\.[^<> ]+)>$'
    if [[ ! "$v" =~ $re ]]; then
        echo "$3: ROBODR_RELEASE=1: $2 must be 'Name <address>' (got '$v'; release.yml takes it from the repository variable ROBODR_MAINTAINER)" >&2
        exit 2
    fi
    addr="${BASH_REMATCH[1],,}"
    case "$addr" in
    *.invalid | *@invalid | *@example.* | *.example | *.example.* | *@localhost | *.localhost)
        echo "$3: ROBODR_RELEASE=1: $2 is a placeholder address ($addr); set the real maintainer (repository variable ROBODR_MAINTAINER)" >&2
        exit 2
        ;;
    esac
}
