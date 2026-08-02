#!/bin/sh
set -eu

expected_version="v0.7.1"
d2_bin="${D2_BIN:-d2}"
mode="${1:-check}"

if [ "$("$d2_bin" version)" != "$expected_version" ]; then
    echo "error: D2 $expected_version is required (set D2_BIN to the pinned binary)" >&2
    exit 1
fi

case "$mode" in
    render | check) ;;
    *)
        echo "usage: $0 [render|check]" >&2
        exit 1
        ;;
esac

diagram_directory="docs/architecture"
diagrams="cli-modules scan-pipeline detector-config-trust"

render_diagram() {
    name="$1"
    output="$2"
    "$d2_bin" validate "$diagram_directory/$name.d2"
    "$d2_bin" fmt --check "$diagram_directory/$name.d2"
    "$d2_bin" --layout=elk --theme=0 --pad=40 --omit-version --salt="$name" \
        "$diagram_directory/$name.d2" "$output"
}

if [ "$mode" = "render" ]; then
    for name in $diagrams; do
        render_diagram "$name" "$diagram_directory/$name.svg"
    done
    exit 0
fi

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

for name in $diagrams; do
    rendered="$temporary_directory/$name.svg"
    render_diagram "$name" "$rendered"
    if ! cmp -s "$rendered" "$diagram_directory/$name.svg"; then
        echo "error: $diagram_directory/$name.svg is stale; run $0 render" >&2
        exit 1
    fi
done
