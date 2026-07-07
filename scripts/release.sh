#!/usr/bin/env bash
#
# Bump every version-pinned reference for a new release, in one shot.
#
#   scripts/release.sh 0.1.6
#
# What it updates:
#   - server.json          registry version + OCI image identifier
#   - README(.ko).md       the deliberately-pinned `docker run …:<ver>` example
#
# What it deliberately does NOT touch (these are version-agnostic by design):
#   - internal/mcp/server.go   version comes from -ldflags main.version at build
#   - README Docker quickstart / MCP config   use the floating `:latest` tag
#   - README GitHub Action example            uses the moving `@v0` major tag
#
# After running: review `git diff`, commit on a release branch, open a PR, and
# once merged tag `vX.Y.Z`. The release workflow builds artifacts, publishes
# server.json to the MCP Registry (OIDC), and re-points the `v0` alias tag.
set -euo pipefail

ver="${1:?usage: scripts/release.sh <version, e.g. 0.1.6>}"
ver="${ver#v}" # tolerate a leading v
if ! printf '%s' "$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "error: version must be semver like 0.1.6 (got '$ver')" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"

# server.json — registry version + OCI image tag.
python3 - "$root/server.json" "$ver" <<'PY'
import json, sys
path, ver = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
d["version"] = ver
for pkg in d.get("packages", []):
    if pkg.get("registryType") == "oci":
        pkg["identifier"] = f"ghcr.io/rostradamus/klaws:{ver}"
with open(path, "w") as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY

# README pinned-docker example (EN + KO): `…/klaws:<ver> scan`.
for f in "$root/README.md" "$root/README.ko.md"; do
  perl -pi -e "s{ghcr\.io/rostradamus/klaws:[0-9]+\.[0-9]+\.[0-9]+ scan}{ghcr.io/rostradamus/klaws:${ver} scan}g" "$f"
done

echo "Bumped version references to ${ver}. Changed files:"
git -C "$root" diff --name-only

echo
echo "Validate server.json before releasing:"
echo "  mcp-publisher validate"
