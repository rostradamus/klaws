# Release & Publishing Runbook

How to cut a klaws release and publish it to the [official MCP registry](https://registry.modelcontextprotocol.io).

## Versioning

`klaws` uses [semantic versioning](https://semver.org) with `vMAJOR.MINOR.PATCH` git tags. The version is injected into the binary at build time (`-ldflags -X main.version=...`) and is also advertised by the MCP server and declared in `server.json`.

Keep these three in sync when bumping the version:

- the git tag (`vX.Y.Z`)
- `version` and the package `identifier` tag in [`server.json`](server.json)
- the version string in [`internal/mcp/server.go`](internal/mcp/server.go) (`server.NewMCPServer`)

## 1. Cut a release

A push of a `v*` tag triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which runs GoReleaser to:

- build cross-platform binaries (linux/darwin/windows × amd64/arm64) and publish them with checksums to a GitHub Release, and
- build and push a multi-arch OCI image to `ghcr.io/rostradamus/klaws` (`:X.Y.Z` and `:latest`).

```bash
# from an up-to-date main
git tag -a vX.Y.Z -m "klaws vX.Y.Z"
git push origin vX.Y.Z
```

Watch the run:

```bash
gh run watch "$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
gh release view vX.Y.Z --json tagName,assets --jq '{tagName, assets:[.assets[].name]}'
```

## 2. Make the GHCR image public (first release only)

New GitHub Container Registry packages default to **private**. The MCP registry (and end users) must be able to pull the image, so set it public once:

Repo → **Packages** → `klaws` → **Package settings** → **Change visibility** → **Public**.

Verify the image carries the ownership label the registry checks (must equal the `name` in `server.json`):

```bash
docker pull ghcr.io/rostradamus/klaws:X.Y.Z
docker inspect ghcr.io/rostradamus/klaws:X.Y.Z \
  --format '{{ index .Config.Labels "io.modelcontextprotocol.server.name" }}'
# expect: io.github.rostradamus/klaws
```

The label is set by `LABEL io.modelcontextprotocol.server.name=...` in the [`Dockerfile`](Dockerfile).

## 3. Publish to the MCP registry

Install the publisher CLI (`brew install mcp-publisher`, or grab a binary from the
[registry releases](https://github.com/modelcontextprotocol/registry/releases/latest)).

```bash
# validate without publishing (offline schema check)
mcp-publisher validate server.json

# authenticate (interactive GitHub OAuth — must be the rostradamus account,
# which owns the io.github.rostradamus/* namespace)
mcp-publisher login github

# publish from the repo root (reads ./server.json)
mcp-publisher publish
```

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Registry validation failed for package` | The image must be public (step 2) and carry the `io.modelcontextprotocol.server.name` label matching `server.json`. After flipping visibility, wait a minute and retry. |
| `Invalid or expired Registry JWT token` | Re-run `mcp-publisher login github`. |
| `server.json is invalid` | Run `mcp-publisher validate server.json`; check `$schema`, `registryType` (camelCase), and that `identifier` includes the image tag (`ghcr.io/rostradamus/klaws:X.Y.Z`). |

## Updating a published server

Bump the version (all three places above), cut a new tag, then re-run `mcp-publisher publish`. The registry keys releases by version and marks the newest as latest.
