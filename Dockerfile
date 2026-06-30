# GoReleaser builds the binary and uses this Dockerfile to assemble the image,
# so it only needs to COPY the prebuilt binary into a minimal base.
FROM gcr.io/distroless/static:nonroot
# Proves ownership of the server name to the MCP registry; the value MUST match
# the "name" field in server.json.
LABEL io.modelcontextprotocol.server.name="io.github.rostradamus/klaws"
COPY klaws /klaws
ENTRYPOINT ["/klaws"]
# Default to the MCP stdio server; override with e.g. `scan /work`.
CMD ["serve"]
