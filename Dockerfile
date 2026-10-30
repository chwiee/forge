# forge's own image (used as CI job image and by the forge-db mirror).
# Alpine, not scratch: GitLab/Azure DevOps job containers need a shell.
# Build the binary first: make build   (or let forge build itself: forge run .)
FROM alpine:3.22
RUN apk add --no-cache git ca-certificates \
 && adduser -D -u 65532 forge
COPY bin/forge /usr/local/bin/forge
ENV FORGE_CACHE_DIR=/cache
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/forge"]
CMD ["--help"]
