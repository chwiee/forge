#!/usr/bin/env bash
# Runs INSIDE WSL (called by up.sh): builds the forge image for amd64+arm64 with forge
# itself (cross-compiled, no emulation) and pushes it to ECR. Gates apply here too.
#   forge-image.sh <forge-repo-path> <linux-forge-binary> <repo> <tag>
set -euo pipefail
SRC="$1" BIN="$2" REPO="$3" TAG="$4"

install -m 0755 "$BIN" /usr/local/bin/forge
WORK=/root/forge-lab-src
rm -rf "$WORK" && mkdir -p "$WORK/lab/eks-multiarch"
cp -r "$SRC/cmd" "$SRC/internal" "$SRC/go.mod" "$SRC/go.sum" "$WORK/"
cp "$SRC/lab/eks-multiarch/Dockerfile.forge" "$WORK/lab/eks-multiarch/"
cd "$WORK"
forge run . -f lab/eks-multiarch/Dockerfile.forge \
  --platform linux/amd64,linux/arm64 \
  --registry ecr --name "$REPO" --create-repo --tag "$TAG" \
  --region "$AWS_REGION"
