#!/usr/bin/env bash
# Shared settings for the lab scripts (Git Bash on Windows, Linux or macOS).
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-lab}"
# Single-Region project: everything lives in the project's selected Region.
export AWS_REGION="${AWS_REGION:-us-east-2}"
export AWS_DEFAULT_REGION="$AWS_REGION"
export PYTHONUTF8=1            # aws.exe on Windows breaks on non-ASCII output without it

STACK=forge-lab
CLUSTER=forge-lab
CTX=forge-lab                  # dedicated kubectl context: never touches your other clusters
REPO_PREFIX=forge-lab
APPS=(orders-go catalog-node billing-java)
WSL_DISTRO="${WSL_DISTRO:-Ubuntu-24.04}"

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORGE_DIR="$(cd "$LAB_DIR/../.." && pwd)"
TMP="$LAB_DIR/.tmp"; mkdir -p "$TMP"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

need() { for b in "$@"; do command -v "$b" >/dev/null 2>&1 || die "missing '$b'"; done; }
k()    { kubectl --context "$CTX" "$@"; }

account_id() {
  aws sts get-caller-identity --query Account --output text 2>/dev/null ||
    die "no AWS session — run: aws login --profile $AWS_PROFILE"
}
registry()     { echo "${ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"; }
stack_status() { aws cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo NONE; }
forge_tag()    { echo "lab-$(git -C "$FORGE_DIR" rev-parse --short HEAD)"; }

# render replaces __PLACEHOLDERS__ in a manifest template.
render() {
  sed -e "s|__ACCOUNT__|${ACCOUNT}|g" -e "s|__REGION__|${AWS_REGION}|g" \
      -e "s|__REGISTRY__|${REGISTRY}|g" -e "s|__FORGE_IMAGE__|${FORGE_IMAGE:-}|g" \
      -e "s|__APP__|${APP:-}|g" -e "s|__ARCH__|${ARCH:-}|g" -e "s|__TAG__|${TAG:-}|g" \
      -e "s|__REPO_PREFIX__|${REPO_PREFIX}|g" "$1"
}

# wsl_run runs a script inside the Linux distro (forge is a Linux binary) with the
# same AWS profile/Region. ~/.aws in the distro must point to the Windows one.
wsl_run() {
  MSYS_NO_PATHCONV=1 wsl -d "$WSL_DISTRO" -u root -- env AWS_PROFILE="$AWS_PROFILE" \
    AWS_REGION="$AWS_REGION" "$@"
}
win_to_wsl() { local p; p="$(cd "$1" && pwd -W 2>/dev/null || pwd)"; p="${p//\\//}"; echo "/mnt/$(echo "${p:0:1}" | tr 'A-Z' 'a-z')${p:2}"; }
