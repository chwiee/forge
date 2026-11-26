#!/usr/bin/env bash
# Brings the lab up: forge image -> ECR (in WSL) while CloudFormation creates the
# EKS cluster (~15-18 min), then the forge-db mirror inside the cluster.
# Idempotent: running again only does what is missing.
source "$(dirname "$0")/lib.sh"

need aws kubectl go git wsl curl
ACCOUNT="$(account_id)"; REGISTRY="$(registry)"
FORGE_IMAGE="$REGISTRY/$REPO_PREFIX/forge:$(forge_tag)"
log "account $ACCOUNT · Region $AWS_REGION · profile $AWS_PROFILE"
warn "confirm the Region in AWS Settings > View all projects > Overview > Additional Info > Region"

# ------------------------------------------------------------------ 1. forge image (background)
log "1/4 forge image $FORGE_IMAGE"
if aws ecr describe-images --repository-name "$REPO_PREFIX/forge" --image-ids imageTag="$(forge_tag)" >/dev/null 2>&1; then
  ok "already in ECR"; IMG_PID=""
else
  (cd "$FORGE_DIR" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$TMP/forge" ./cmd/forge)
  wsl_run bash "$(win_to_wsl "$LAB_DIR/infra")/forge-image.sh" "$(win_to_wsl "$FORGE_DIR")" \
    "$(win_to_wsl "$TMP")/forge" "$REPO_PREFIX/forge" "$(forge_tag)" >"$TMP/forge-image.log" 2>&1 &
  IMG_PID=$!
  ok "building in WSL (log: $TMP/forge-image.log)"
fi

# ------------------------------------------------------------------ 2. cluster
log "2/4 EKS cluster (CloudFormation stack $STACK)"
case "$(stack_status)" in
  CREATE_COMPLETE|UPDATE_COMPLETE) ok "stack already up" ;;
  NONE)
    MYIP="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
    VERSION="$(aws eks describe-cluster-versions --query "clusterVersions[?versionStatus=='STANDARD_SUPPORT'].clusterVersion" --output text | tr '\t' '\n' | sort -V | tail -1)"
    ok "Kubernetes $VERSION · API reachable only from $MYIP/32"
    (cd "$LAB_DIR/infra" && aws cloudformation deploy --stack-name "$STACK" --template-file cluster.yaml \
      --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
      --tags project=forge-lab disposable=yes \
      --parameter-overrides KubernetesVersion="$VERSION" AdminCidr="$MYIP/32" RepoPrefix="$REPO_PREFIX")
    ok "stack created" ;;
  *) die "stack is $(stack_status) — run ./infra/down.sh and try again" ;;
esac
aws eks update-kubeconfig --name "$CLUSTER" --alias "$CTX" >/dev/null
k get nodes -L kubernetes.io/arch,node.kubernetes.io/instance-type

# ------------------------------------------------------------------ 3. wait for the image
log "3/4 waiting for the forge image"
if [[ -n "$IMG_PID" ]]; then
  if wait "$IMG_PID"; then ok "pushed (gates passed)"; else tail -40 "$TMP/forge-image.log"; die "forge image failed"; fi
fi

# ------------------------------------------------------------------ 4. in-cluster pieces
log "4/4 forge-ci namespace + forge-db mirror"
render "$LAB_DIR/k8s/base.yaml" | k apply -f - >/dev/null
k -n forge-ci rollout status deploy/forge-db --timeout=300s
ok "ready"

cat <<EOF

$(printf '\033[1;32m')Lab up.$(printf '\033[0m') Next:

  ./infra/run.sh     # 3 apps x 2 archs in parallel, checks gates and the ECR index
  ./infra/down.sh    # ALWAYS at the end (~US\$ 0.55/h while up)
EOF
