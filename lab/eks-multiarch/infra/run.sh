#!/usr/bin/env bash
# The test: 3 apps x 2 architectures = 6 forge Jobs at the same time, then checks:
#   orders-go     -> both Jobs exit 0 and ECR has <tag> as an index with amd64 + arm64
#   catalog-node  -> both Jobs exit 1 (CVE gate) and NOTHING was pushed
#   billing-java  -> both Jobs exit 1 (CVE gate) and NOTHING was pushed
# Finally runs orders-go:<tag> on both node groups from the same tag.
source "$(dirname "$0")/lib.sh"

need aws kubectl tar
ACCOUNT="$(account_id)"; REGISTRY="$(registry)"
FORGE_IMAGE="$REGISTRY/$REPO_PREFIX/forge:$(forge_tag)"
TAG="${TAG:-run-$(date +%Y%m%d-%H%M%S)}"
declare -A EXPECT=([orders-go]=0 [catalog-node]=1 [billing-java]=1)
log "run $TAG"

# ------------------------------------------------------------------ 1. sources
log "1/5 app sources -> ConfigMaps"
for APP in "${APPS[@]}"; do
  tar -czf "$TMP/$APP.tgz" -C "$LAB_DIR/apps/$APP" .
  k -n forge-ci create configmap "src-$APP" --from-file=src.tgz="$TMP/$APP.tgz" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  ok "$APP ($(du -h "$TMP/$APP.tgz" | cut -f1))"
done

# ------------------------------------------------------------------ 2. 6 Jobs at once
log "2/5 starting 6 builds in parallel"
k -n forge-ci delete job -l forge.dev/app --ignore-not-found >/dev/null
for APP in "${APPS[@]}"; do
  for ARCH in amd64 arm64; do
    render "$LAB_DIR/k8s/build-job.yaml" | k apply -f - >/dev/null
    ok "build-$APP-$ARCH"
  done
done

# ------------------------------------------------------------------ 3. wait
log "3/5 waiting (first run ~5-8 min: cold base images + Maven/npm downloads)"
START=$SECONDS
while :; do
  done_n="$(k -n forge-ci get jobs -l forge.dev/run="$TAG" -o jsonpath='{range .items[*]}{.status.succeeded}{.status.failed}{"\n"}{end}' | grep -c . || true)"
  printf '\r  %d/6 finished · %ds ' "$done_n" $((SECONDS - START))
  [[ "$done_n" -ge 6 ]] && break
  (( SECONDS - START > 1800 )) && die "timeout"
  sleep 10
done
echo

# ------------------------------------------------------------------ 4. results
log "4/5 results"
FAIL=0
exit_code() { k -n forge-ci get pods -l "forge.dev/app=$1,forge.dev/arch=$2,forge.dev/run=$TAG" \
  -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}'; }
printf '  %-14s %-6s %-6s %-9s %s\n' APP ARCH EXIT EXPECTED NODE
for APP in "${APPS[@]}"; do
  for ARCH in amd64 arm64; do
    code="$(exit_code "$APP" "$ARCH")"
    node="$(k -n forge-ci get pods -l "forge.dev/app=$APP,forge.dev/arch=$ARCH,forge.dev/run=$TAG" -o jsonpath='{.items[0].spec.nodeName}')"
    mark="✓"; [[ "$code" == "${EXPECT[$APP]}" ]] || { mark="✗"; FAIL=1; }
    printf '  %-14s %-6s %-6s %-9s %s %s\n' "$APP" "$ARCH" "$code" "${EXPECT[$APP]}" "$node" "$mark"
    k -n forge-ci logs "job/build-$APP-$ARCH" >"$TMP/$TAG-$APP-$ARCH.log" 2>&1 || true
  done
done
ok "full forge logs: $TMP/$TAG-*.log"

echo
for APP in "${APPS[@]}"; do
  tags="$(aws ecr describe-images --repository-name "$REPO_PREFIX/$APP" --query 'imageDetails[].imageTags[]' \
    --output text 2>/dev/null | tr '\t' '\n' | grep -E "^$TAG(-amd64|-arm64)?$" | sort | tr '\n' ' ' || true)"
  if [[ "${EXPECT[$APP]}" == 0 ]]; then
    manifest="$(aws ecr batch-get-image --repository-name "$REPO_PREFIX/$APP" --image-ids imageTag="$TAG" \
      --accepted-media-types application/vnd.oci.image.index.v1+json application/vnd.docker.distribution.manifest.list.v2+json \
      --query 'images[0].imageManifest' --output text 2>/dev/null || true)"
    archs="$(echo "$manifest" | grep -o '"architecture" *: *"[a-z0-9]*"' | sed 's/.*"\([a-z0-9]*\)"$/\1/' | sort | tr '\n' ' ')"
    if [[ "$manifest" == *index* || "$manifest" == *manifest.list* ]] && [[ "$archs" == "amd64 arm64 " ]]; then
      ok "$APP: ECR tags [$tags] · $TAG is a multi-arch index ($archs)"
    else
      warn "$APP: expected index amd64+arm64 at $TAG, got tags [$tags] archs [$archs]"; FAIL=1
    fi
  else
    if [[ -z "$tags" ]]; then ok "$APP: blocked by the gate · nothing pushed"
    else warn "$APP: should be blocked but ECR has [$tags]"; FAIL=1; fi
  fi
done
echo; grep -h "cve " "$TMP/$TAG"-*-amd64.log 2>/dev/null | sed 's/^/  amd64 /' || true

# ------------------------------------------------------------------ 5. one tag, two archs
log "5/5 running orders-go:$TAG (no arch suffix) on both node groups"
if [[ "$FAIL" == 0 ]]; then
  render "$LAB_DIR/k8s/orders.yaml" | k apply -f - >/dev/null
  k -n forge-lab-apps rollout status deploy/orders-go --timeout=180s
  for p in $(k -n forge-lab-apps get pods -l app=orders-go -o jsonpath='{.items[*].metadata.name}'); do
    node="$(k -n forge-lab-apps get pod "$p" -o jsonpath='{.spec.nodeName}')"
    narch="$(k get node "$node" -o jsonpath='{.metadata.labels.kubernetes\.io/arch}')"
    info="$(k get --raw "/api/v1/namespaces/forge-lab-apps/pods/$p:8080/proxy/info")"
    ok "node arch $narch -> /info $info"
  done
else
  warn "skipped: fix the results above first"
fi

echo
if [[ "$FAIL" == 0 ]]; then printf '\033[1;32mLAB PASSED\033[0m — remember: ./infra/down.sh\n'
else printf '\033[1;31mLAB FAILED\033[0m — see logs in %s\n' "$TMP"; exit 1; fi
