#!/usr/bin/env bash
# Tears everything down and looks for anything still billing.
#   ./down.sh               deletes the stack (cluster, nodes, NAT, VPC, IAM) AND the forge-lab/* ECR repos
#   ./down.sh --keep-images keeps the ECR repos (cents/month; next up.sh skips the forge image build)
source "$(dirname "$0")/lib.sh"

KEEP=0; [[ "${1:-}" == "--keep-images" ]] && KEEP=1
need aws kubectl
ACCOUNT="$(account_id)"

# ------------------------------------------------------------------ 1. workloads
log "1/4 workloads"
if aws eks describe-cluster --name "$CLUSTER" >/dev/null 2>&1; then
  aws eks update-kubeconfig --name "$CLUSTER" --alias "$CTX" >/dev/null
  # Nothing here creates AWS resources (no LoadBalancer Services, no PVCs), but
  # deleting first is the safe habit: Kubernetes cleans up what IT created.
  k delete namespace forge-ci forge-lab-apps --ignore-not-found --wait=true --timeout=120s || warn "namespaces slow to delete"
  ok "namespaces gone"
else
  ok "no cluster"
fi

# ------------------------------------------------------------------ 2. stack
log "2/4 CloudFormation stack $STACK (~10 min)"
if [[ "$(stack_status)" != NONE ]]; then
  aws cloudformation delete-stack --stack-name "$STACK"
  aws cloudformation wait stack-delete-complete --stack-name "$STACK" || die "delete failed — check CloudFormation events for $STACK"
  ok "stack deleted"
else
  ok "no stack"
fi
kubectl config delete-context "$CTX" >/dev/null 2>&1 || true

# ------------------------------------------------------------------ 3. ECR
log "3/4 ECR repositories $REPO_PREFIX/*"
repos="$(aws ecr describe-repositories --query "repositories[?starts_with(repositoryName, '$REPO_PREFIX/')].repositoryName" --output text | tr '\t' ' ')"
if [[ $KEEP == 1 ]]; then
  ok "kept: ${repos:-none}"
else
  for r in $repos; do aws ecr delete-repository --repository-name "$r" --force >/dev/null && ok "deleted $r"; done
  [[ -z "$repos" ]] && ok "none"
fi

# ------------------------------------------------------------------ 4. leftovers
log "4/4 anything still billing in $AWS_REGION?"
LEFT=0
check() { local out; out="$("${@:2}" 2>/dev/null || true)"
  if [[ -n "$out" && "$out" != "None" ]]; then warn "$1:"; echo "$out" | sed 's/^/      /'; LEFT=1; fi; }
check "EKS clusters"      aws eks list-clusters --query 'clusters[]' --output text
check "NAT gateways"      aws ec2 describe-nat-gateways --filter Name=state,Values=available,pending --query 'NatGateways[].NatGatewayId' --output text
check "Elastic IPs"       aws ec2 describe-addresses --query 'Addresses[].PublicIp' --output text
check "running EC2"       aws ec2 describe-instances --filters Name=instance-state-name,Values=running,pending --query 'Reservations[].Instances[].[InstanceId,InstanceType]' --output text
check "detached EBS"      aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[].[VolumeId,Size]' --output text
check "load balancers"    aws elbv2 describe-load-balancers --query 'LoadBalancers[].LoadBalancerName' --output text

if [[ $LEFT == 0 ]]; then printf '\n\033[1;32mAll clean.\033[0m\n'
else printf '\n\033[1;33mSomething above is still running (may belong to other projects) — check before deleting.\033[0m\n'; exit 2; fi
