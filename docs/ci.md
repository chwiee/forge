# forge no CI

O forge é um binário só. Em qualquer CI o padrão é o mesmo:

1. usar a imagem `ghcr.io/chwiee/forge` (ou baixar o binário);
2. rodar `forge run . --registry <ecr|ghcr> --name <repo>`;
3. publicar `.forge/report.json` como artefato.

Exit codes: **0** aprovado e publicado · **1** reprovado em algum gate (push bloqueado) · **2** erro técnico.

Variáveis úteis:

| Variável | Para quê |
|---|---|
| `FORGE_DB_URL` | espelho do banco de CVEs (`http://forge-db.forge.svc:8080/databases`) |
| `FORGE_CACHE_DIR` | cache de camadas/base/banco — monte um volume persistente aqui |
| `AWS_REGION`, `FORGE_ECR_ACCOUNT` | ECR (credencial vem de Pod Identity/IRSA/OIDC/env) |
| `GITHUB_TOKEN` ou `GHCR_TOKEN` | GHCR |
| `FORGE_TAG` | tag padrão (senão usa o SHA do commit do CI) |

## GitLab CI (executor Kubernetes)

```yaml
build-image:
  image:
    name: ghcr.io/chwiee/forge:latest
    entrypoint: [""]
  variables:
    FORGE_DB_URL: http://forge-db.forge.svc.cluster.local:8080/databases
    FORGE_CACHE_DIR: /cache
    AWS_REGION: us-east-2
  script:
    - forge run . --registry ecr --name $CI_PROJECT_PATH_SLUG --tag $CI_COMMIT_SHORT_SHA --tag $CI_COMMIT_REF_SLUG
  artifacts:
    when: always
    paths: [.forge/report.json]
```

No `config.toml` do runner, o pod do job precisa de:

```toml
[runners.kubernetes.pod_security_context]
  run_as_user = 0
[runners.kubernetes.build_container_security_context]
  allow_privilege_escalation = true
  # seccomp Unconfined: padrão do Kubernetes; só configure se o cluster usa RuntimeDefault
```

## Azure DevOps (agente em container / Kubernetes)

```yaml
pool: k8s-agents
container: ghcr.io/chwiee/forge:latest
steps:
  - script: forge run . --registry ecr --name $(Build.Repository.Name) --tag $(Build.BuildId)
    env:
      FORGE_DB_URL: http://forge-db.forge.svc.cluster.local:8080/databases
      AWS_REGION: us-east-2
  - publish: .forge/report.json
    artifact: forge-report
    condition: always()
```

As cores ANSI aparecem no log do Azure DevOps (o forge detecta `TF_BUILD`).

## GitHub Actions em pods (ARC) + Karpenter — multi-arch nativo, sem QEMU

Modelo recomendado. Cada arquitetura compila no seu próprio nó, **sem emulação**, e
cada pod publica sozinho. Não há job de "junção".

```
 workflow (matrix arch)
   ├─ runs-on: arc-amd64 ─► Karpenter sobe nó x86      ─► forge run --multiarch ... ─┐
   └─ runs-on: arc-arm64 ─► Karpenter sobe nó Graviton ─► forge run --multiarch ... ─┤
                                                                                    ▼
            cada pod: build nativo → gates → push <tag>-<arch> → se todas as arquiteturas
            deste run existem no registry, grava o índice multi-arch em <tag>
```

| Peça | Arquivo |
|---|---|
| NodePool do Karpenter (amd64 + arm64, spot, taint `ci`) | [`deploy/karpenter/nodepool-ci.yaml`](../deploy/karpenter/nodepool-ci.yaml) |
| Runner scale set por arquitetura (`hostUsers: false`) | [`deploy/arc/values-arm64.yaml`](../deploy/arc/values-arm64.yaml) (copie para amd64) |
| Imagem do runner com o forge | [`deploy/arc/Dockerfile.runner`](../deploy/arc/Dockerfile.runner) |

Workflow:

```yaml
name: image
on: {push: {branches: [main]}}
permissions: {id-token: write, contents: read}
jobs:
  image:
    strategy:
      fail-fast: false           # one arch failing must not hide the other's report
      matrix: {arch: [amd64, arm64]}
    runs-on: arc-${{ matrix.arch }}
    steps:
      - uses: actions/checkout@v4
      - name: forge
        run: >
          forge run .
          --registry ecr --name ${{ github.event.repository.name }} --create-repo
          --tag ${{ github.sha }} --tag latest
          --multiarch linux/amd64,linux/arm64
          --report forge-${{ matrix.arch }}.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: {name: forge-${{ matrix.arch }}, path: forge-${{ matrix.arch }}.json}
```

Como a junção é segura sem um job extra nem trava no registry:

- cada pod **publica antes de verificar**; quem verifica por último sempre enxerga as duas arquiteturas;
- se os dois enxergarem ao mesmo tempo, os dois gravam **o mesmo índice byte a byte** (ordem fixa) — mesmo digest;
- as imagens por arquitetura levam os labels `dev.forge.build-id` (`GITHUB_RUN_ID-GITHUB_RUN_ATTEMPT`) e
  `dev.forge.gates=passed`: nunca se junta com um `<tag>-arm64` de outro run nem com imagem reprovada;
- se uma arquitetura reprova nos gates, ela não publica e a tag `<tag>` **não é criada** — nada parcial em produção.

Testado: 30 rodadas de publicação simultânea num registry em memória (`internal/cli/multiarch_test.go`)
— a tag final sempre com as duas arquiteturas.

Credenciais: o service account do runner com **EKS Pod Identity/IRSA** (permissões de push no ECR) —
nenhum segredo no workflow. Para GHCR, `GITHUB_TOKEN` com `packages: write`.

### Por que `hostUsers: false` (e não `privileged`)

O pod roda como root **dentro** de um user namespace do Kubernetes; no nó ele é um uid sem privilégio
(testado no k3s v1.36: `0 → 2544631808`). O forge cria seu namespace aninhado para os RUN
(`forge doctor` mostra `isolation: user namespace`). Sem `privileged`, sem capabilities extras.
Requer Kubernetes 1.33+ e containerd 2.x (EKS 1.33+ atende).

### Emulação QEMU

Desligada por padrão. `--emulate` só para dev local (precisa de root real e registra um handler
global no kernel do nó). Em CI, use runners nativos como acima.

## Local (WSL 2) — sem sudo

Use uma distro Linux (Ubuntu), **não** a `docker-desktop`, e trabalhe no filesystem do WSL
(`~/projetos/...`), não em `/mnt/c` (lento e sem dono/permissão Linux).

Uma vez só (pacote de ~100 KB com os helpers `newuidmap`/`newgidmap`):

```bash
sudo apt install uidmap
```

Depois, tudo sem `sudo`:

```bash
forge doctor              # deve mostrar: user rootless (uids 100000-165535), isolation full
forge run . --no-push
forge run . --registry ecr --name app --region us-east-2 --create-repo
```

O forge se re-executa num user namespace com a sua faixa do `/etc/subuid` (o Ubuntu reserva 65.536
uids ao criar o usuário): `adduser`, `chown` e `apt` funcionam, e os donos dos arquivos são gravados
corretamente na imagem. Sem o `uidmap`, ele cai num modo limitado (só o seu uid) e o `doctor` explica.

Credenciais AWS do Windows no WSL: `ln -s /mnt/c/Users/<você>/.aws ~/.aws`.

Emulação (dev): `sudo forge emulation install arm64` uma vez por sessão do WSL; depois
`forge run . --platform linux/arm64 --emulate` sem sudo.
