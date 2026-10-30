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

## GitHub Actions

```yaml
jobs:
  image:
    runs-on: ubuntu-latest
    permissions: {contents: read, packages: write}
    steps:
      - uses: actions/checkout@v4
      - name: forge   # (as releases ainda não foram publicadas)
        run: |
          curl -fsSL -o forge https://github.com/chwiee/forge/releases/latest/download/forge-linux-amd64
          chmod +x forge
          sudo -E ./forge run . --registry ghcr --name ${{ github.event.repository.name }} --tag ${{ github.sha }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`sudo` dá o modo de isolamento `full` no runner hospedado. Sem sudo funciona em modo `rootless`,
mas Dockerfiles com `adduser`/`chown` para outro usuário falham.

## Local (WSL 2)

Use uma distro Linux (Ubuntu), **não** a `docker-desktop`, e trabalhe no filesystem do WSL
(`~/projetos/...`), não em `/mnt/c` (lento e sem dono/permissão Linux).

```bash
sudo forge run . --no-push        # tudo menos o push
forge doctor                      # mostra o nível de isolamento disponível
```
