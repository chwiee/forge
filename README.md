# forge

Construtor de imagens de container completo, num binário só, **sem Docker, Podman ou BuildKit instalados**.

```
forge run . --registry ecr --name payments-api
```

| Etapa | O que faz | Como |
|---|---|---|
| **Build** | Lê o Dockerfile (multi-stage, ARG, heredoc, `.forgeignore`) e constrói a imagem | motor próprio em Go: parser oficial do BuildKit + sandbox com namespaces Linux |
| **Slim** | Reduz tamanho e número de camadas sem mudar o comportamento | squash das camadas do Dockerfile + remoção de lixo do build |
| **Scan** | CVEs de todos os pacotes (SO, Go, Java, .NET, Node, Python…) | Syft + Grype como bibliotecas, banco com cache/espelho |
| **Sec** | Boas práticas de hardening → nota 0-100 com a correção | regras próprias + lint oficial do BuildKit |
| **Leaks** | Segredos na imagem, na config/histórico e no contexto | Gitleaks como biblioteca |
| **Push** | ECR ou GHCR, só se todos os gates passarem | go-containerregistry + AWS SDK |

Roda local no **WSL 2** ou em **pods/runners** (GitLab, Azure DevOps, GitHub Actions, Jenkins) — num pod comum, sem `privileged`.

## Exemplo de saída

```
  ▲ forge v0.1.0  ·  build · slim · scan · sec · leaks · push

  context   /work/go-multistage
  target    ghcr.io/chwiee/forge-demo:dev

  ▸ Build
    ↺ 1/8     WORKDIR /src  cached
    ↺ 2/8     COPY go.mod main.go ./  cached
    ✓ 3/8     RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/app .  13.9s
    ✓ 4/8     RUN apt-get update && apt-get install -y ca-certificates  8.2s
    ✓ 5/8     COPY --from=build /out/app /usr/local/bin/app
    ✓ 6/8     COPY config.yaml /etc/app/config.yaml
    · 7/8     USER 65532:65532
    · 8/8     ENTRYPOINT ["/usr/local/bin/app"]
  ✔ Build   8 steps · 2 cached · 4 layers · 47.9 MB 25.1s
  ✔ Slim    47.9 MB → 32.6 MB  (−32.0%) · 4 → 2 layers 3.0s
    ✓ removed 19.8 MB of apt cache
  ✖ Scan    4 critical · 96 high · 85 medium · 14 low · 43 fixable · 92 packages 6.8s
  ✔ Sec     score 94/100 (A) · 3 findings 46ms
  ✖ Leaks   1 secret(s) in the image · 1 in context 86ms
  ✖ Push    blocked by security gates
```

No terminal, cada etapa tem spinner animado e a linha atual do RUN aparece ao lado; no CI a saída
vira linhas estáticas coloridas (sem `\r`, legível no log do Azure DevOps/GitLab).

## Comandos

| Comando | Para quê |
|---|---|
| `forge run [ctx]` | pipeline inteiro (o que o CI usa) |
| `forge build [ctx]` | build + slim; salva OCI (`--oci`) e/ou tar (`--tar`, para `docker load`/`kind load`) |
| `forge scan <oci-dir\|ref>` | só CVEs, de uma imagem local ou de registry |
| `forge push <oci-dir\|ref>...` (alias `manifest`) | publica uma imagem, ou junta várias (uma por arquitetura) numa tag multi-arch |
| `forge emulation status\|install\|uninstall` | emulação QEMU para RUN de outra arquitetura |
| `forge db serve\|sync\|update` | espelho do banco de CVEs / aquecer cache |
| `forge cache ls\|prune` | uso e limpeza do cache |
| `forge doctor` | diz o que esta máquina/pod suporta |

Flags principais do `run`:

```
--registry ecr|ghcr      --name <repo>          -t/--tag <tag> (repetível)
-f/--file Dockerfile     --target <stage>       --build-arg K=V
--slim off|safe|aggressive                      --squash app|all|off
--fail-on critical|high|medium|low|none         --only-fixed (padrão true)
--min-score 50           --ignore-cve CVE-...   --sbom sbom.cdx.json
--no-push                --no-cache             --report .forge/report.json
--create-repo (ECR)      --ecr-account/--region --owner (GHCR)
```

## Multi-arch (amd64 + arm64 numa tag só)

```bash
sudo forge run . --registry ecr --name api --platform linux/amd64,linux/arm64
```

O forge constrói uma imagem por plataforma (build, slim, scan, sec e leaks **para cada uma**) e publica
**uma tag** (manifest list / OCI index): `docker pull` e o kubelet escolhem a arquitetura sozinhos.

| Peça | Como funciona |
|---|---|
| Dockerfile multi-arch padrão | `FROM --platform=$BUILDPLATFORM` + `ARG TARGETOS TARGETARCH`: o stage de compilação roda **nativo** e faz cross-compile; o cache é compartilhado entre as plataformas. Exemplo: [`examples/multiarch`](examples/multiarch/Dockerfile). |
| RUN de outra arquitetura | o forge baixa o QEMU estático de uma imagem fixada por digest (`tonistiigi/binfmt`, a mesma fonte do buildx) e registra no `binfmt_misc` do kernel — sem daemon, sem pacote. Precisa de root; vale até o reboot (no WSL, até a distro reiniciar — o forge re-registra sozinho quando um RUN precisa). |
| Runners nativos (mais rápido) | cada runner (x86, Graviton) roda `forge run . --no-push --oci out/<arch>`; um job final junta: `forge manifest out/amd64 out/arm64 --registry ecr --name api`. Imagens que reprovaram nos gates são recusadas. |

Testado no WSL: imagem arm64 construída num x86, binário aarch64 executado de dentro do rootfs dela.

## Destinos

| `--registry` | Referência gerada | Credencial |
|---|---|---|
| `ecr` | `<conta>.dkr.ecr.<região>.amazonaws.com/<name>:<tag>` | AWS SDK: Pod Identity, IRSA, OIDC do CI, `aws login`, env |
| `ghcr` | `ghcr.io/<owner>/<name>:<tag>` | `GHCR_TOKEN` ou `GITHUB_TOKEN` (+ `GITHUB_ACTOR`) |

Sem `--tag`, usa o SHA do commit do CI (`CI_COMMIT_SHORT_SHA`, `GITHUB_SHA`, `BUILD_SOURCEVERSION`) ou `latest`.
Refs como `refs/tags/v1.2` viram `v1.2`.

## Banco de CVEs no cluster

Um Deployment com `forge db serve` baixa o banco do Grype ao subir e a cada 24 h, e serve por HTTP.
Os runners usam `FORGE_DB_URL=http://forge-db.forge.svc.cluster.local:8080/databases`.
Se o espelho cair, o forge usa o endereço público e, por último, o banco já em cache — o build não para.
Manifests: [`deploy/k8s/forge-db.yaml`](deploy/k8s/forge-db.yaml).

## Requisitos

- Linux (WSL 2 com Ubuntu, container ou pod). Nada mais.
- Para os RUN: root **ou** user namespaces habilitados. Num pod: `runAsUser: 0` + seccomp `Unconfined`
  (padrão do Kubernetes) — **sem `privileged` e sem capabilities extras**. Veja [`deploy/k8s/runner-pod.yaml`](deploy/k8s/runner-pod.yaml).
- No WSL use `sudo forge` e trabalhe fora de `/mnt/c`.

## Compilar

```bash
make build      # bin/forge (Linux, estático, ~90 MB)
make test
```

## Documentação

- [Arquitetura, cache, isolamento, slim e gates](docs/arquitetura.md)
- [Uso no CI: GitLab, Azure DevOps, GitHub Actions, WSL](docs/ci.md)
- [Exemplos](examples/) — `alpine-basic` (passa) e `go-multistage` (reprova de propósito: CVE + segredo)
