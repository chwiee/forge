# Uso do forge — etapas, validações e o que o usuário vê

Todas as saídas abaixo são **reais**, capturadas no WSL (Ubuntu 24.04, usuário comum, sem sudo)
com `forge v0.4.1-dev`. No terminal elas têm cores e spinner animado; no CI (GitHub Actions, GitLab,
Azure DevOps) saem exatamente assim, linha a linha, com cores ANSI.

## Formato

```
forge run [contexto] [flags]
```

| Objetivo | Comando |
|---|---|
| Tudo menos o push (validar o Dockerfile) | `forge run . --no-push` |
| Publicar no ECR (cria o repositório) | `forge run . --registry ecr --name team/app --region us-east-2 --create-repo --tag v1.0.0` |
| Publicar no GHCR | `forge run . --registry ghcr --name app --tag v1.0.0` (usa `GITHUB_TOKEN`) |
| Multi-arch num pod por arquitetura (CI) | `forge run . --registry ecr --name app --tag v1 --multiarch linux/amd64,linux/arm64` |
| Gate de CVE mais rígido | `... --fail-on high` (ou `--only-fixed=false` para contar até as sem correção) |
| Só build + slim, sem scan/push | `forge build . --oci out/` |
| Só scan de uma imagem existente | `forge scan <ref-ou-pasta-oci>` |
| O que esta máquina/pod suporta | `forge doctor` |

Ajuda completa: `forge run --help`.

## Como ler a saída

| Símbolo | Significado |
|---|---|
| `▸ Etapa` | etapa começou (no terminal vira um spinner com a linha atual do RUN) |
| `✔` | etapa ok |
| `✖` | etapa falhou (gate reprovado ou erro) |
| `▲` | aviso: não bloqueia |
| `○` | etapa pulada ou cancelada (com o motivo) |
| `✓ 3/9 RUN ...` | passo do Dockerfile executado (com o tempo, se > 0,2 s) |
| `↺ 3/9 RUN ... cached` | passo reaproveitado do cache |
| `· 7/9 ENV ...` | instrução só de metadado (não gera camada) |

As etapas rodam **em paralelo** quando não dependem umas das outras — por isso a ordem das linhas
`▸` varia entre execuções. O resumo no fim (caixa `forge`) é sempre o mesmo formato.

## As etapas

| Etapa | O que faz | O que valida | Bloqueia o push? | No JSON (`.forge/report.json`) |
|---|---|---|---|---|
| **Registry** | resolve o destino (`--registry`, `--name`, `--tag`), cria o repo ECR se `--create-repo` | credencial válida **e** permissão de push (pede token com escopo de push, sem enviar nada); repo ECR existe | erro técnico → cancela tudo na hora | `push.registry`, `push.refs` |
| **VulnDB** | carrega o banco de CVEs (espelho `FORGE_DB_URL` → público → cache local) | banco disponível e com menos de 7 dias | erro técnico se nenhuma fonte responder | `platforms[].cve.db` |
| **Context** | procura segredos nos arquivos do contexto de build (respeita `.forgeignore`) | Gitleaks (~200 regras) | só com `--leaks-fail-on-context` | `contextLeaks` |
| **Build** | executa o Dockerfile (multi-stage, ARG, heredoc, COPY/ADD) sem Docker | Dockerfile válido (parser oficial do BuildKit); cada RUN termina com código 0 | erro técnico (mostra as últimas 40 linhas do RUN) | `platforms[].build` |
| **Slim** | funde as camadas do Dockerfile e remove lixo de instalação | só aplica se a imagem ficar **menor**; senão mantém a original | nunca | `platforms[].slim` |
| **Scan** | SBOM (Syft) + CVEs (Grype) de todos os pacotes: SO, Go, Java, .NET, Node, Python… | **gate CVE**: nenhuma vulnerabilidade ≥ `--fail-on` (padrão `critical`) **com correção disponível** | **sim** | `platforms[].cve` |
| **Sec** | boas práticas: root, tag `latest`, segredo em ENV/ARG, `curl \| sh`, setuid, sudo, lint do BuildKit | **gate de nota**: score ≥ `--min-score` (padrão 50) | **sim** | `platforms[].sec` |
| **Leaks** | segredos nos arquivos que **vão para a imagem**, em ENV/LABEL e no histórico de build | **gate de segredo**: zero segredos na imagem | **sim** | `platforms[].leaks` |
| **Push** | publica a imagem (ou o índice multi-arch) em todas as tags | só roda se **todos** os gates passaram | — | `push` |
| **Join** (`--multiarch`) | publica `<tag>-<arch>`; o último runner grava `<tag>` com todas as arquiteturas | todas as arquiteturas do mesmo `build-id` publicadas e aprovadas | não cria `<tag>` parcial | `push.refs`, `digest` |

### Retorno (exit code)

| Código | Significado | No pipeline |
|---|---|---|
| `0` | tudo aprovado (e publicado, se não for `--no-push`) | job verde |
| `1` | algum gate reprovou — push bloqueado | job vermelho: corrigir a imagem |
| `2` | erro técnico (credencial, rede, Dockerfile, RUN falhou) — a mensagem diz a etapa | job vermelho: corrigir o ambiente/Dockerfile |

## A. Aprovado (`examples/alpine-basic`)

```
$ forge run . --no-push

  ▲ forge v0.4.1-dev  ·  build · slim · scan · sec · leaks · push

  context   /home/forgetest/forge-examples/alpine-basic

  ▸ Context
  ▸ Build
  ▸ VulnDB
  ✔ Context no secrets · 1 files 18ms
  ✔ VulnDB  ready · built 2026-11-25 06:22 996ms
    ↺ 1/9     RUN apk add curl  cached
    ↺ 2/9     RUN echo "temp build data" > /tmp/build.log && mkdir -p /app/data  cached
    ↺ 3/9     WORKDIR /app  cached
    ↺ 4/9     COPY . .  cached
    ↺ 5/9     RUN adduser -D -u 10001 app && chown -R app /app  cached
    · 6/9     USER app
    · 7/9     ENV APP_ENV=production
    · 8/9     EXPOSE 8080
    · 9/9     CMD ["sh", "-c", "echo hello from forge && cat /app/hello.txt"]
  ✔ Build   9 steps · 5 cached · 5 layers · 8.6 MB 1.6s
  ▸ Slim
  ✔ Slim    8.6 MB → 6.3 MB  (−26.9%) · 5 → 2 layers · cached 0ms
  ▸ Leaks
  ▸ Scan
  ▸ Sec
  ✔ Sec     score 96/100 (A) · 2 findings 21ms
  ✔ Leaks   no secrets · 13 files checked 45ms
  ✔ Scan    12 critical · 38 high · 21 medium · 1 low · 2 fixable · 24 packages 1.2s

  ▸ Push
  ○ Push    skipped (--no-push) 0ms

  Critical & high vulnerabilities
    SEVERITY  ID                     PACKAGE      VERSION    FIXED IN
    Critical  CVE-2026-10536         curl         8.14.1-r2  —
    Critical  CVE-2026-111497 (KEV)  brotli-libs  1.1.0-r2   —
    ...
    … 38 more in the JSON report

  Hardening
    ● SEC003 base image not pinned by digest: alpine:3.20 (line 1)  −2
        ↳ pin with @sha256:<digest> for reproducible, tamper-proof builds
    · SEC008 no HEALTHCHECK  −2
        ↳ add HEALTHCHECK (or rely on Kubernetes liveness/readiness probes)

  ╭─ forge ─────────────────────────────────────────────────────────────────────╮
  │  digest    sha256:c5c630ecc835…                                             │
  │  base      index.docker.io/library/alpine@sha256:c64c687cbea9…              │
  │  size      8.6 MB → 6.3 MB  −26.9%                                          │
  │  layers    5 → 2                                                            │
  │  cves      12 critical · 38 high · 21 medium · 1 low                        │
  │  score     96/100 (A)                                                       │
  │  secrets   none in the image                                                │
  │  gates     cve ✔ 0 ≥ critical with fix · sec ✔ 96 ≥ 50 · leaks ✔ 0 in image │
  │  report    .forge/report.json                                               │
  │  result    ✔ passed  in 2.8s                                                │
  ╰─────────────────────────────────────────────────────────────────────────────╯
```

Por que **passou com 12 críticas**: a linha `gates` mostra que **0** delas tem correção publicada
(`FIXED IN —`). O gate padrão bloqueia o que o time **consegue** corrigir agora; as demais aparecem
na tabela e no JSON. `--only-fixed=false` faz contar todas. `(KEV)` = explorada ativamente (lista da CISA).

## B. Reprovado (`examples/go-multistage`: CVE corrigível + token no arquivo)

```
$ forge run . --no-push

  ▲ forge v0.4.1-dev  ·  build · slim · scan · sec · leaks · push

  context   /home/forgetest/forge-examples/go-multistage

  ▸ Build
  ▸ VulnDB
  ▸ Context
  ▲ Context 1 secret(s) in the build context — Leaks checks what ships in the image 20ms
  ✔ VulnDB  ready · built 2026-11-25 06:22 1.0s
    ↺ 1/8     WORKDIR /src  cached
    ↺ 2/8     COPY go.mod main.go ./  cached
    ↺ 3/8     RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/app .  cached
    ↺ 4/8     RUN apt-get update && apt-get install -y ca-certificates  cached
    ↺ 5/8     COPY --from=build /out/app /usr/local/bin/app  cached
    ↺ 6/8     COPY config.yaml /etc/app/config.yaml  cached
    · 7/8     USER 65532:65532
    · 8/8     ENTRYPOINT ["/usr/local/bin/app"]
  ✔ Build   8 steps · 6 cached · 4 layers · 47.9 MB 8.3s
  ▸ Slim
  ✔ Slim    47.9 MB → 32.6 MB  (−32.0%) · 4 → 2 layers · cached 0ms
  ▸ Leaks
  ▸ Scan
  ▸ Sec
  ✔ Sec     score 94/100 (A) · 3 findings 36ms
  ✖ Leaks   1 secret(s) in the image · 0 in context 71ms
  ✖ Scan    4 critical · 84 high · 116 medium · 19 low · 44 fixable · 92 packages 1.6s

  ▸ Push
  ○ Push    skipped (--no-push) 0ms

  Secrets
    ● context  github-pat  config.yaml:4  ghp_********
    accept a false positive: add its fingerprint (file:rule:line) to .gitleaksignore

  Critical & high vulnerabilities
    SEVERITY  ID              PACKAGE   VERSION          FIXED IN
    Critical  CVE-2026-56857  stdlib    go1.24.13        1.26.9, 1.27.2
    Critical  CVE-2026-78663  stdlib    go1.24.13        1.26.9
    Critical  CVE-2026-5450   libc-bin  2.36-9+deb12u14  —
    Critical  CVE-2026-5450   libc6     2.36-9+deb12u14  —
    High      CVE-2026-25679  stdlib    go1.24.13        1.25.8, 1.26.1
    ...
    … 76 more in the JSON report

  Hardening
    ● SEC003 base image not pinned by digest: debian:bookworm-slim (line 9)  −2
        ↳ pin with @sha256:<digest> for reproducible, tamper-proof builds
    ● SEC012 apt-get install without --no-install-recommends (line 10)  −2
        ↳ add --no-install-recommends (smaller image, fewer CVEs)
    · SEC008 no HEALTHCHECK  −2
        ↳ add HEALTHCHECK (or rely on Kubernetes liveness/readiness probes)

  Secrets
    ● image    github-pat  /etc/app/config.yaml:4  ghp_********
    accept a false positive: add its fingerprint (file:rule:line) to .gitleaksignore

  ╭─ forge ───────────────────────────────────────────────────────────────────────╮
  │  digest    sha256:df2feedaf378…                                               │
  │  base      index.docker.io/library/debian@sha256:311f7a192fd9…                │
  │  size      47.9 MB → 32.6 MB  −32.0%                                          │
  │  layers    4 → 2                                                              │
  │  cves      4 critical · 84 high · 116 medium · 19 low                         │
  │  score     94/100 (A)                                                         │
  │  secrets   1 in the image                                                     │
  │  gates     cve ✖ 2 ≥ critical with fix · sec ✔ 94 ≥ 50 · leaks ✖ 1 in image   │
  │  report    .forge/report.json                                                 │
  │  result    ✖ blocked — 2 check(s) failed  in 9.9s                             │
  │            ↳ cve: 2 vulnerabilities at or above critical with a fix available │
  │            ↳ leaks: 1 secret(s) shipped in the image                          │
  ╰───────────────────────────────────────────────────────────────────────────────╯
exit 1
```

O que o usuário faz com isso:
- **cve**: a coluna `FIXED IN` diz a versão — aqui, compilar com Go ≥ 1.26.9 resolve as duas críticas.
- **leaks**: o segredo mostra arquivo e linha (`/etc/app/config.yaml:4`), nunca o valor (`ghp_********`).
  Falso positivo? Adicionar o fingerprint `arquivo:regra:linha` no `.gitleaksignore`.
- **sec** passou, mas cada achado traz a correção (`↳`).

## C. Erro técnico (sessão AWS expirada)

```
$ AWS_PROFILE=lab forge run . --registry ecr --name forge-demo --region us-east-2

  ▲ forge v0.4.1-dev  ·  build · slim · scan · sec · leaks · push

  context   /home/forgetest/forge-examples/alpine-basic

  ▸ Build
  ▸ VulnDB
  ▸ Context
  ▸ Registry
  ✔ Context  no secrets · 1 files 22ms
  ✖ Registry not ready 483ms
  ○ Build    cancelled (registry failed) 484ms
  ✔ VulnDB   ready · built 2026-11-25 06:22 1.1s
  ✖ registry: ecr: cannot discover AWS account: AWS session expired (profile lab) — run `aws login --profile lab` and retry
exit 2
```

A checagem do registry roda **junto** com o build: credencial errada derruba tudo em meio segundo,
em vez de descobrir só depois do build inteiro. A última linha sempre diz a etapa e o que fazer.

## D. `forge doctor`

```
$ forge doctor

  ▲ forge v0.4.1-dev  ·  doctor

  ✔ user        rootless: user namespace with your subordinate ids (uids 100000-165535)
  ✔ isolation   full (namespaces + /proc + chroot)
  ✔ cache       /home/forgetest/.cache/forge
  ▲ db mirror   FORGE_DB_URL not set: DB comes from grype.anchore.io
  ▲ ghcr        no GHCR_TOKEN/GITHUB_TOKEN (docker config.json is used if present)
  ✔ ecr         ~/.aws/config found (set AWS_PROFILE to pick a profile)
```

## Relatório JSON

Sempre gravado (`--report`, padrão `.forge/report.json`), aprovado ou não — para o CI publicar como
artefato e para dashboards. Estrutura (trecho real):

```json
{
  "forgeVersion": "v0.4.1-dev",
  "duration": "2.753s",
  "dockerfile": "/home/forgetest/forge-examples/alpine-basic/Dockerfile",
  "platforms": [
    {
      "platform": "linux/amd64",
      "image": { "digest": "sha256:c5c630ec…", "base": "index.docker.io/library/alpine@sha256:c64c687c…",
                 "compressedSize": 6319493, "layers": 2 },
      "build": { "steps": 9, "cached": 5, "duration": "1.552s" },
      "slim":  { "applied": true, "sizeBefore": 8646485, "sizeAfter": 6319493, "layersBefore": 5, "layersAfter": 2 },
      "cve":   { "vulnerabilities": [ { "id": "CVE-2026-111497", "severity": "Critical", "package": "brotli-libs",
                                        "version": "1.1.0-r2", "type": "apk", "knownExploited": true } ],
                 "counts": { "...": 0 }, "fixable": { "...": 0 }, "db": { "built": "...", "source": "..." }, "failed": false },
      "sec":   { "score": 96, "grade": "A", "findings": [ { "id": "SEC003", "severity": "low", "fix": "..." } ] },
      "leaks": { "findings": [], "blocking": 0, "filesScanned": 13, "failed": false }
    }
  ],
  "contextLeaks": { "findings": [], "filesScanned": 1 },
  "gates": { "cveFailOn": "critical", "cveOnlyFixed": true, "minScore": 50 },
  "push": { "registry": "ecr", "refs": ["…/forge-demo:demo-1"], "digest": "sha256:…" },
  "passed": true,
  "failures": []
}
```

`--sbom sbom.cdx.json` grava também o SBOM completo (CycloneDX) — um arquivo por arquitetura no
multi-arch.
