# Arquitetura do forge

```
Dockerfile ─► parser BuildKit (lib) ─► builder ──► slim ──► scan ─┐
                                          │                 sec  ├─► gates ─► push (ECR/GHCR)
                     cache de passos ◄────┤                 leaks┘
                     sandbox (RUN) ◄──────┘
```

| Pacote | Responsabilidade |
|---|---|
| `internal/dockerfile` | Parser e lint **oficiais** do BuildKit usados como biblioteca (sem daemon). |
| `internal/builder` | Executa os stages; pull da base com go-containerregistry; COPY/ADD/RUN/WORKDIR viram camadas. |
| `internal/sandbox` | Executa cada RUN: o forge se re-executa (`forge __sandbox`) em namespaces Linux, monta `/proc` e `/dev`, faz chroot. |
| `internal/rootfs` | Extrai camadas (com whiteouts OCI), tira "retratos" do filesystem e gera a camada pelo diff. |
| `internal/cache` | Camadas por digest + índice `chave do passo → camada`. |
| `internal/ignore` | `.forgeignore` (ou `.dockerignore`), mesma sintaxe do Docker. |
| `internal/slim` | Squash das camadas do Dockerfile + remoção de lixo do build. |
| `internal/scan` | Syft (SBOM) + Grype (CVEs) como bibliotecas; banco com cache e espelho. |
| `internal/sec` | Checagens de hardening → nota 0-100 com a correção de cada achado. |
| `internal/leaks` | Gitleaks como biblioteca: arquivos da imagem, config/histórico e contexto. |
| `internal/emulation` | QEMU estático (imagem fixada por digest) registrado no `binfmt_misc` para RUN de outra arquitetura. |
| `internal/registry` | ECR (token via AWS SDK) e GHCR (`GITHUB_TOKEN`); push com progresso. |
| `internal/dbmirror` | `forge db serve`: espelho do banco do Grype para o cluster. |
| `internal/ui` | Spinner no terminal; linhas estáticas coloridas no CI. |

## Como um passo vira camada

1. Antes do passo: retrato do rootfs (`path → modo, tamanho, mtime, ctime, uid, gid, inode`).
2. Executa (RUN no sandbox, COPY/ADD direto no diretório).
3. Retrato de novo; o diff dá os arquivos novos/alterados e os apagados (viram *whiteouts*).
4. O diff vira um tar → gzip → cache (`blobs/sha256.tar.gz`).

O **ctime** é a peça-chave: o kernel atualiza em qualquer alteração e ninguém consegue forjá-lo,
então `cp -p`/`touch -r` (que preservam o mtime) não escapam do diff.

`/proc`, `/sys`, `/dev`, `/etc/resolv.conf`, `/etc/hosts` e `/etc/hostname` nunca entram em camadas
(o sandbox injeta o DNS do host durante o RUN e restaura o original depois).

## Cache

Chave de cada passo = `sha256(chave do passo anterior + instrução expandida + entradas)`.

| Passo | Entradas da chave |
|---|---|
| `FROM imagem` | digest da imagem resolvida para a plataforma |
| `RUN` | comando, ENV + ARGs, USER, WORKDIR, SHELL |
| `COPY`/`ADD` locais | hash do **conteúdo** dos arquivos (respeitando o ignore) |
| `COPY --from=stage` | chave final do stage de origem |
| `ADD <url>` | URL + `--checksum` (o conteúdo remoto não é revalidado) |

O rootfs só é extraído quando algum passo **erra** o cache. Build 100% em cache não extrai nada
(build do exemplo alpine: 1,9 s).

O cache vive em `--cache-dir` (padrão `~/.cache/forge`; `FORGE_CACHE_DIR`):

```
layers/   camadas dos passos + índice de chaves (forge cache prune)
images/   camadas das imagens base (evita baixar de novo)
grype-db/ banco de vulnerabilidades
work/     rootfs temporário de cada build (apagado no fim)
```

## Isolamento do RUN (detectado sozinho)

| Nível | Quando | O que tem |
|---|---|---|
| `full` | root com CAP_SYS_ADMIN (WSL com sudo, pod privilegiado) | namespaces mount/pid/uts/ipc, `/proc`, `/dev`, chroot |
| `userns` | root sem CAP_SYS_ADMIN (**pod comum**) | user namespace com mapeamento 0→0 (todos os uids reais) + o mesmo acima |
| `rootless` | usuário comum (WSL sem sudo) | user namespace mapeando só o seu uid para root |
| `chroot` | root, mas seccomp/AppArmor bloqueiam namespaces | só chroot, **sem `/proc`** (Go/Java/.NET falham) |

Rede: compartilhada com o host (como `docker build` padrão) — proxy e DNS do runner funcionam.

Testado (Docker Desktop simulando pods):

| Cenário | Nível | Resultado |
|---|---|---|
| `--privileged` | full | alpine + go multi-stage ok |
| root, caps padrão, seccomp Unconfined (padrão do K8s) | userns | `go build` + `apt-get` ok |
| root, seccomp padrão do Docker | chroot | `go build` falha (sem `/proc`) — dica impressa |
| uid 1000 | rootless | `apk add` ok; `adduser -u 10001`/`chown` falham — dica impressa |

## Slim

1. **Squash `app`** (padrão): funde as camadas criadas pelo Dockerfile numa só. Arquivo criado num RUN e
   apagado noutro deixa de ocupar espaço. As camadas da base ficam intactas (compartilhadas no registry).
   `--squash all` gera uma camada única (maior ganho, perde o compartilhamento).
2. **Limpeza** só do que o build criou (nunca arquivos da base):
   - `safe` (padrão): cache apt/apk/dnf, `/tmp`, logs de instalação, `~/.cache`, `~/.npm/_cacache`, histórico de shell;
   - `aggressive`: + docs/man, `__pycache__`/`.pyc`, `~/.m2`, `~/.gradle/caches`, `~/.nuget/packages`, `go/pkg/mod`.
3. Se o resultado não for menor, entrega a original. O resultado do slim também é cacheado.

## Gates e push

| Gate | Padrão | Flag |
|---|---|---|
| CVE | reprova com **crítica que tem correção** | `--fail-on`, `--only-fixed`, `--ignore-cve` |
| Hardening | nota mínima 50 | `--min-score` |
| Segredos | reprova segredo **na imagem** (arquivo, ENV, LABEL, histórico); contexto só avisa | `--leaks-fail-on-context`, `.gitleaksignore` |

Todas as etapas rodam mesmo se uma reprovar (relatório completo); o push só acontece com tudo aprovado.
O destino é resolvido **antes** do build (credencial errada falha em segundos).

## Multi-arch

- Cada stage tem sua plataforma: `FROM --platform=...` (expandido com `BUILDPLATFORM`/`TARGETPLATFORM`) ou a plataforma alvo.
- `TARGET*` = plataforma alvo; `BUILD*` = esta máquina. A chave de cache do `FROM` é o digest da imagem daquela plataforma.
- RUN de stage com arquitetura estrangeira chama `emulation.Ensure` **só quando erra o cache** (build 100% em cache não precisa de emulação).
- Emulação: QEMU estático de `tonistiigi/binfmt:qemu-v10.2.3:400a4873…` (fixado por digest), registrado como `forge-qemu-<arch>` com flags `CFP` (`F` = o kernel abre o interpretador no registro, funciona dentro do chroot; `P` = preserva argv[0], sem isso o BusyBox quebra com `applet not found`). Handlers de outras ferramentas (Docker Desktop, binfmt) são reaproveitados.
- Em pod, registrar binfmt exige `privileged`: prefira **um runner nativo por arquitetura + `forge manifest`**.
- O OCI salvo por `forge run --oci` leva `dev.forge.gates=passed|failed`; `forge build` grava `unscanned`. `forge manifest` recusa `failed` e escaneia `unscanned` antes de publicar.
- Índice: Docker manifest list se todas as imagens forem Docker schema 2, senão OCI image index.

## Concorrência

- `forge run` usa `errgroup`: o primeiro erro técnico cancela o `context` de todas as tarefas (RUN em andamento recebe SIGKILL via `exec.CommandContext`). A causa é a primeira erro devolvido, com prefixo da etapa; tarefas canceladas não imprimem erro, só `cancelled (<etapa> failed)`.
- Builds usam um contexto filho (`context.WithCancelCause`): gate reprovado cancela só os builds pendentes, sem interromper scans em curso.
- Cache de passos: `cache.Open` devolve um `Store` único por diretório com **lock por chave** — dois builds que chegam ao mesmo passo (stage `$BUILDPLATFORM`) executam uma vez só; o segundo pega do cache.
- Cache de imagens base (`cache.BlobCache`): grava em temporário, confere o digest e renomeia (o fs cache do go-containerregistry grava no lugar e pode servir blob truncado). Índices por digest e por diffID.
- Banco do Grype carregado uma vez (tarefa VulnDB); scans são serializados por mutex (Syft/Grype não garantem uso concorrente; o scan com o banco carregado leva 1-4 s). Scan, Sec e Leaks de uma imagem rodam em paralelo entre si.
- Preflight do registry: ECR `DescribeRepositories` + `remote.CheckPushPermission` (pede token com escopo de push, não envia nada).
- Deliberadamente **não** fazemos upload antecipado das camadas: uma camada com segredo poderia chegar ao registry (sem tag, mas baixável por digest) antes do gate de Leaks.
- UI: região viva com uma linha por etapa ativa; no CI e com várias plataformas, sub-linhas prefixadas com a etapa.

## Rootless (WSL sem sudo) e pods com `hostUsers: false`

- **WSL/usuário comum** (`internal/userns`): o forge se re-executa num user namespace; o pai chama `newuidmap`/`newgidmap` (pacote `uidmap`) mapeando `0 → você` e `1..65536 → sua faixa do /etc/subuid`. O filho espera o mapeamento e se re-executa de novo — o kernel só concede as capabilities do namespace num `execve` feito já como uid 0. Lá dentro o forge é "root" com todos os uids reais: extração mantém donos, `adduser`/`chown`/`apt` funcionam, a camada grava os uids certos. Testado: `adduser -u 10001` + `chown` → `10001` gravado na imagem.
- **Pod `hostUsers: false`**: o pod só enxerga 65.536 uids. O nível `userns` espelha `/proc/self/uid_map` (antes pedia 2^31 e falharia). Testado no k3s v1.36 com a imagem distroless: `doctor` = `user namespace`, `adduser`, `apt-get` e `go build` ok; uid 0 do pod = uid 2544631808 no nó.
- Emulação QEMU é **opt-in** (`--emulate`): em namespace rootless o registro no `binfmt_misc` exige root real (`sudo forge emulation install <arch>` uma vez).

## Multi-arch distribuído (`--multiarch`)

- Cada runner constrói só a sua arquitetura (nativa), roda os gates, grava os labels `dev.forge.build-id` e `dev.forge.gates=passed` e publica `<tag>-<arch>`.
- Depois confere `<tag>-<arch>` de todas as plataformas esperadas; se todas têm o mesmo build-id e gates aprovados, grava o índice (ordem fixa por plataforma → mesmo digest em qualquer runner) em todas as tags.
- Correção sem trava: cada runner publica **antes** de verificar, então o último a verificar sempre vê todos; escritas simultâneas são idênticas. Coberto por `internal/cli/multiarch_test.go` (30 rodadas concorrentes + rejeição de build-id antigo).
- Build-id padrão: `GITHUB_RUN_ID-GITHUB_RUN_ATTEMPT`, `gl-CI_PIPELINE_ID`, `ado-BUILD_BUILDID` (ou `--build-id`).

## Limitações conhecidas (v0.4)

- `RUN --mount` (cache/secret/bind) é ignorado com aviso.
- `ONBUILD` é ignorado.
- `ADD` de repositório git não é suportado.
- Modo `rootless` não muda para outros uids (sem `newuidmap`).
