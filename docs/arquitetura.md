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

## Limitações conhecidas (v0.1)

- Build só da arquitetura do host (RUN executa binários nativos). Multi-arch = um runner por arquitetura.
- `RUN --mount` (cache/secret/bind) é ignorado com aviso.
- `ONBUILD` é ignorado.
- `ADD` de repositório git não é suportado.
- Modo `rootless` não muda para outros uids (sem `newuidmap`).
