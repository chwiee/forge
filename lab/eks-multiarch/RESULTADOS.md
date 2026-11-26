# Resultado do lab: build multi-arch distribuído no EKS (26/11/2026)

**Veredito: PASSOU.** O forge compilou a mesma aplicação ao mesmo tempo em dois node groups
(amd64 e arm64), bloqueou as duas imagens com CVE crítica e, na aprovada, publicou **uma tag só**
que funciona nas duas arquiteturas sem o usuário escolher nada.

O ambiente foi destruído no mesmo dia: stack CloudFormation, repositórios ECR `forge-lab/*`,
contexto do kubectl e diretórios temporários do WSL. O código do lab continua neste diretório para
reproduzir (veja o [README](README.md)).

## Ambiente

| Item | Valor |
|---|---|
| Conta / Region | projeto do lab, `us-east-2` (single-Region) |
| EKS | **1.37** (`v1.37.1-eks`), Access Entries, API pública só para o IP do operador (/32) |
| Nós | 1× `m7i.xlarge` (amd64) + 1× `m7g.xlarge` (arm64), AL2023, subnets privadas, 1 NAT |
| forge | commit `6f70c6e`, imagem multi-arch gerada pelo próprio forge no WSL (cross-compile, 0 CVE crítica, score 66) |
| Banco de CVEs | `forge-db` no cluster (Grype DB de 26/11 06:22) |
| Run | `run-20261126-090357` (= `--build-id` e tag) |

## Resultado por build

6 Jobs disparados juntos; todos terminaram em **~3,7 min** (do disparo ao último).

| App | Arch | Nó | Exit | Tempo | CVEs (crit/high) | Gate |
|---|---|---|---|---|---|---|
| orders-go | amd64 | m7i | **0** | 2m05s | 0 / 0 | ✔ publicado |
| orders-go | arm64 | m7g | **0** | 2m44s | 0 / 0 | ✔ publicado + gravou o índice |
| catalog-node | amd64 | m7i | **1** | 1m44s | 3 / 71 | ✖ 1 crítica com fix (lodash CVE-2019-10744) |
| catalog-node | arm64 | m7g | **1** | 2m38s | 3 / 71 | ✖ idem |
| billing-java | amd64 | m7i | **1** | 2m12s | 24 / 72 | ✖ 23 críticas com fix (Log4Shell, Spring4Shell, Tomcat…) |
| billing-java | arm64 | m7g | **1** | 2m51s | 24 / 72 | ✖ idem |

As 3 críticas do catalog-node incluem 2 da glibc da imagem base **sem fix**. O gate conta só as
que têm correção (`--only-fixed`), por isso o número que bloqueia é 1.

### O que ficou no ECR

| Repositório | Tags |
|---|---|
| `forge-lab/orders-go` | `<run>-amd64`, `<run>-arm64`, **`<run>` = índice OCI (amd64 + arm64)** |
| `forge-lab/catalog-node` | **vazio** |
| `forge-lab/billing-java` | **vazio** |

### Junção sem job extra

O pod amd64 terminou primeiro, publicou `-amd64` e registrou que esperava o arm64.
O pod arm64 terminou por último, viu as duas arquiteturas do mesmo `build-id` e gravou o índice
(`Join … → amd64 · arm64`, 398 ms).

### Uma tag, duas arquiteturas

Um Deployment com `orders-go:run-20261126-090357` (sem sufixo) e 2 réplicas forçadas em arquiteturas diferentes:

```
node arch arm64 -> /info {"app":"orders-go","arch":"arm64","go":"go1.27.4",...}
node arch amd64 -> /info {"app":"orders-go","arch":"amd64","go":"go1.27.4",...}
```

## Achados

1. **`hostUsers: false` funciona no EKS 1.37 com AL2023**, sem configuração extra no nó. Pod Identity
   também funciona dentro do user namespace: o push no ECR usou a role do Pod Identity sem nenhum segredo.
2. **O gargalo foi o banco de CVEs, não o build.** Carregar o DB levou de 1m38s a 2m46s por pod (6 pods
   baixando ~200 MB do `forge-db` ao mesmo tempo, com cache em `emptyDir`). O build em si levou
   ~1m15s. Para o pipeline real:
   - cache persistente (PVC ou volume do nó) em `FORGE_CACHE_DIR`;
   - ou pré-aquecer o DB na imagem do runner.

   Isso deve cortar ~1–2 min por build.
3. **O `--create-repo` cria o repositório mesmo quando o gate reprova.** Ele fica vazio, nenhuma tag é
   publicada. Aceitável, mas vale decidir se o forge deve criar o repositório só na hora do push.
4. **Pod Security:** o namespace dos builds precisa de `enforce: privileged`, porque o seccomp
   `Unconfined` viola o `baseline`. No pipeline real, uma regra do Kyverno deve liberar isso **só**
   para os pods do forge (exigindo `hostUsers: false` junto) e manter o resto do cluster em
   `baseline`/`restricted`.
5. arm64 (m7g) foi ~30–40% mais lento que amd64 (m7i) neste run. Boa parte disso é a disputa pelo
   download do DB; o build em si foi parecido (~1m14s vs ~1m18s no orders-go).

## Custo e tempo

| Etapa | Tempo |
|---|---|
| `up.sh` (stack + imagem do forge em paralelo + forge-db) | ~18 min |
| `run.sh` (6 builds + verificações + deploy de prova) | ~5 min |
| `down.sh` (stack) | ~10 min |

Custo estimado da rodada: **< US$ 0,50** (~US$ 0,52/h ligado, ~45 min no ar) + tráfego do NAT.

## Próximos passos sugeridos

- Levar o modelo para o pipeline real: GitHub Actions em ARC + Karpenter, `--multiarch`, Kargo
  observando o ECR (só enxerga a tag quando o índice existe).
- Resolver o achado 2 (cache do DB) antes de medir o tempo do pipeline.
- Política Kyverno para os pods do forge (achado 4).
