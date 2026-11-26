# Lab: build multi-arch distribuído no EKS

Prova, num EKS descartável, que o `forge --multiarch`:

1. compila **ao mesmo tempo** a mesma aplicação em dois grupos de nós diferentes (amd64 e arm64), **nativo, sem QEMU**;
2. **bloqueia** o push quando a imagem tem CVE crítica com correção disponível;
3. na aplicação aprovada, grava **uma tag só** (`orders-go:<tag>`) que é um índice OCI com as duas arquiteturas. Quem usa a imagem não escolhe arquitetura.

```
                         CloudFormation: stack "forge-lab" (us-east-2)
 ┌──────────────────────────────── EKS forge-lab ─────────────────────────────────┐
 │  node group amd64 (m7i.xlarge)              node group arm64 (m7g.xlarge)      │
 │  ├ build-orders-go-amd64     ─┐          ┌─ build-orders-go-arm64              │
 │  ├ build-catalog-node-amd64   │ mesmo    │  build-catalog-node-arm64           │
 │  └ build-billing-java-amd64   │ build-id │  build-billing-java-arm64           │
 │                               ▼          ▼                                     │
 │        forge-db (espelho do banco de CVEs) ◄── todos os scans                  │
 └───────────────────────────────┬────────────────────────────────────────────────┘
          Pod Identity (só push em forge-lab/*)
                                 ▼
  ECR forge-lab/orders-go:  <tag>-amd64  <tag>-arm64  <tag> = índice (amd64+arm64)
  ECR forge-lab/catalog-node, forge-lab/billing-java:  nada (gate reprovou)
```

> **Última execução:** 26/11/2026, passou. Detalhes, tempos e achados em [RESULTADOS.md](RESULTADOS.md).

## As 3 aplicações

| App | Stack | Lib "de mercado" | Esperado |
|---|---|---|---|
| `orders-go` | Go 1.27.4 + gin 1.12 + uuid, distroless | tudo atualizado | **passa** e publica o índice multi-arch |
| `catalog-node` | Node 22 + express 4.17.1 | `lodash 4.17.11`: CVE-2019-10744 (crítica, fix 4.17.12) | **bloqueada** (exit 1) |
| `billing-java` | Spring Boot 2.5.6 + Java 17 | `log4j-core 2.14.1`: Log4Shell; `spring-beans`: Spring4Shell | **bloqueada** (exit 1, 23 críticas) |

Validado localmente no WSL (`forge run --no-push`) antes de ir para a AWS. Resultados: orders-go 0 CVE e score 94;
catalog-node com 1 crítica com fix; billing-java com 23 críticas com fix (4 no catálogo KEV da CISA).

## Uso

Pré-requisitos: AWS CLI v2 com o perfil `lab`, `kubectl`, Go, Git Bash e WSL `Ubuntu-24.04` com `~/.aws`
apontando para o do Windows (o binário do forge é Linux: a imagem do próprio forge é gerada no WSL).

```bash
aws login --profile lab          # sessão de ~12h
cd lab/eks-multiarch
./infra/up.sh                    # ~18 min: cluster + imagem do forge (em paralelo) + forge-db
./infra/run.sh                   # ~5-8 min: 6 builds simultâneos e as verificações
./infra/down.sh                  # ~10 min: apaga tudo e procura sobras que cobram
```

Confirme a Region do projeto em **AWS Settings > View all projects > Overview > Additional Info > Region**.
O lab usa `us-east-2` por padrão (`AWS_REGION=...` para trocar).

O `run.sh` termina com `LAB PASSED` só se **todas** as condições abaixo valerem:

- os Jobs de `orders-go` saem com 0 e a tag `<tag>` no ECR é um índice com `amd64` e `arm64`;
- os Jobs de `catalog-node` e `billing-java` saem com 1 (gate) e **nenhuma** tag desse run existe no ECR;
- um Deployment com `orders-go:<tag>` (sem sufixo de arquitetura), com 2 réplicas forçadas em arquiteturas
  diferentes, sobe e o `/info` de cada pod responde com a arquitetura do seu nó.

Rodar o `run.sh` de novo gera um run novo (`TAG=run-AAAAMMDD-HHMMSS`); o segundo é mais rápido porque as
imagens base já estão nos nós.

## Por que assim (e alternativas)

| Decisão | Motivo | Alternativa |
|---|---|---|
| **CloudFormation** (1 stack) | sobe e apaga tudo de forma atômica, sem instalar nada (não há `eksctl` aqui) | `eksctl` (YAML menor, mas precisa instalar) ou Terraform |
| **Jobs no cluster** em vez de GitHub Actions + ARC | testa exatamente o que importa (pods em nós diferentes + `--build-id` comum) sem GitHub App, runners nem segredos | o modelo ARC + Karpenter de [`docs/ci.md`](../../docs/ci.md) para o pipeline real |
| Fontes via **ConfigMap** (tar.gz) | nada de repositório nem token para clonar | `git clone` num initContainer (é o que o pipeline real faz) |
| **1 nó on-demand por arquitetura**, xlarge | 3 builds por nó com folga (Maven e npm são pesados); sem risco de falta de capacidade spot | spot (~60% mais barato, pode ser interrompido) ou Karpenter |
| Nós em **subnet privada** + 1 NAT | nada exposto à internet | subnet pública sem NAT (mais barato, menos seguro) |

### Segurança

- API do Kubernetes pública **só para o seu IP** (`/32`), detectado pelo `up.sh`; acesso privado ligado.
- Autenticação só por Access Entries (`authenticationMode: API`); quem cria o cluster vira admin.
- Pods de build com `hostUsers: false`: root no pod é um uid sem privilégio no nó. Sem `privileged` e sem capabilities extras.
- A role do forge (Pod Identity) só faz push e cria repositórios em `forge-lab/*`. Nenhum segredo no cluster.
- Namespace das apps com Pod Security `restricted`. O pod da aplicação roda sem root, com FS somente leitura e `drop ALL`.
- `UpgradePolicy: STANDARD`: o cluster nunca cai em suporte estendido (que é cobrado à parte).

## Custos (us-east-2, on-demand)

| Item | US$/h |
|---|---|
| Control plane EKS | 0,10 |
| m7i.xlarge (amd64) | ~0,20 |
| m7g.xlarge (arm64) | ~0,16 |
| NAT Gateway + IP público | ~0,05 |
| EBS 2× 60 GB gp3 | ~0,01 |
| **Total** | **~0,52** |

Uma rodada completa (subir, testar e derrubar) leva cerca de 40 min e custa **menos de US$ 0,50**, mais centavos
de tráfego no NAT (imagens base, Maven e npm). O `down.sh` apaga também os repositórios `forge-lab/*` do ECR
(`--keep-images` para manter). Se o projeto tiver **limite de gasto** (AWS Settings > Billing) e algo começar a dar
`AccessDenied` do nada, confira lá primeiro.

## Estrutura

```
lab/eks-multiarch/
├── apps/                 orders-go (passa) · catalog-node (CVE) · billing-java (CVE)
├── Dockerfile.forge      imagem do forge multi-arch (cross-compile, sem emulação)
├── infra/
│   ├── cluster.yaml      CloudFormation: VPC, EKS, 2 node groups, Pod Identity, IAM
│   ├── up.sh · run.sh · down.sh · lib.sh
│   └── forge-image.sh    roda no WSL: forge constrói e publica a si mesmo
└── k8s/                  forge-ci + forge-db · Job de build · Deployment do orders-go
```
