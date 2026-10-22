# TP1 — Integração de Sistemas de Informação

Processo **ETL em KNIME** para gestão de vulnerabilidades de contentores.

Scans do **Trivy** a 6 imagens Docker antigas, enriquecidos com **CISA KEV**,
**EPSS** e **MITRE CWE**, carregados em **PostgreSQL** e apresentados num
dashboard **Grafana**.

Licenciatura em Engenharia de Sistemas Informáticos — IPCA, 2026/27.

---

## O que o processo faz

| Fase | O quê |
|---|---|
| **E** — Extração | 6 JSON do Trivy, XML do MITRE CWE, CSV do EPSS (ficheiros locais) e catálogo CISA KEV + scores EPSS por **API REST** |
| **T** — Transformação | achatamento do JSON aninhado, regex de normalização dos CWE, *ungroup* de coleções, joins, agregações e cálculo de risco |
| **L** — Carregamento | 6 tabelas em PostgreSQL, exportação CSV e dashboard Grafana |

Formatos consumidos: **JSON**, **CSV**, **XML** e respostas **JSON** de API REST.

---

## Pré-requisitos

- **PostgreSQL 16+** (desenvolvido em 18.3)
- **KNIME Analytics Platform** com a *KNIME REST Client Extension*
- **Docker** (apenas para o dashboard Grafana)

---

## Instalação

### 1. Dados de origem

Os scans do Trivy já estão em `dados/trivy/` — são o resultado deste trabalho
e não se obtêm de outro sítio.

As restantes fontes **não estão no repositório** por serem volumosas e
publicamente descarregáveis. Antes de correr o workflow:

```bash
# MITRE CWE  -> dados/cwe/cwec_v4.20.xml   (~18 MB)
curl -L -o dados/cwe/cwe.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
unzip dados/cwe/cwe.zip -d dados/cwe/

# EPSS       -> dados/epss/epss.csv        (~11 MB)
curl -L -o dados/epss/epss.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
gunzip -k dados/epss/epss.csv.gz
```

O catálogo CISA KEV é obtido pelo próprio workflow, a partir do feed:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

> O EPSS é publicado diariamente e o KEV cresce com o tempo. Os valores de
> validação abaixo referem-se à execução de 2026-10-22.

### 2. Configuração

```bash
cp .env.example .env
```

Preencher `PG_PASSWORD` e, se desejado, `GRAFANA_PASSWORD`.
O `.env` está excluído do controlo de versões.

### 3. Base de dados

```sql
CREATE DATABASE isi_tp1;
```

Ligar a `isi_tp1` e executar `sql/01_schema.sql` (6 tabelas, 13 restrições,
15 índices) seguido de `sql/vistas_dashboard.sql` (5 vistas).

> Atenção: executar com a base `isi_tp1` activa, não com a `postgres`.

### 4. Workflow

No KNIME: **File → Import KNIME Workflow** → `knime/tp1-vulnerabilidades.knwf`

Ajustar o nó de ligação à base de dados com as credenciais do `.env` e os
caminhos dos ficheiros de origem, e executar.

### 5. Dashboard

```bash
docker compose up -d
```

Disponível em **http://localhost:3000** (`admin` / password do `.env`).
A fonte de dados e o dashboard são provisionados automaticamente a partir de
`grafana/`.

O Grafana liga-se a `host.docker.internal:5432`, ou seja ao PostgreSQL do
**anfitrião** — é lá que o KNIME escreve. O serviço `postgres` do
`docker-compose.yml` está atrás do perfil `db` e não arranca por omissão.

---

## Validação da carga

Depois de executar o workflow, estes são os valores esperados:

| Tabela | Linhas |
|---|---|
| `dim_imagem` | 6 |
| `dim_cve` | 679 |
| `dim_cwe` | 1391 |
| `dim_kev` | 1754 *(catálogo vivo; cresce)* |
| `fact_vulnerabilidade` | 2642 |
| `ponte_vuln_cwe` | 2787 |

Verificações adicionais: 666 CVE com EPSS, 5 CVE no KEV, 436 ocorrências sem
correção disponível.

---

## Modelo de dados

Modelo em estrela. A granularidade dos factos é
`imagem × target × pacote × vulnerabilidade`, combinação verificada como única
nos ficheiros de origem.

```
dim_imagem ─┐
            ├─> fact_vulnerabilidade ─> ponte_vuln_cwe <─ dim_cwe
dim_cve ────┘                                    (N:N)
dim_kev  (dimensão de referência, sem FK)
```

- O **EPSS** vive em `dim_cve` por ser atributo da vulnerabilidade e não da
  ocorrência.
- `dim_kev` não tem chave estrangeira para `dim_cve` porque se carrega o
  catálogo completo, e a maioria dessas CVE não aparece nos scans.
- `ponte_vuln_cwe` existe porque `CweIDs` é uma lista no Trivy.

### Cálculo do risco

Feito nas vistas, em escala 0-10:

```
risco = 50% CVSS  +  30% EPSS  +  20% KEV
```

O CVSS diz quão grave *seria*; o EPSS, quão provável é a exploração; o KEV,
que já está a ser explorada. Uma CVE presente no KEV é sempre tratada como
prioridade crítica, independentemente do CVSS.

---

## Estrutura

```
dados/trivy/     6 scans do Trivy (JSON)
dados/cwe/       MITRE CWE (descarregar)
dados/epss/      EPSS (descarregar)
knime/           workflow exportado (.knwf)
sql/             esquema e vistas
grafana/         provisionamento do dashboard
saidas/          exportações geradas
```

---

## Dashboard

O dashboard corre localmente em `http://localhost:3000` após `docker compose up -d`.

![Dashboard de gestão de vulnerabilidades](imagens/dashboard.png)

### Principais resultados

- **2642** ocorrências de vulnerabilidade em 6 imagens
- **679** vulnerabilidades distintas, das quais **5** com exploração confirmada (CISA KEV)
- **436** ocorrências sem correção disponível
- A CVE de maior risco é a **CVE-2025-24813** (risco 9,90; CVSS 9,8; EPSS 0,9993)
- Os **5 prazos de correção da CISA já expiraram**, o mais antigo desde novembro de 2021

A ordenação por risco difere da ordenação por CVSS: a **CVE-2021-3711** tem CVSS 9,8
— superior ao de quatro das cinco CVE do KEV — mas fica em 6.º lugar por não estar
a ser explorada. É esta diferença que justifica o modelo de priorização.

---

## Demonstração

Vídeo com a demonstração do processo completo — leitura das fontes,
transformações, carregamento e dashboard:

<img src="imagens/qrcode-video.png" alt="QR Code para o vídeo de demonstração" width="200">
