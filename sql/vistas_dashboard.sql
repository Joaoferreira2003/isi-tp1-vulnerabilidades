-- ===============================================================
-- TP1 ISI — Vistas para o dashboard (Grafana)
-- Apenas CREATE VIEW: não altera nem apaga dados nas tabelas.
--
-- NOTA: o esquema não tem coluna "risco". O risco é calculado aqui,
-- nas vistas, a partir de três sinais independentes. Manter o cálculo
-- numa vista (e não numa coluna material) significa que basta alterar
-- este ficheiro para ajustar a fórmula, sem recarregar nada.
-- ===============================================================

-- ---------------------------------------------------------------
-- VISTA BASE — junta tudo e calcula risco e prioridade.
-- As outras vistas assentam nesta, para a fórmula existir num só sítio.
--
-- Fórmula do risco (escala 0-10):
--   50%  CVSS      -> gravidade técnica  (cai para o v2 se não houver v3)
--   30%  EPSS      -> probabilidade de exploração nos próximos 30 dias
--   20%  KEV       -> exploração confirmada no mundo real
--
-- A ponderação é discutível e é isso mesmo que se pretende: é uma
-- decisão de negócio que se pode justificar e alterar na defesa.
-- O CVSS sozinho diz quão grave *seria*; o EPSS diz quão provável é;
-- o KEV diz que já aconteceu.
-- ---------------------------------------------------------------
CREATE OR REPLACE VIEW vw_vulnerabilidade_completa AS
SELECT
    f.id_vuln,
    i.artifact_name                              AS imagem,
    i.os_familia,
    i.os_versao,
    f.target,
    f.classe,
    f.tipo_pacote,
    f.pkg_name,
    f.installed_version,
    f.fixed_version,
    (f.fixed_version IS NOT NULL)                AS tem_correcao,
    f.estado_correcao,
    f.cve_id,
    c.tipo_id,
    c.titulo,
    f.severidade,
    f.cvss_v3_score,
    f.cvss_v2_score,
    c.epss_score,
    c.epss_percentile,
    c.em_kev,
    k.vendor_project                             AS kev_fornecedor,
    k.date_added                                 AS kev_data_adicao,
    k.due_date                                   AS kev_prazo,
    k.known_ransomware                           AS kev_ransomware,
    ROUND(
          COALESCE(f.cvss_v3_score, f.cvss_v2_score, 0) * 0.50
        + COALESCE(c.epss_score, 0) * 10         * 0.30
        + CASE WHEN c.em_kev THEN 10 ELSE 0 END  * 0.20
    , 2)                                         AS risco
FROM fact_vulnerabilidade f
JOIN      dim_imagem i ON i.id_imagem = f.id_imagem
JOIN      dim_cve    c ON c.cve_id    = f.cve_id
LEFT JOIN dim_kev    k ON k.cve_id    = f.cve_id;

COMMENT ON VIEW vw_vulnerabilidade_completa IS
  'Vista base: ocorrencia + imagem + CVE + KEV, com risco calculado 0-10';


-- ---------------------------------------------------------------
-- VISTA 1 — Vulnerabilidades por imagem e prioridade
-- Para um gráfico de barras empilhadas no Grafana.
--
-- A prioridade não é a severidade do Trivy: uma CVE no KEV é sempre
-- crítica, por mais baixo que seja o CVSS, porque já está a ser
-- explorada. É esta a diferença entre "gravidade" e "urgência".
-- ---------------------------------------------------------------
CREATE OR REPLACE VIEW vw_vuln_por_imagem AS
SELECT
    imagem,
    CASE WHEN em_kev       THEN 'Critica (KEV)'
         WHEN risco >= 8.0 THEN 'Critica'
         WHEN risco >= 6.0 THEN 'Alta'
         WHEN risco >= 4.0 THEN 'Media'
         ELSE                   'Baixa' END      AS prioridade,
    count(*)                                     AS n_vulnerabilidades,
    count(*) FILTER (WHERE NOT tem_correcao)     AS sem_correcao,
    ROUND(AVG(risco), 2)                         AS risco_medio,
    MAX(risco)                                   AS risco_maximo
FROM vw_vulnerabilidade_completa
GROUP BY imagem, 2;

COMMENT ON VIEW vw_vuln_por_imagem IS
  'Contagem por imagem e nivel de prioridade, com quantas nao tem correcao';


-- ---------------------------------------------------------------
-- VISTA 2 — Top 10 por risco
-- A lista de "o que corrigir primeiro". É a vista que responde à
-- pergunta de negócio do trabalho.
--
-- Agrega por CVE e não por ocorrência: a mesma CVE aparece em várias
-- imagens, e numa lista de prioridades isso seria ruído. A coluna
-- n_imagens mostra o alcance.
-- ---------------------------------------------------------------
CREATE OR REPLACE VIEW vw_top_risco AS
SELECT
    cve_id,
    titulo,
    MAX(risco)                                   AS risco,
    MAX(cvss_v3_score)                           AS cvss_v3,
    MAX(epss_score)                              AS epss,
    MAX(epss_percentile)                         AS epss_percentil,
    bool_or(em_kev)                              AS em_kev,
    count(DISTINCT imagem)                       AS n_imagens,
    string_agg(DISTINCT imagem, ', ' ORDER BY imagem) AS imagens_afetadas,
    count(*)                                     AS n_ocorrencias,
    count(*) FILTER (WHERE NOT tem_correcao)     AS ocorrencias_sem_correcao
FROM vw_vulnerabilidade_completa
GROUP BY cve_id, titulo
ORDER BY risco DESC, n_imagens DESC
LIMIT 10;

COMMENT ON VIEW vw_top_risco IS
  'As 10 CVE mais prioritarias, agregadas por CVE e nao por ocorrencia';


-- ---------------------------------------------------------------
-- VISTA 3 — Distribuição por severidade
-- Para um gráfico circular ou de barras. Inclui o cruzamento com a
-- existência de correção, que é a informação accionável: uma
-- CRITICAL sem correção disponível é um problema diferente de uma
-- CRITICAL que basta actualizar.
-- ---------------------------------------------------------------
CREATE OR REPLACE VIEW vw_distribuicao_severidade AS
SELECT
    severidade,
    count(*)                                     AS n_total,
    count(*) FILTER (WHERE tem_correcao)         AS com_correcao,
    count(*) FILTER (WHERE NOT tem_correcao)     AS sem_correcao,
    count(*) FILTER (WHERE em_kev)               AS em_kev,
    ROUND(AVG(cvss_v3_score), 2)                 AS cvss_medio,
    ROUND(AVG(epss_score), 6)                    AS epss_medio,
    ROUND(100.0 * count(*) / NULLIF(SUM(count(*)) OVER (), 0), 1) AS percentagem
FROM vw_vulnerabilidade_completa
GROUP BY severidade;

COMMENT ON VIEW vw_distribuicao_severidade IS
  'Distribuicao por severidade cruzada com disponibilidade de correcao';


-- ---------------------------------------------------------------
-- VISTA 4 — CVE no catálogo KEV
-- Exploração confirmada no mundo real. Esperam-se 5 CVE.
-- É a vista mais importante do dashboard apesar de ser a mais pequena:
-- estas são as que têm de ser corrigidas primeiro, sem discussão.
-- ---------------------------------------------------------------
CREATE OR REPLACE VIEW vw_kev_criticas AS
SELECT
    v.cve_id,
    v.titulo,
    v.kev_fornecedor,
    v.kev_data_adicao,
    v.kev_prazo,
    (v.kev_prazo < CURRENT_DATE)                 AS prazo_expirado,
    v.kev_ransomware,
    v.epss_score,
    MAX(v.cvss_v3_score)                         AS cvss_v3,
    MAX(v.risco)                                 AS risco,
    count(DISTINCT v.imagem)                     AS n_imagens,
    string_agg(DISTINCT v.imagem, ', ' ORDER BY v.imagem) AS imagens_afetadas,
    count(*) FILTER (WHERE NOT v.tem_correcao)   AS ocorrencias_sem_correcao
FROM vw_vulnerabilidade_completa v
WHERE v.em_kev
GROUP BY v.cve_id, v.titulo, v.kev_fornecedor, v.kev_data_adicao,
         v.kev_prazo, v.kev_ransomware, v.epss_score
ORDER BY risco DESC;

COMMENT ON VIEW vw_kev_criticas IS
  'CVE presentes no catalogo CISA KEV: exploracao confirmada (esperadas 5)';
