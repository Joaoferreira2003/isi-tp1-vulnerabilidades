# ===============================================================
# Grafana com a fonte de dados e o dashboard já provisionados.
#
# Usado no deploy para o Railway, onde não há volumes montados: os
# ficheiros de provisionamento têm de viajar dentro da imagem.
#
# Localmente não é preciso -- o docker-compose.yml monta as pastas
# directamente, o que permite editar sem reconstruir a imagem.
# ===============================================================
FROM grafana/grafana:11.3.0

COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/   /var/lib/grafana/dashboards/

# O Railway injecta a porta em $PORT; o Grafana lê GF_SERVER_HTTP_PORT.
ENV GF_USERS_ALLOW_SIGN_UP=false \
    GF_AUTH_ANONYMOUS_ENABLED=false \
    GF_SERVER_ROOT_URL=%(protocol)s://%(domain)s/
