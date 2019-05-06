# TODO all these caddy base images seem rather crappy
FROM yobasystems/alpine-caddy
COPY Caddyfile /etc/

RUN mkdir -p /home/caddy/.caddy

CMD --conf /etc/Caddyfile -agree -ca https://acme-staging-v02.api.letsencrypt.org/directory -email scionlab-admins@sympa.ethz.ch
