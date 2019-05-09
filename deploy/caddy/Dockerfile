# TODO all these caddy base images seem rather crappy
FROM yobasystems/alpine-caddy
COPY Caddyfile /etc/

RUN mkdir -p /home/caddy/.caddy

CMD ["-conf","/etc/Caddyfile","-agree","-email","scionlab-admins@sympa.ethz.ch"]
