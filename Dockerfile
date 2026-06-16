FROM ghcr.io/gardener/cc-utils/alpine:3

RUN apk add --no-cache bash git libev \
&& pip3 install --no-cache-dir --prefer-binary \
  aiohttp \
  async-lru \
  cryptography \
  dacite \
  "github3.py" \
  pyjwt \
  pyyaml

COPY github_oidc_federation/ /app/github_oidc_federation/

RUN ln -sf /etc/ssl/certs/ca-certificates.crt "$(python3 -m certifi)"

ENV PYTHONPATH=/app

ENTRYPOINT ["python3", "-m", "github_oidc_federation.app"]
