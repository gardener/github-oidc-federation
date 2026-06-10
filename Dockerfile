FROM ghcr.io/gardener/cc-utils/alpine:3

COPY github_oidc_federation/ /github_oidc_federation/
COPY pyproject.toml VERSION /

RUN apk add --no-cache \
  bash \
  gcc \
  git \
  libc-dev \
  libev-dev \
  libffi-dev \
  python3-dev \
&& pip3 install --no-cache-dir . \
&& apk del --no-cache \
  libc-dev \
  libffi-dev \
  python3-dev \
&& ln -sf /etc/ssl/certs/ca-certificates.crt "$(python3 -m certifi)"

ENTRYPOINT ["github-oidc-federation"]
