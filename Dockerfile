FROM ghcr.io/gardener/cc-utils/alpine:3

COPY app.py token_exchange.py /

RUN --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt,ro \
  apk add --no-cache \
  bash \
  gcc \
  git \
  libc-dev \
  libev-dev \
  libffi-dev \
  python3-dev \
&& pip3 install --upgrade --no-cache-dir -r /tmp/requirements.txt \
&& apk del --no-cache \
  libc-dev \
  libffi-dev \
  python3-dev \
&& ln -sf /etc/ssl/certs/ca-certificates.crt "$(python3 -m certifi)"

ENTRYPOINT ["python3", "-m", "app"]
