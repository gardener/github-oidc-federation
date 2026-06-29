FROM ghcr.io/gardener/cc-utils/alpine:3

RUN --mount=type=bind,source=.,target=/src,rw \
    apk add --no-cache bash git \
    && sed -i 's/-.*$//' /src/VERSION \
    && pip3 install --no-cache-dir --prefer-binary /src

ENTRYPOINT ["python3", "-m", "github_oidc_federation.app"]
