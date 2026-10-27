FROM python:3.14-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

RUN --mount=type=bind,source=.,target=/src,rw \
    apk add --no-cache bash git curl ca-certificates \
    && curl https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt \
         -o /usr/local/share/ca-certificates/SAP_Global_Root_CA.crt \
    && curl https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt \
         -o /usr/local/share/ca-certificates/SAPNetCA_G2_2.crt \
    && update-ca-certificates \
    && sed -i 's/-.*$//' /src/VERSION \
    && pip3 install --no-cache-dir --prefer-binary --break-system-packages /src

ENTRYPOINT ["python3", "-m", "github_oidc_federation.app"]
