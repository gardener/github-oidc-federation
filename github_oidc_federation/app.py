#!/usr/bin/env python3

import argparse
import collections.abc
import os

import aiohttp.web
import dacite
import requests
import yaml

import ci.log
import github

from . import github_api
from . import http_client
from . import jwt_verifier
from . import token_request_handler


ci.log.configure_default_logging()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--productive", action="store_true", default=False)
    parser.add_argument("--port", default=3000, type=int)
    parser.add_argument("--github-app-credentials-path", default="/secrets")
    parser.add_argument("--expected-audience", default="github-oidc-federation")

    return parser.parse_args()


def iter_github_app_credentials(
    github_app_credentials_path: str,
) -> collections.abc.Iterable[github.GitHubAppCredentials]:
    for github_app_credential_name in os.listdir(github_app_credentials_path):
        github_app_credential_path = os.path.join(
            github_app_credentials_path,
            github_app_credential_name,
        )

        if not os.path.isfile(github_app_credential_path):
            continue

        with open(github_app_credential_path) as f:
            github_app_credential_raw = yaml.safe_load(f)

        yield dacite.from_dict(
            data_class=github.GitHubAppCredentials,
            data=github_app_credential_raw,
        )


def run_app():
    parsed_arguments = parse_args()

    host = "0.0.0.0" if parsed_arguments.productive else "localhost"
    port = parsed_arguments.port

    github_app_credentials = list(
        iter_github_app_credentials(
            github_app_credentials_path=parsed_arguments.github_app_credentials_path,
        )
    )

    token_request_handler.ALLOWED_HOSTS = set(c.host for c in github_app_credentials)
    token_request_handler.GITHUB_API_LOOKUP = github.github_app_api_lookup(github_app_credentials)
    github_api.GITHUB_APP_CREDENTIALS = github_app_credentials
    http_client.SESSION = requests.Session()
    jwt_verifier.EXPECTED_AUDIENCE = parsed_arguments.expected_audience

    app = aiohttp.web.Application()
    app.router.add_post("/token-exchange", token_request_handler.request_token)

    aiohttp.web.run_app(app, host=host, port=port)


if __name__ == "__main__":
    run_app()
