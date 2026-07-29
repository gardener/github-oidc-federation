#!/usr/bin/env python3

import argparse
import collections.abc
import logging
import os

import aiohttp.web
import dacite
import yaml

import github_oidc_federation.cache_invalidation_handler as cache_invalidation_handler
import github_oidc_federation.http_client as http_client
import github_oidc_federation.models as models
import github_oidc_federation.token_request_handler as token_request_handler

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(name)s %(message)s')

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument('--productive', action='store_true', default=False)
    parser.add_argument('--port', default=3000, type=int)
    parser.add_argument('--github-app-credentials-path', default='/secrets')
    parser.add_argument('--expected-audience', default='github-oidc-federation')

    return parser.parse_args()


def iter_github_app_credentials(
    github_app_credentials_path: str,
) -> collections.abc.Iterable[models.GitHubAppCredentials]:
    for github_app_credential_name in os.listdir(github_app_credentials_path):
        github_app_credential_path = os.path.join(
            github_app_credentials_path,
            github_app_credential_name,
        )

        if not os.path.isfile(github_app_credential_path):
            continue

        with open(github_app_credential_path) as f:
            github_app_credential_raw = yaml.safe_load(f)

        # convert list to tuple so it is hashable for cache.
        if raw_selectors := github_app_credential_raw.get('selectors'):
            github_app_credential_raw['selectors'] = tuple(
                models.GitHubAppSelector(**selector) for selector in raw_selectors
            )

        yield dacite.from_dict(
            data_class=models.GitHubAppCredentials,
            data=github_app_credential_raw,
        )


def run_app() -> None:
    parsed_arguments = parse_args()

    host = '0.0.0.0' if parsed_arguments.productive else 'localhost'
    port = parsed_arguments.port

    github_app_credentials = list(
        iter_github_app_credentials(
            github_app_credentials_path=parsed_arguments.github_app_credentials_path,
        ),
    )

    k8s_sa_token = None
    k8s_namespace = None
    try:
        with open(cache_invalidation_handler.K8S_SA_TOKEN_PATH) as f:
            k8s_sa_token = f.read()
        with open(cache_invalidation_handler.K8S_SA_NAMESPACE_PATH) as f:
            k8s_namespace = f.read()
    except OSError:
        logger.warning('K8s service account files not found — cache broadcast disabled')

    app = build_app(
        github_app_credentials=github_app_credentials,
        expected_audience=parsed_arguments.expected_audience,
        k8s_sa_token=k8s_sa_token,
        k8s_namespace=k8s_namespace,
    )
    aiohttp.web.run_app(app, host=host, port=port)


def build_app(
    github_app_credentials: list[models.GitHubAppCredentials],
    expected_audience: str,
    k8s_sa_token: str | None = None,
    k8s_namespace: str | None = None,
) -> aiohttp.web.Application:
    async def on_startup(_):
        http_client.SESSION = aiohttp.ClientSession()

    async def on_cleanup(_):
        await http_client.SESSION.close()

    app = aiohttp.web.Application()
    app['allowed_hosts'] = set(c.host for c in github_app_credentials)
    app['github_app_credentials'] = github_app_credentials
    app['expected_audience'] = expected_audience
    app['k8s_sa_token'] = k8s_sa_token
    app['k8s_namespace'] = k8s_namespace

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    app.router.add_post('/token-exchange', token_request_handler.request_token)
    app.router.add_post('/invalidate-cache', cache_invalidation_handler.invalidate_cache)

    return app


if __name__ == '__main__':
    run_app()
