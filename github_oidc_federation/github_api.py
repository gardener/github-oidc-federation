import collections.abc
import logging

import aiohttp.web
import cachetools
import github3
import github3.apps
import github3.exceptions

import github
from .http_client import fetch_with_retries
from .models import TokenRequest


logger = logging.getLogger(__name__)

GITHUB_APP_CREDENTIALS: collections.abc.Sequence[github.GitHubAppCredentials] = []


def fetch_raw_oidc_config(token_request: TokenRequest) -> str:
    _, organization, repo_name = github.host_org_and_repo(token_request.repo_url)
    try:
        repo = token_request.github_api.repository(organization, repo_name)
        try:
            oidc_federation_raw = repo.file_contents('oidc-federation.yaml').decoded.decode()
        except github3.exceptions.NotFoundError:
            oidc_federation_raw = repo.file_contents('oidc-federation.json').decoded.decode()
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to fetch oidc-federation-config',
        )
    return oidc_federation_raw


def fetch_installation_token(token_request: TokenRequest, sub: str) -> dict:
    for github_app_credential in GITHUB_APP_CREDENTIALS:
        if github_app_credential.matches(token_request.repo_url):
            break
    else:
        raise aiohttp.web.HTTPInternalServerError(
            reason=f'No matching GitHub App credentials for {token_request.repo_url}',
        )

    jwt_token = github3.apps.create_token(
        private_key_pem=github_app_credential.private_key.encode(),
        app_id=str(github_app_credential.app_id),
    )

    installation_id = _get_installation_id_for_org(
        organization=token_request.organization,
        github_api=token_request.github_api,
        private_key=github_app_credential.private_key.encode(),
        app_id=github_app_credential.app_id,
    )

    api_url = f'https://api.{token_request.host}' if token_request.host == 'github.com' else f'https://{token_request.host}/api/v3'
    token_res = fetch_with_retries(
        url=f'{api_url}/app/installations/{installation_id}/access_tokens',
        headers={
            'Authorization': f'Bearer {jwt_token}',
            'User-Agent': f'github-oidc-federation: {token_request.issuer}:{sub}',
        },
        json={
            'repositories': token_request.requested_repositories,
            'permissions': {
                permission.replace('-', '_'): level
                for permission, level in token_request.permissions.items()
            },
        }
    )

    return token_res.json()


@cachetools.cached(cache=cachetools.TTLCache(maxsize=1024, ttl=60*60*24)) # 24h
def _get_installation_id_for_org(
    organization: str,
    github_api: github3.GitHub,
    private_key: bytes,
    app_id: int,
) -> int:
    github_api.login_as_app(
        private_key_pem=private_key,
        app_id=str(app_id),
    )

    installation = github_api.app_installation_for_organization(organization)

    return installation.id
