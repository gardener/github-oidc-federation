import base64
import collections.abc
import logging

import aiohttp.web
import github3.apps
from async_lru import alru_cache

import github
from .http_client import fetch_with_retries
from .models import TokenRequest


logger = logging.getLogger(__name__)

GITHUB_APP_CREDENTIALS: collections.abc.Sequence[github.GitHubAppCredentials] = []


def find_credential(repo_url: str) -> github.GitHubAppCredentials:
    for cred in GITHUB_APP_CREDENTIALS:
        if cred.matches(repo_url):
            return cred
    raise aiohttp.web.HTTPInternalServerError(
        reason=f'No matching GitHub App credentials for {repo_url}',
    )


async def fetch_installation_token(token_request: TokenRequest, sub: str) -> dict:
    credential = token_request.credential
    private_key = _extract_private_key(credential)
    jwt_token = _create_jwt(credential.app_id, private_key)

    installation_id = await _get_installation_id_for_org(
        host=token_request.host,
        org=token_request.organization,
        app_id=credential.app_id,
        private_key=private_key,
    )

    token_res = await fetch_with_retries(
        url=f'{_get_api_url(token_request.host)}/app/installations/{installation_id}/access_tokens',
        headers={
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github+json',
            'User-Agent': f'github-oidc-federation: {token_request.issuer}:{sub}',
        },
        json={
            'repositories': token_request.requested_repositories,
            'permissions': {
                permission.replace('-', '_'): level
                for permission, level in token_request.permissions.items()
            },
        },
    )
    return token_res.to_json()


def _extract_private_key(credential):
    raw_private_key = credential.private_key
    private_key = raw_private_key.encode() if isinstance(raw_private_key, str) else raw_private_key
    return private_key


def _create_jwt(app_id: int, private_key: bytes) -> str:
    return github3.apps.create_token(
        private_key_pem=private_key,
        app_id=str(app_id),
    )


@alru_cache(maxsize=1024, ttl=60 * 60 * 24)
async def _get_installation_id_for_org(
    host: str,
    org: str,
    app_id: int,
    private_key: bytes,
) -> int:
    jwt = _create_jwt(app_id, private_key)
    try:
        res = await fetch_with_retries(
            url=f'{_get_api_url(host)}/orgs/{org}/installation',
            headers={
                'Authorization': f'Bearer {jwt}',
                'Accept': 'application/vnd.github+json',
            },
        )
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason=f'Failed to fetch installation ID for org {org}',
        )

    return res.to_json()['id']


def _get_api_url(host: str) -> str:
    if host == 'github.com':
        return 'https://api.github.com'
    return f'https://{host}/api/v3'


async def fetch_raw_oidc_config(
    repo_url: str, host: str, credential: github.GitHubAppCredentials
) -> str:
    _, org, repo_name = github.host_org_and_repo(repo_url)
    private_key = _extract_private_key(credential)
    jwt = _create_jwt(credential.app_id, private_key)

    installation_id = await _get_installation_id_for_org(host, org, credential.app_id, private_key)
    installation_token = await _get_app_installation_token(host, jwt, installation_id)

    for filename in ('oidc-federation.yaml', 'oidc-federation.json'):
        try:
            contents_response = await fetch_with_retries(
                url=f'{_get_api_url(host)}/repos/{org}/{repo_name}/contents/{filename}',
                headers={
                    'Authorization': f'Bearer {installation_token}',
                    'Accept': 'application/vnd.github+json',
                },
            )
            content_b64 = contents_response.to_json()['content']
            return base64.b64decode(content_b64.replace('\n', '')).decode()
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                continue
            logger.error(e)
            raise aiohttp.web.HTTPInternalServerError(
                reason='Failed to fetch oidc-federation-config',
            )
        except Exception as e:
            logger.error(e)
            raise aiohttp.web.HTTPInternalServerError(
                reason='Failed to fetch oidc-federation-config',
            )

    raise aiohttp.web.HTTPInternalServerError(
        reason='Failed to fetch oidc-federation-config',
    )


async def _get_app_installation_token(host, jwt, installation_id):
    try:
        token_response = await fetch_with_retries(
            url=f'{_get_api_url(host)}/app/installations/{installation_id}/access_tokens',
            headers={
                'Authorization': f'Bearer {jwt}',
                'Accept': 'application/vnd.github+json',
            },
            json={},
        )
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to obtain installation access token',
        )

    installation_token = token_response.to_json()['token']
    return installation_token
