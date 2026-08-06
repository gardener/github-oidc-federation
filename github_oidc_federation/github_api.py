import base64
import collections.abc
import logging
import time

import aiohttp
import aiohttp.web
import async_lru
import jwt

import github_oidc_federation.http_client as http_client
import github_oidc_federation.models as models

logger = logging.getLogger(__name__)


def find_credential(
    repo_url: str,
    credentials: collections.abc.Sequence[models.GitHubAppCredentials],
) -> models.GitHubAppCredentials | None:
    for credential in credentials:
        if credential.matches(repo_url):
            return credential
    return None


async def fetch_installation_token(token_request: models.TokenRequest, sub: str) -> dict:
    credential = token_request.credential
    private_key = credential.private_key.encode('utf-8')
    jwt_token = _create_jwt(credential.app_id, private_key)

    installation_id = await _get_installation_id_for_org(
        host=token_request.host,
        org=token_request.organization,
        app_id=credential.app_id,
        private_key=private_key,
    )

    token_res = await http_client.fetch_with_retries(
        url=f'{_get_api_url(token_request.host)}/app/installations/{installation_id}/access_tokens',
        method='POST',
        headers={
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github+json',
            'User-Agent': f'github-oidc-federation: {token_request.issuer}:{sub}',
        },
        json_body={
            'repositories': token_request.requested_repositories,
            'permissions': {
                permission.replace('-', '_'): level
                for permission, level in token_request.permissions.items()
            },
        },
    )
    return token_res.to_json()


def _create_jwt(app_id: int, private_key: bytes) -> str:
    now = int(time.time())
    return jwt.encode(
        payload={'iat': now - 60, 'exp': now + 600, 'iss': str(app_id)},
        key=private_key,
        algorithm='RS256',
    )


@async_lru.alru_cache(ttl=60 * 60 * 24)  # 24 hours
async def _get_installation_id_for_org(
    host: str,
    org: str,
    app_id: int,
    private_key: bytes,
) -> int:
    jwt_token = _create_jwt(app_id, private_key)
    try:
        res = await http_client.fetch_with_retries(
            url=f'{_get_api_url(host)}/orgs/{org}/installation',
            method='GET',
            headers={
                'Authorization': f'Bearer {jwt_token}',
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
    repo_url: str, host: str, credential: models.GitHubAppCredentials
) -> str:
    _, org, repo_name = models.get_host_org_and_repo_from_url(repo_url)
    private_key = credential.private_key.encode('utf-8')
    jwt_token = _create_jwt(credential.app_id, private_key)

    installation_id = await _get_installation_id_for_org(host, org, credential.app_id, private_key)
    installation_token = await _get_app_installation_token(host, jwt_token, installation_id)

    # oidc-federation.yaml is expected at the root of the .github-oidc repository
    try:
        contents_response = await http_client.fetch_with_retries(
            url=f'{_get_api_url(host)}/repos/{org}/{repo_name}/contents/oidc-federation.yaml',
            method='GET',
            headers={
                'Authorization': f'Bearer {installation_token}',
                'Accept': 'application/vnd.github+json',
            },
        )
        content_b64 = contents_response.to_json()['content']
        return base64.b64decode(content_b64.replace('\n', '')).decode()
    except aiohttp.ClientResponseError as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to fetch oidc-federation-config',
        )
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to fetch oidc-federation-config',
        )


async def _get_app_installation_token(host: str, jwt_token: str, installation_id: int) -> str:
    try:
        token_response = await http_client.fetch_with_retries(
            url=f'{_get_api_url(host)}/app/installations/{installation_id}/access_tokens',
            method='POST',
            headers={
                'Authorization': f'Bearer {jwt_token}',
                'Accept': 'application/vnd.github+json',
            },
            json_body={},
        )
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to obtain installation access token',
        )

    return token_response.to_json()['token']
