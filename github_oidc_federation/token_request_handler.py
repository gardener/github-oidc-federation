import collections.abc
import logging
import re

import aiohttp.web

import github_oidc_federation.github_api as github_api
import github_oidc_federation.jwt_verifier as jwt_verifier
import github_oidc_federation.models as models
import github_oidc_federation.oidc_config as oidc_config

logger = logging.getLogger(__name__)

_REPOSITORY_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')


async def request_token(request: aiohttp.web.Request) -> aiohttp.web.Response:
    allowed_hosts: set[str] = request.app['allowed_hosts']
    credentials = request.app['github_app_credentials']
    audience: str = request.app['expected_audience']

    body = await request.json()
    token_request: models.TokenRequest = _resolve_request(body, allowed_hosts, credentials)
    oidc_federation_config = await oidc_config.retrieve_oidc_federation_config(
        token_request, credentials
    )

    claims = await jwt_verifier.verify_jwt(token_request.raw_jwt, token_request.issuer, audience)

    oidc_config.find_matching_entry(
        token_request, oidc_federation_config, claims, _is_request_authorized
    )

    result = await github_api.fetch_installation_token(token_request, claims['sub'])
    return aiohttp.web.json_response(result)


def _resolve_request(
    body: dict,
    allowed_hosts: set[str],
    credentials: collections.abc.Sequence[models.GitHubAppCredentials],
) -> models.TokenRequest:
    raw_jwt = body.get('token')
    host = body.get('host')
    organization = body.get('organization')
    permissions = body.get('permissions')
    repositories = body.get('repositories')

    _validate_request(raw_jwt, host, organization, permissions, repositories, allowed_hosts)
    issuer = jwt_verifier.extract_issuer(raw_jwt)

    repo_name = '.github-oidc' if host == 'github.com' else '.github'
    repo_url = f'{host}/{organization}/{repo_name}'

    credential = github_api.find_credential(repo_url, credentials)
    if credential is None:
        raise aiohttp.web.HTTPForbidden(
            reason=f'The host {host} and org {organization} are not supported',
        )

    return models.TokenRequest(
        raw_jwt=raw_jwt,
        host=host,
        organization=organization,
        permissions=permissions,
        requested_repositories=repositories,
        issuer=issuer,
        repo_url=repo_url,
        credential=credential,
    )


def _validate_request(
    raw_jwt: str | None,
    host: str | None,
    organization: str | None,
    permissions: dict | None,
    repositories: list | None,
    allowed_hosts: set[str],
) -> None:
    if not raw_jwt:
        raise aiohttp.web.HTTPBadRequest(reason='Missing token property')

    if not host:
        raise aiohttp.web.HTTPBadRequest(reason='Missing host property')

    if host not in allowed_hosts:
        raise aiohttp.web.HTTPForbidden(reason=f'The host {host} is not supported')

    if not organization:
        raise aiohttp.web.HTTPBadRequest(reason='Missing organization property')

    if not permissions or not isinstance(permissions, dict):
        raise aiohttp.web.HTTPBadRequest(
            reason='Permissions property must be an object with permission and permission level',
        )

    if repositories and not isinstance(repositories, list):
        raise aiohttp.web.HTTPBadRequest(
            reason='Repositories property must be an array of strings',
        )

    if repositories and any(not _REPOSITORY_PATTERN.fullmatch(r) for r in repositories):
        raise aiohttp.web.HTTPBadRequest(
            reason=f'The repositories {repositories} are not supported',
        )


def _is_request_authorized(
    token_request: models.TokenRequest,
    entry: models.OidcFederationEntry,
) -> bool:
    return (
        _check_matching_repositories(token_request, entry)
        and _check_permissions(token_request, entry)
        and _check_org_permissions_without_repository_scope(token_request)
    )


def _check_matching_repositories(
    token_request: models.TokenRequest,
    entry: models.OidcFederationEntry,
) -> bool:
    if entry.repositories:
        if not token_request.requested_repositories:
            logger.warning(
                'entry specifies repositories but request does not specify any repositories',
            )
            return False

        requested_repositories_match_entry_repositories = all(
            repository in entry.repositories for repository in token_request.requested_repositories
        )
        if not requested_repositories_match_entry_repositories:
            logger.warning('request repositories do not match entry repositories')
            return False
    return True


def _check_permissions(
    token_request: models.TokenRequest,
    entry: models.OidcFederationEntry,
) -> bool:
    for permission, requested_level in token_request.permissions.items():
        allowed_level = entry.permissions.get(permission)

        if not allowed_level or allowed_level < models.PermissionLevel(requested_level):
            logger.warning(
                f'Request {requested_level} permissions do not match entry {allowed_level} '
                f'permissions for {permission}',
            )
            return False
    return True


def _check_org_permissions_without_repository_scope(
    token_request: models.TokenRequest,
) -> bool:
    if token_request.requested_repositories and any(
        permission.startswith('organization') for permission in token_request.permissions
    ):
        logger.warning(
            'Organization level permissions are only allowed if they are not restricted to '
            'a repository',
        )
        return False
    return True
