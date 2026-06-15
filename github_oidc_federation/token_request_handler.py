import logging
import re

import aiohttp.web

from .github_api import find_credential, fetch_installation_token
from .jwt_verifier import extract_issuer, verify_jwt
from .models import OidcFederationEntry, PermissionLevel, TokenRequest
from .oidc_config import retrieve_oidc_federation_config, find_matching_entry


logger = logging.getLogger(__name__)

_REPOSITORY_PATTERN = re.compile(r'^[A-Za-z0-9._-]+$')

ALLOWED_HOSTS: set[str] = set()


async def request_token(request: aiohttp.web.Request) -> aiohttp.web.Response:
    body = await request.json()
    token_request: TokenRequest = _resolve_request(body)
    oidc_federation_config = await retrieve_oidc_federation_config(token_request)

    claims = await verify_jwt(token_request.jwt, token_request.issuer)

    oidc_federation_config_entry = find_matching_entry(token_request, oidc_federation_config, claims)
    if not _is_request_authorized(token_request, oidc_federation_config_entry):
        raise aiohttp.web.HTTPUnauthorized(
            reason=(
                'The requested scope and/or permissions are not granted in the oidc-federation '
                f'cfg in "{token_request.repo_url}". Access not allowed'
            ),
        )

    result = await fetch_installation_token(token_request, claims['sub'])
    return aiohttp.web.json_response(result)


def _resolve_request(body: dict) -> TokenRequest:
    token = body.get('token')
    host = body.get('host')
    organization = body.get('organization')
    permissions = body.get('permissions')
    repositories = body.get('repositories')

    _validate_request(token, host, organization, permissions, repositories)
    issuer = extract_issuer(token)

    repo_name = '.github-oidc' if host == 'github.com' else '.github'
    repo_url = f'{host}/{organization}/{repo_name}'

    try:
        credential = find_credential(repo_url)
    except aiohttp.web.HTTPInternalServerError:
        raise aiohttp.web.HTTPUnauthorized(
            reason=f'The host {host} and org {organization} are not supported',
        )

    return TokenRequest(
        jwt=token,
        host=host,
        organization=organization,
        permissions=permissions,
        requested_repositories=repositories,
        issuer=issuer,
        repo_url=repo_url,
        credential=credential,
    )


def _validate_request(token, host, organization, permissions, repositories):
    if not token:
        raise aiohttp.web.HTTPBadRequest(reason='Missing token property')

    if not host:
        raise aiohttp.web.HTTPBadRequest(reason='Missing host property')

    if host not in ALLOWED_HOSTS:
        raise aiohttp.web.HTTPUnauthorized(reason=f'The host {host} is not supported')

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
        raise aiohttp.web.HTTPUnauthorized(
            reason=f'The repositories {repositories} are not supported',
        )


def _is_request_authorized(
    token_request: TokenRequest,
    entry: OidcFederationEntry,
) -> bool:
    return (
        _check_matching_repositories(token_request, entry)
        and _check_permissions(token_request, entry)
        and _check_no_org_permissions_with_repositories(token_request)
    )


def _check_matching_repositories(
    token_request: TokenRequest,
    entry: OidcFederationEntry,
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
    token_request: TokenRequest,
    entry: OidcFederationEntry,
) -> bool:
    for permission, requested_level in token_request.permissions.items():
        allowed_level = entry.permissions.get(permission)

        if not allowed_level or allowed_level < PermissionLevel(requested_level):
            logger.warning(
                f'Request {requested_level} permissions do not match entry {allowed_level} '
                f'permissions for {permission}',
            )
            return False
    return True


def _check_no_org_permissions_with_repositories(
    token_request: TokenRequest,
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
