import collections.abc
import enum
import logging

import aiohttp.web
import dacite
import yaml
import async_lru

import github_oidc_federation.github_api as github_api
import github_oidc_federation.models as models

logger = logging.getLogger(__name__)


async def retrieve_oidc_federation_config(
    token_request: models.TokenRequest,
    credentials: collections.abc.Sequence[models.GitHubAppCredentials],
) -> list[models.OidcFederationEntry]:
    credential = github_api.find_credential(token_request.repo_url, credentials)
    if credential is None:
        raise aiohttp.web.HTTPInternalServerError(
            reason=f'No matching GitHub App credentials for {token_request.repo_url}',
        )
    oidc_federation_config = await _fetch_and_parse_oidc_config(
        token_request.repo_url,
        token_request.host,
        credential,
    )

    allowed_issuers = {entry.issuer for entry in oidc_federation_config}
    if token_request.issuer not in allowed_issuers:
        raise aiohttp.web.HTTPForbidden(
            reason=f'The issuer {token_request.issuer} is not supported',
        )

    return oidc_federation_config


@async_lru.alru_cache(maxsize=32768, ttl=60 * 15)  # 15 minutes
async def _fetch_and_parse_oidc_config(
    repo_url: str,
    host: str,
    credential: models.GitHubAppCredentials,
) -> list[models.OidcFederationEntry]:
    logger.info(f'Fetching oidc-federation-config for {repo_url}')
    raw = await github_api.fetch_raw_oidc_config(repo_url, host, credential)
    return _parse_raw_oidc_config(raw)


def clear_config_cache() -> None:
    _fetch_and_parse_oidc_config.cache_clear()


def find_matching_entry(
    token_request: models.TokenRequest,
    oidc_federation_config: list[models.OidcFederationEntry],
    claims: dict,
    is_authorized: collections.abc.Callable[
        ['models.TokenRequest', 'models.OidcFederationEntry'], bool
    ],
) -> models.OidcFederationEntry:
    claims_matched = False
    for entry in oidc_federation_config:
        if entry.issuer == token_request.issuer and _entry_matches_claims(entry, claims):
            claims_matched = True
            if is_authorized(token_request, entry):
                return entry
    if claims_matched:
        raise aiohttp.web.HTTPForbidden(
            reason=(
                'The requested scope and/or permissions are not granted in the oidc-federation '
                f'cfg in "{token_request.repo_url}". Access not allowed'
            ),
        )
    raise aiohttp.web.HTTPForbidden(
        reason=(
            f'No matching entry found in the oidc-federation cfg in "{token_request.repo_url}". '
            'Access not allowed'
        ),
    )


def _entry_matches_claims(entry: models.OidcFederationEntry, claims: dict) -> bool:
    if entry.subject and entry.subject != claims.get('sub'):
        return False

    if entry.principals:
        return any(principal.items() <= claims.items() for principal in entry.principals)
    return True


def _parse_raw_oidc_config(oidc_federation_raw: str) -> list[models.OidcFederationEntry]:
    try:
        oidc_federation_config = [
            dacite.from_dict(
                data_class=models.OidcFederationEntry,
                data=oidc_federation_entry,
                config=dacite.Config(cast=[enum.Enum]),
            )
            for oidc_federation_entry in yaml.safe_load(oidc_federation_raw)
        ]
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to parse oidc-federation cfg',
        )
    return oidc_federation_config
