import enum
import logging

import aiohttp.web
import dacite
import yaml
from async_lru import alru_cache

from .github_api import fetch_raw_oidc_config, find_credential
from .models import OidcFederationEntry, TokenRequest


logger = logging.getLogger(__name__)


async def retrieve_oidc_federation_config(
    token_request: TokenRequest,
) -> list[OidcFederationEntry]:
    oidc_federation_config = await _fetch_and_parse_oidc_config(
        token_request.repo_url,
        token_request.host,
    )

    allowed_issuers = {entry.issuer for entry in oidc_federation_config}
    if token_request.issuer not in allowed_issuers:
        raise aiohttp.web.HTTPUnauthorized(
            reason=f'The issuer {token_request.issuer} is not supported',
        )

    return oidc_federation_config


@alru_cache(maxsize=32768, ttl=60 * 15)
async def _fetch_and_parse_oidc_config(
    repo_url: str,
    host: str,
) -> list[OidcFederationEntry]:
    logger.info(f'Fetching oidc-federation-config for {repo_url}')
    credential = find_credential(repo_url)
    raw = await fetch_raw_oidc_config(repo_url, host, credential)
    return _parse_raw_oidc_config(raw)


def find_matching_entry(
    token_request: TokenRequest,
    oidc_federation_config: list[OidcFederationEntry],
    claims: dict,
) -> OidcFederationEntry:
    for entry in oidc_federation_config:
        if entry.issuer == token_request.issuer and _entry_matches_claims(entry, claims):
            return entry
    raise aiohttp.web.HTTPUnauthorized(
        reason=(
            f'No entry found in the oidc-federation cfg in "{token_request.repo_url}". '
            'Access not allowed'
        ),
    )


def _entry_matches_claims(entry: OidcFederationEntry, claims: dict) -> bool:
    if entry.subject and entry.subject != claims.get('sub'):
        return False

    if entry.principals:
        return any(principal.items() <= claims.items() for principal in entry.principals)
    return True


def _parse_raw_oidc_config(oidc_federation_raw: str) -> list[OidcFederationEntry]:
    try:
        oidc_federation_config = [
            dacite.from_dict(
                data_class=OidcFederationEntry,
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
