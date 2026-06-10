import enum
import logging

import aiohttp.web
import cachetools
import dacite
import yaml

from .github_api import fetch_raw_oidc_config
from .models import OidcFederationEntry, TokenRequest


logger = logging.getLogger(__name__)


@cachetools.cached(cache=cachetools.TTLCache(maxsize=32768, ttl=60*15)) # 15min
def retrieve_oidc_federation_config(token_request: TokenRequest) -> list[OidcFederationEntry]:
    logger.info(f'Fetching oidc-federation-config for {token_request.repo_url}')
    oidc_federation_raw = fetch_raw_oidc_config(token_request)
    oidc_federation_config = _parse_raw_oidc_config(oidc_federation_raw)

    allowed_issuers = {entry.issuer for entry in oidc_federation_config}
    if token_request.issuer not in allowed_issuers:
        raise aiohttp.web.HTTPUnauthorized(reason=f'The issuer {token_request.issuer} is not supported')

    return oidc_federation_config


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
        )
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
            ) for oidc_federation_entry in yaml.safe_load(oidc_federation_raw)
        ]
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to parse oidc-federation cfg',
        )
    return oidc_federation_config
