import datetime
import logging

import aiohttp.web
import jwt
import jwt.algorithms
import async_lru

import github_oidc_federation.http_client as http_client


logger = logging.getLogger(__name__)


def extract_issuer(raw_jwt: str) -> str:
    decoded_jwt = jwt.decode(jwt=raw_jwt, options={'verify_signature': False})
    issuer = decoded_jwt.get('iss')
    if not issuer:
        raise aiohttp.web.HTTPBadRequest(reason='Missing issuer in token')
    return issuer


async def verify_jwt(raw_jwt: str, issuer: str, audience: str) -> dict:
    unverified_header = jwt.get_unverified_header(raw_jwt)
    kid = unverified_header.get('kid')
    public_key = await _fetch_public_key(issuer, kid)

    try:
        claims = jwt.decode(
            jwt=raw_jwt,
            key=public_key,
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer,
            leeway=datetime.timedelta(seconds=10),
        )
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPUnauthorized(reason='Token verification failed')

    if not claims.get('sub'):
        raise aiohttp.web.HTTPBadRequest(reason='Missing sub claim in token')

    return claims


@async_lru.alru_cache(maxsize=2048, ttl=60 * 60 * 24)  # 24 hours
async def _fetch_public_key(issuer: str, kid: str):
    try:
        openid_configuration_response = await http_client.fetch_with_retries(
            url=f'{issuer}/.well-known/openid-configuration',
            method='GET',
        )
    except Exception:
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to fetch issuer openid-configuration',
        )

    if not (jwks_uri := openid_configuration_response.to_json().get('jwks_uri')):
        raise aiohttp.web.HTTPBadRequest(
            reason='Missing jwks_uri in issuer openid-configuration',
        )

    try:
        jwks_res = await http_client.fetch_with_retries(url=jwks_uri, method='GET')
    except Exception:
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to fetch issuer JWKS',
        )

    for jwk in jwks_res.to_json().get('keys', []):
        if jwk.get('kid') == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

    raise aiohttp.web.HTTPUnauthorized(reason='Token verification failed')
