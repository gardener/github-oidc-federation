import logging

import aiohttp.web
import jwt
import jwt.algorithms
from async_lru import alru_cache
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .http_client import fetch_with_retries


logger = logging.getLogger(__name__)

EXPECTED_AUDIENCE: str | None = None


def extract_issuer(token: str) -> str:
    decoded_jwt = jwt.decode(jwt=token, options={'verify_signature': False})
    issuer = decoded_jwt.get('iss')
    if not issuer:
        raise aiohttp.web.HTTPBadRequest(reason='Missing issuer in token')
    return issuer


async def verify_jwt(token: str, issuer: str) -> dict:
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get('kid')
    public_key = await _fetch_public_key(issuer, kid)

    try:
        claims = jwt.decode(
            jwt=token,
            key=public_key,
            algorithms=['RS256'],
            audience=EXPECTED_AUDIENCE,
            issuer=issuer,
        )
    except Exception as e:
        logger.error(e)
        raise aiohttp.web.HTTPUnauthorized(reason='Token verification failed')

    if not claims.get('sub'):
        raise aiohttp.web.HTTPBadRequest(reason='Missing sub claim in token')

    return claims


@alru_cache(maxsize=2048, ttl=60 * 60 * 24)
async def _fetch_public_key(issuer: str, kid: str) -> RSAPublicKey:
    try:
        openid_configuration_response = await fetch_with_retries(
            url=f'{issuer}/.well-known/openid-configuration',
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
        jwks_res = await fetch_with_retries(url=jwks_uri)
    except Exception:
        raise aiohttp.web.HTTPInternalServerError(
            reason='Failed to fetch issuer openid-configuration',
        )

    for jwk in jwks_res.to_json().get('keys', []):
        if jwk.get('kid') == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

    raise aiohttp.web.HTTPUnauthorized(reason='Token verification failed')
