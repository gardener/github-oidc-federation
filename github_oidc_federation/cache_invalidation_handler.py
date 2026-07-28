import logging

import aiohttp.web

import github_oidc_federation.jwt_verifier as jwt_verifier
import github_oidc_federation.oidc_config as oidc_config

logger = logging.getLogger(__name__)


async def invalidate_cache(request: aiohttp.web.Request) -> aiohttp.web.Response:
    audience: str = request.app['expected_audience']

    authorization = request.headers.get('Authorization', '')
    if not authorization.startswith('Bearer '):
        raise aiohttp.web.HTTPUnauthorized(reason='Missing or invalid Authorization header')

    raw_jwt = authorization.removeprefix('Bearer ')
    issuer = jwt_verifier.extract_issuer(raw_jwt)
    await jwt_verifier.verify_jwt(raw_jwt, issuer, audience)

    oidc_config.clear_config_cache()
    logger.info('OIDC config cache cleared')

    return aiohttp.web.Response(status=204)
