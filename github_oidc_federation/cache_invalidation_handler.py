import asyncio
import logging
import os
import ssl

import aiohttp
import aiohttp.web

import github_oidc_federation.http_client as http_client
import github_oidc_federation.oidc_config as oidc_config

logger = logging.getLogger(__name__)

_K8S_SA_BASE_PATH = '/var/run/secrets/kubernetes.io/serviceaccount'
K8S_SA_TOKEN_PATH = f'{_K8S_SA_BASE_PATH}/token'
K8S_SA_NAMESPACE_PATH = f'{_K8S_SA_BASE_PATH}/namespace'
_K8S_SA_CA_PATH = f'{_K8S_SA_BASE_PATH}/ca.crt'


async def _get_sibling_pod_ips(namespace: str, sa_token: str) -> list[str]:
    own_ip = os.environ.get('POD_IP', '')
    ssl_ctx = ssl.create_default_context(cafile=_K8S_SA_CA_PATH)
    url = (
        f'https://kubernetes.default.svc/api/v1/namespaces/{namespace}'
        f'/pods?labelSelector=role%3Dgithub-oidc-federation'
    )
    if http_client.SESSION is None:
        raise RuntimeError('http_client.SESSION not initialised')
    session = http_client.SESSION
    async with session.get(
        url,
        headers={'Authorization': f'Bearer {sa_token}'},
        ssl=ssl_ctx,
        timeout=aiohttp.ClientTimeout(total=5),
    ) as resp:
        data = await resp.json()
    return [
        item['status']['podIP']
        for item in data.get('items', [])
        if item.get('status', {}).get('podIP') and item['status']['podIP'] != own_ip
    ]


async def _invalidate_sibling(ip: str) -> None:
    try:
        await http_client.fetch_with_retries(
            url=f'http://{ip}:3000/invalidate-cache',
            method='POST',
            headers={'X-Internal-Broadcast': 'true'},
            retries=0,
            timeout=5,
        )
        logger.info(f'Broadcast cache invalidation to pod {ip}')
    except Exception:
        logger.exception(f'Failed to broadcast cache invalidation to pod {ip}')


async def _broadcast_to_siblings(namespace: str, sa_token: str) -> None:
    ips = await _get_sibling_pod_ips(namespace, sa_token)
    await asyncio.gather(*(_invalidate_sibling(ip) for ip in ips))


async def invalidate_cache(request: aiohttp.web.Request) -> aiohttp.web.Response:
    is_internal = request.headers.get('X-Internal-Broadcast') == 'true'

    if not is_internal:
        sa_token: str | None = request.app['k8s_sa_token']
        namespace: str | None = request.app['k8s_namespace']
        if sa_token and namespace:
            try:
                await _broadcast_to_siblings(namespace, sa_token)
            except Exception:
                logger.exception('Failed to broadcast cache invalidation to siblings')
        else:
            logger.warning('K8s service account not available — skipping cache broadcast')

    oidc_config.clear_config_cache()
    logger.info('OIDC config cache cleared')

    return aiohttp.web.Response(status=204)
