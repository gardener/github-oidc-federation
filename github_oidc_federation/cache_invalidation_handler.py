import asyncio
import hashlib
import hmac
import json
import logging
import os
import ssl

import aiohttp
import aiohttp.web

import github_oidc_federation.http_client as http_client
import github_oidc_federation.oidc_config as oidc_config

logger = logging.getLogger(__name__)

_OIDC_CONFIG_FILENAME = 'oidc-federation.yaml'

_SIGNATURE_HEADER = 'X-Hub-Signature-256'

# Fixed body sibling pods POST when broadcasting an invalidation to each other.
# It is signed with the webhook secret like any other request — the
# `X-Internal-Broadcast` header is only a routing hint (skip re-broadcast) and
# carries no trust on its own.
_INTERNAL_BROADCAST_BODY = b'{"internal":true}'


def _is_valid_signature(secret: str, raw_body: bytes, signature_header: str | None) -> bool:
    """
    Verify a GitHub-style ``X-Hub-Signature-256`` HMAC-SHA256 over the raw request
    body. Returns False on a missing/malformed header or a mismatching digest.
    """
    if not signature_header or not signature_header.startswith('sha256='):
        return False
    expected = hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    received = signature_header.removeprefix('sha256=')
    return hmac.compare_digest(expected, received)


def sign_body(secret: str, raw_body: bytes) -> str:
    """Produce the ``X-Hub-Signature-256`` header value for ``raw_body``."""
    digest = hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    return f'sha256={digest}'


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


async def _invalidate_sibling(ip: str, webhook_secret: str) -> None:
    try:
        await http_client.fetch_with_retries(
            url=f'http://{ip}:3000/invalidate-cache',
            method='POST',
            data=_INTERNAL_BROADCAST_BODY,
            headers={
                'X-Internal-Broadcast': 'true',
                _SIGNATURE_HEADER: sign_body(webhook_secret, _INTERNAL_BROADCAST_BODY),
            },
            retries=0,
            timeout=5,
        )
        logger.info(f'Broadcast cache invalidation to pod {ip}')
    except Exception:
        logger.exception(f'Failed to broadcast cache invalidation to pod {ip}')


async def _broadcast_to_siblings(namespace: str, sa_token: str, webhook_secret: str) -> None:
    ips = await _get_sibling_pod_ips(namespace, sa_token)
    await asyncio.gather(*(_invalidate_sibling(ip, webhook_secret) for ip in ips))


def _push_affects_oidc_config(payload: dict) -> bool:
    for commit in payload.get('commits', []):
        changed = commit.get('added', []) + commit.get('modified', []) + commit.get('removed', [])
        if any(_OIDC_CONFIG_FILENAME in f for f in changed):
            return True
    return False


async def invalidate_cache(request: aiohttp.web.Request) -> aiohttp.web.Response:
    webhook_secret: str | None = request.app['webhook_secret']
    raw_body = await request.read()

    # Authenticate every caller via the webhook HMAC. The `X-Internal-Broadcast`
    # header is a forgeable routing hint and is NOT trusted for authentication —
    # sibling broadcasts sign their body too. Fail closed if no secret is
    # configured or the signature is missing/invalid.
    if not webhook_secret:
        logger.warning('webhook secret not configured — rejecting /invalidate-cache request')
        return aiohttp.web.Response(status=401)

    if not _is_valid_signature(
        webhook_secret,
        raw_body,
        request.headers.get(_SIGNATURE_HEADER),
    ):
        logger.warning('invalid or missing signature on /invalidate-cache request')
        return aiohttp.web.Response(status=401)

    is_internal = request.headers.get('X-Internal-Broadcast') == 'true'

    if not is_internal and raw_body:
        try:
            payload = json.loads(raw_body)
            if not _push_affects_oidc_config(payload):
                return aiohttp.web.Response(status=204)
        except Exception:
            # body is authenticated (HMAC verified) but unparseable. we cannot
            # confirm whether it touches the config, so clear the cache rather
            # than drop a potentially legitimate invalidation
            logger.exception('Failed to parse webhook payload — proceeding with cache invalidation')

    if not is_internal:
        sa_token: str | None = request.app['k8s_sa_token']
        namespace: str | None = request.app['k8s_namespace']
        if sa_token and namespace:
            try:
                await _broadcast_to_siblings(namespace, sa_token, webhook_secret)
            except Exception:
                logger.exception('Failed to broadcast cache invalidation to siblings')
        else:
            logger.warning('K8s service account not available — skipping cache broadcast')

    oidc_config.clear_config_cache()
    logger.info('OIDC config cache cleared')

    return aiohttp.web.Response(status=204)
