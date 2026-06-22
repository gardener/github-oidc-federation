import json
import logging

import aiohttp


logger = logging.getLogger(__name__)

SESSION: aiohttp.ClientSession | None = None


async def fetch_with_retries(
    url: str,
    json_body: dict | None = None,
    data: dict | None = None,
    headers: dict | None = None,
    retries: int = 3,
) -> '_Response':
    if SESSION is None:
        raise RuntimeError('http_client.SESSION not initialised')
    method = 'POST' if (json_body is not None or data is not None) else 'GET'
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            async with SESSION.request(
                method=method,
                url=url,
                json=json_body,
                data=data,
                headers=headers,
            ) as response:
                if response.ok:
                    body = await response.read()
                    return _Response(response.status, body)
                logger.warning(
                    f'rq against {url=} failed: status={response.status} reason={response.reason}',
                )
                last_exc = aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=response.reason,
                )
                continue
        except Exception as e:
            logger.warning(f'rq against {url=} failed: {e}')
            last_exc = e
            if attempt == retries:
                raise

        if attempt < retries:
            logger.warning(f'Retrying... ({retries - attempt} left)')

    raise last_exc


class _Response:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body
        self.ok = status < 400

    def to_json(self) -> dict:
        return json.loads(self._body)
