import logging

import requests


logger = logging.getLogger(__name__)

SESSION: requests.Session | None = None


def fetch_with_retries(
    url: str,
    json: dict | None = None,
    data: dict | None = None,
    headers: dict | None = None,
    retries: int = 3,
) -> requests.Response:
    method = "POST" if (json or data) else "GET"
    for attempt in range(retries + 1):
        try:
            res = SESSION.request(method=method, url=url, json=json, data=data, headers=headers)
            if res.ok:
                return res
            logger.warning(
                f"rq against {url=} failed: {res.status_code=} {res.reason=} {res.content=}"
            )
        except Exception as e:
            logger.warning(f"rq against {url=} failed: {e}")
            if attempt == retries:
                raise

        if attempt < retries:
            logger.warning(f"Retrying... ({retries - attempt} left)")

    res.raise_for_status()
