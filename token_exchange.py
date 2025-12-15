import collections.abc
import dataclasses
import enum
import functools
import logging

import dacite
import falcon
import github3
import github3.apps
import github3.exceptions
import jwt
import jwt.algorithms
import requests
import yaml

import github


logger = logging.getLogger(__name__)


class PermissionLevel(enum.StrEnum):
    READ = 'read'
    WRITE = 'write'
    ADMIN = 'admin'

    @staticmethod
    def is_allowed(
        requested: str,
        allowed: str | None,
    ) -> bool:
        permission_level_to_weights = {
            PermissionLevel.READ: 1,
            PermissionLevel.WRITE: 2,
            PermissionLevel.ADMIN: 3,
        }

        if (
            requested not in permission_level_to_weights
            or not allowed
        ):
            return False

        return permission_level_to_weights[requested] <= permission_level_to_weights[allowed]


@dataclasses.dataclass
class OidcFederation:
    issuer: str
    subject: str
    permissions: dict[str, PermissionLevel]
    repositories: list[str] | None


def fetch_with_retries(
    url: str,
    session: requests.Session,
    method: str='GET',
    json: dict | None=None,
    data: dict | None=None,
    headers: dict | None=None,
    remaining_retries: int=3,
) -> requests.Response:
    res = session.request(
        method=method,
        url=url,
        json=json,
        data=data,
        headers=headers,
    )

    if not res.ok:
        logger.warning(f'rq against {url=} failed: {res.status_code=} {res.reason=} {res.content=}')

        if remaining_retries > 0:
            logger.warning(f'Retrying... ({remaining_retries=})')
            return fetch_with_retries(
                url=url,
                session=session,
                method=method,
                json=json,
                data=data,
                headers=headers,
                remaining_retries=remaining_retries - 1,
            )

    res.raise_for_status()

    return res


def github_host_to_api_url(host: str) -> str:
    if host == 'github.com':
        return f'https://api.{host}'

    return f'https://{host}/api/v3'


@functools.cache
def installation_id_for_org(
    organization: str,
    github_api: github3.GitHub,
    private_key: bytes,
    app_id: int,
) -> int:
    github_api.login_as_app(
        private_key_pem=private_key,
        app_id=app_id,
    )

    installation = github_api.app_installation_for_organization(organization)

    return installation.id


class TokenExchange:
    def __init__(
        self,
        github_app_credentials: collections.abc.Sequence[github.GitHubAppCredentials],
        expected_audience: str,
    ):
        self._github_app_credentials = github_app_credentials
        self._github_api_lookup = github.github_app_api_lookup(github_app_credentials)
        self._expected_audience = expected_audience
        self._session = requests.Session()

    def on_post(
        self,
        req: falcon.Request,
        resp: falcon.Response,
    ):
        body = req.get_media()

        logger.info(body)

        if not (token := body.get('token')):
            raise falcon.HTTPBadRequest(
                description='Missing token property',
            )

        if not (host := body.get('host')):
            raise falcon.HTTPBadRequest(
                description='Missing host property',
            )

        if not (organization := body.get('organization')):
            raise falcon.HTTPBadRequest(
                description='Missing organization property',
            )

        if (
            not (permissions := body.get('permissions'))
            or not isinstance(permissions, dict)
        ):
            raise falcon.HTTPBadRequest(
                description=(
                    'Permissions property must be an object with permission and permission level'
                ),
            )

        if (
            (repositories := body.get('repositories'))
            and not isinstance(repositories, list)
        ):
            raise falcon.HTTPBadRequest(
                description='Repositories property must be an array of strings',
            )

        decoded_jwt = jwt.decode(
            jwt=token,
            options={
                'verify_signature': False, # we don't know the public key yet
            },
        )

        if not (issuer := decoded_jwt.get('iss')):
            raise falcon.HTTPBadRequest(
                description='Missing issuer in token',
            )

        try:
            openid_cfg_res = fetch_with_retries(
                url=f'{issuer}/.well-known/openid-configuration',
                session=self._session,
            )
        except Exception:
            raise falcon.HTTPInternalServerError(
                description='Failed to fetch issuer openid-configuration',
            )

        if not (jwks_uri := openid_cfg_res.json().get('jwks_uri')):
            raise falcon.HTTPBadRequest(
                description='Missing jwks_uri in issuer openid-configuration',
            )

        try:
            jwks_res = fetch_with_retries(
                url=jwks_uri,
                session=self._session,
            )
        except Exception:
            raise falcon.HTTPInternalServerError(
                description='Failed to fetch issuer openid-configuration',
            )

        header = jwt.get_unverified_header(token)
        logger.info(header)

        kid = header.get('kid')

        for jwk in jwks_res.json().get('keys', []):
            if jwk.get('kid') != kid:
                continue

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            break
        else:
            raise falcon.HTTPUnauthorized(
                description='Token verification failed',
            )

        try:
            payload = jwt.decode(
                jwt=token,
                key=public_key,
                algorithms=['RS256'],
                audience=self._expected_audience,
                issuer=issuer,
            )
        except Exception as e:
            logger.error(e)
            raise falcon.HTTPUnauthorized(
                description='Token verification failed',
            )

        logger.info(payload)

        if not (sub := payload.get('sub')):
            raise falcon.HTTPBadRequest(
                description='Missing sub claim in token',
            )

        repo_url = f'https://{host}/{organization}/.github'
        logger.info(f'Fetching oidc-federation cfg for {repo_url}')

        try:
            github_api = self._github_api_lookup(repo_url)
            repo = github_api.repository(organization, '.github')

            try:
                oidc_federation_raw = repo.file_contents('oidc-federation.yaml').decoded.decode()
            except github3.exceptions.NotFoundError:
                oidc_federation_raw = repo.file_contents('oidc-federation.json').decoded.decode()
        except Exception as e:
            logger.error(e)
            raise falcon.HTTPInternalServerError(
                description='Failed to fetch oidc-federation cfg',
            )

        logger.info(oidc_federation_raw)

        try:
            oidc_federation = [
                dacite.from_dict(
                    data_class=OidcFederation,
                    data=oidc_federation_entry,
                    config=dacite.Config(
                        cast=[enum.Enum],
                    ),
                ) for oidc_federation_entry in yaml.safe_load(oidc_federation_raw)
            ]
        except Exception as e:
            logger.error(e)
            raise falcon.HTTPInternalServerError(
                description='Failed to parse oidc-federation cfg',
            )

        for oidc_federation_entry in oidc_federation:
            if oidc_federation_entry.issuer != issuer:
                continue

            if oidc_federation_entry.subject != sub:
                continue

            logger.info('Found matching entry in oidc-federation cfg')

            if oidc_federation_entry.repositories is not None:
                if not repositories:
                    logger.warning(
                        'entry specifies repository restrictions, but none are provided in request'
                    )
                    continue

                if not all(
                    repository in oidc_federation_entry.repositories
                    for repository in repositories
                ):
                    logger.warning('request repositories do not match entry repositories')
                    continue

            is_allowed = True
            if oidc_federation_entry.permissions:
                for permission, level in permissions.items():
                    allowed_level = oidc_federation_entry.permissions.get(permission)

                    if not PermissionLevel.is_allowed(
                        requested=level,
                        allowed=allowed_level,
                    ):
                        logger.warning(
                            f'Request {level} permissions do not match entry {allowed_level} '
                            f'permissions for {permission}'
                        )
                        is_allowed = False

            if repositories and any(
                permission.startswith('organization')
                for permission in permissions.keys()
            ):
                logger.warning(
                    'Organization level permissions are only allowed if they are not restricted to '
                    'a repository'
                )
                is_allowed = False

            if not is_allowed:
                continue

            break # found matching entry
        else:
            raise falcon.HTTPUnauthorized(
                description='No matching entry in oidc-federation cfg. Access not allowed',
            )

        for github_app_credential in self._github_app_credentials:
            if github_app_credential.matches(repo_url):
                break
        else:
            raise falcon.HTTPInternalServerError(
                description=f'No matching GitHub App credentials for {repo_url}',
            )

        jwt_token = github3.apps.create_token(
            private_key_pem=github_app_credential.private_key.encode(),
            app_id=github_app_credential.app_id,
        )

        installation_id = installation_id_for_org(
            organization=organization,
            github_api=github_api,
            private_key=github_app_credential.private_key.encode(),
            app_id=github_app_credential.app_id,
        )

        api_url = github_host_to_api_url(host)

        token_res = fetch_with_retries(
            url=f'{api_url}/app/installations/{installation_id}/access_tokens',
            session=self._session,
            method='POST',
            headers={
                'Authorization': f'Bearer {jwt_token}',
                'User-Agent': f'github-oidc-federation: {issuer}:{sub}',
            },
            json={
                'repositories': repositories,
                'permissions': dict(
                    (permission.replace('-', '_'), level)
                    for permission, level in permissions.items()
                ),
            }
        )

        resp.media = token_res.json()
