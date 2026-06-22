import dataclasses
import enum
import functools
import typing


@functools.total_ordering
class PermissionLevel(enum.StrEnum):
    READ = 'read'
    WRITE = 'write'
    ADMIN = 'admin'

    _ORDER = enum.nonmember([READ, WRITE, ADMIN])

    def __lt__(self, other: 'PermissionLevel') -> bool:
        return self._ORDER.index(self) < self._ORDER.index(other)


class GitHubAppSelector(typing.NamedTuple):
    org: str
    repos: tuple[str, ...] | None = None


@dataclasses.dataclass(frozen=True)
class GitHubAppCredentials:
    private_key: str
    app_id: int
    host: str
    selectors: tuple[GitHubAppSelector, ...] | None = None

    def matches(self, repo_url: str) -> bool:
        host, org, repo = get_host_org_and_repo_from_url(repo_url)
        if self.selectors is None:
            return self.host == host
        return any(
            selector.org == org and (selector.repos is None or repo in selector.repos)
            for selector in self.selectors
        )


@dataclasses.dataclass
class OidcFederationEntry:
    issuer: str
    subject: str | None
    permissions: dict[str, PermissionLevel]
    repositories: list[str] | None
    principals: list[dict[str, str]] | None

    def __post_init__(self):
        if not self.subject and not self.principals:
            raise ValueError('Either subject or principals must be specified')
        if self.permissions and None in self.permissions.values():
            raise ValueError('Permission levels must not be None')


@dataclasses.dataclass(eq=False)
class TokenRequest:
    raw_jwt: str
    host: str
    organization: str
    permissions: dict[str, str]
    requested_repositories: list[str] | None
    issuer: str
    repo_url: str
    credential: GitHubAppCredentials


def get_host_org_and_repo_from_url(repo_url: str) -> tuple[str, str, str]:
    if '://' in repo_url:
        repo_url = repo_url.split('://')[-1]
    host, org, repo = repo_url.strip('/').split('/')
    return host, org, repo
