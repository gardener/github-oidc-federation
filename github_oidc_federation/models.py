import dataclasses
import enum
import functools

import github


@functools.total_ordering
class PermissionLevel(enum.StrEnum):
    READ = 'read'
    WRITE = 'write'
    ADMIN = 'admin'

    def __lt__(self, other: 'PermissionLevel') -> bool:
        order = list(PermissionLevel)
        return order.index(self) < order.index(other)


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
    jwt: str
    host: str
    organization: str
    permissions: dict[str, str]
    requested_repositories: list[str] | None
    issuer: str
    repo_url: str
    credential: github.GitHubAppCredentials
