#!/usr/bin/env python3

import argparse
import collections.abc
import os

import bjoern
import dacite
import falcon
import yaml

import ci.log
import github

import token_exchange


ci.log.configure_default_logging()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--productive', action='store_true', default=False)
    parser.add_argument('--port', default=3000, type=int)
    parser.add_argument('--github-app-credentials-path', default='/secrets')
    parser.add_argument('--expected-audience', default='github-oidc-federation')

    return parser.parse_args()


def iter_github_app_credentials(
    github_app_credentials_path: str,
) -> collections.abc.Iterable[github.GitHubAppCredentials]:
    for github_app_credential_name in os.listdir(github_app_credentials_path):
        github_app_credential_path = os.path.join(
            github_app_credentials_path,
            github_app_credential_name,
        )

        if not os.path.isfile(github_app_credential_path):
            continue

        with open(github_app_credential_path) as f:
            github_app_credential_raw = yaml.safe_load(f)

        yield dacite.from_dict(
            data_class=github.GitHubAppCredentials,
            data=github_app_credential_raw,
        )


def run_app():
    parsed_arguments = parse_args()

    host = '0.0.0.0' if parsed_arguments.productive else 'localhost'
    port = parsed_arguments.port

    middleware = None

    app = falcon.App(
        middleware=middleware,
    )

    github_app_credentials = list(iter_github_app_credentials(
        github_app_credentials_path=parsed_arguments.github_app_credentials_path,
    ))

    app.add_route(
        '/token-exchange',
        token_exchange.TokenExchange(
            github_app_credentials=github_app_credentials,
            expected_audience=parsed_arguments.expected_audience,
        ),
    )

    if parsed_arguments.productive:
        bjoern.run(app, host, port, reuse_port=True)
    else:
        print('running in development mode')
        print()
        print(f'listening at {host}:{port}')
        print()

        import werkzeug.serving
        werkzeug.serving.run_simple(
            hostname=host,
            port=port,
            application=app,
            use_reloader=True,
            use_debugger=True,
            extra_files=(), # might add cfg-files
        )


if __name__ == '__main__':
    run_app()
