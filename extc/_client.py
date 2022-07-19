# eXTC - Barebones Twitter client
# Copyright (C) 2022  eXhumer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3 of the
# License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from base64 import b64encode
from datetime import datetime, timedelta
from pkg_resources import require
from typing import List, Optional
from urllib.parse import urlparse
from wsgiref.simple_server import make_server

from requests import Session

from ._auth import OAuth2PKCECodeExchangeWSGIApp, OAuth2Scope
from ._utils import NoLoggingWSGIRequestHandler


__version__ = require(__package__)[0].version


class OAuth2Client:
    api_url = "https://api.twitter.com"

    def __init__(self, client_id: str, access_token: Optional[str] = None,
                 token_type: str = "bearer", expires_at: Optional[datetime] = None,
                 refresh_token: Optional[str] = None, client_secret: Optional[str] = None):
        self.__client_id = client_id
        self.__access_token = access_token
        self.__token_type = token_type
        self.__expires_at = expires_at
        self.__refresh_token = refresh_token
        self.__client_secret = client_secret
        self.__session = Session()
        self.__session.headers["User-Agent"] = f"pyeXTC/{__version__}"

    @classmethod
    def new_user_authorization(cls, client_id: str, redirect_uri: str, scopes: List[OAuth2Scope],
                               state: Optional[str] = None, client_secret: Optional[str] = None):
        ctx = cls(client_id, client_secret=client_secret)

        url_parts = urlparse(redirect_uri)
        assert url_parts.scheme.lower() == "http"
        assert url_parts.netloc.lower().startswith(("localhost", "127.0.0.1"))
        netloc_parts = url_parts.netloc.split(":", maxsplit=1)
        host = netloc_parts[0]
        port = int(netloc_parts[1]) if len(netloc_parts) == 2 else 80

        wsgi_app = OAuth2PKCECodeExchangeWSGIApp(client_id, redirect_uri, scopes, state=state)

        with make_server(host, port, wsgi_app, handler_class=NoLoggingWSGIRequestHandler) as srv:
            srv.timeout = 1

            while wsgi_app.authorization_code is None:
                srv.handle_request()

        ctx.__exchange_authorization_code(client_id, wsgi_app.authorization_code,
                                          wsgi_app.code_verifier, redirect_uri,
                                          client_secret=client_secret)

        return ctx

    @property
    def access_token(self):
        return self.__access_token

    @property
    def refresh_token(self):
        return self.__refresh_token

    def __exchange_authorization_code(self, client_id: str, authorization_code: str,
                                      code_verifier: str, redirect_uri: str,
                                      client_secret: Optional[str] = None):
        token_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }

        if client_secret:
            headers = {
                "Authorization": " ".join((
                    "Basic",
                    b64encode(
                        f"{client_id}:{client_secret}".encode("ascii"),
                    ).decode("ascii"),
                ))
            }

        else:
            headers = None
            token_data.update(client_id=client_id)

        res = self.__session.post(
            f"{OAuth2Client.api_url}/2/oauth2/token",
            headers=headers,
            data=token_data,
        )
        res.raise_for_status()
        token_data = res.json()
        access_token: str = token_data["access_token"]
        self.__access_token = access_token
        expires_in: int = token_data["expires_in"]
        self.__expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        token_type: str = token_data["token_type"]
        self.__token_type = token_type

        if "refresh_token" in token_data:
            refresh_token: str = token_data["refresh_token"]
            self.__refresh_token = refresh_token

    def __clean_api_url(self, uri: str):
        while uri[:1] == "/":
            uri = uri[1:]

        return f"{self.api_url}/{uri}"

    def __request(self, method: str, uri: str, **kwargs):
        if "headers" in kwargs:
            if "Authorization" not in kwargs["headers"]:
                if (
                    self.__expires_at and
                    self.__refresh_token and
                    datetime.utcnow() >= self.__expires_at
                ):
                    self.__refresh()

                elif self.__refresh_token and self.__access_token is None:
                    self.__refresh()

                kwargs["headers"]["Authorization"] = " ".join((
                    self.__token_type,
                    self.__access_token,
                ))

        else:
            if (
                self.__expires_at and
                self.__refresh_token and
                datetime.utcnow() >= self.__expires_at
            ):
                self.__refresh()

            elif self.__refresh_token and self.__access_token is None:
                self.__refresh()

            kwargs.update(
                headers={
                    "Authorization": " ".join((
                        self.__token_type,
                        self.__access_token,
                    )),
                },
            )

        return self.__session.request(
            method,
            self.__clean_api_url(uri),
            **kwargs,
        )

    def delete(self, uri: str, **kwargs):
        return self.__request("DELETE", uri, **kwargs)

    def get(self, uri: str, **kwargs):
        return self.__request("GET", uri, **kwargs)

    def patch(self, uri: str, **kwargs):
        return self.__request("PATCH", uri, **kwargs)

    def post(self, uri: str, **kwargs):
        return self.__request("POST", uri, **kwargs)

    def put(self, uri: str, **kwargs):
        return self.__request("PUT", uri, **kwargs)

    def __refresh(self):
        assert self.__refresh_token

        token_data = {"grant_type": "refresh_token", "refresh_token": self.__refresh_token}

        if self.__client_secret:
            headers = {
                "Authorization": " ".join((
                    "Basic",
                    b64encode(
                        f"{self.__client_id}:{self.__client_secret}"
                        .encode("ascii"),
                    ).decode("ascii"),
                ))
            }

        else:
            headers = None
            token_data.update(client_id=self.__client_id)

        res = self.__session.post(
            f"{OAuth2Client.api_url}/2/oauth2/token",
            headers=headers,
            data=token_data,
        )
        res.raise_for_status()
        token_data = res.json()
        access_token: str = token_data["access_token"]
        self.__access_token = access_token
        expires_in: int = token_data["expires_in"]
        self.__expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        token_type: str = token_data["token_type"]
        self.__token_type = token_type

    def revoke(self):
        token_data = {
            "token": self.__access_token,
            "token_type_hint": "access_token",
        }

        if self.__client_secret:
            headers = {
                "Authorization": " ".join((
                    "Basic",
                    b64encode(
                        f"{self.__client_id}:{self.__client_secret}"
                        .encode("ascii"),
                    ).decode("ascii"),
                ))
            }

        else:
            headers = None
            token_data.update(client_id=self.__client_id)

        res = self.__session.post(
            f"{OAuth2Client.api_url}/2/oauth2/revoke",
            headers=headers,
            data=token_data,
        )
        res.raise_for_status()
        assert res.json()["revoked"] is True
        self.__access_token = None
        self.__expires_at = None
        self.__token_type = None

        if self.__refresh_token:
            token_data = {
                "token": self.__refresh_token,
                "token_type_hint": "refresh_token",
            }

            if self.__client_secret:
                headers = {
                    "Authorization": " ".join((
                        "Basic",
                        b64encode(
                            f"{self.__client_id}:{self.__client_secret}"
                            .encode("ascii"),
                        ).decode("ascii"),
                    ))
                }

            else:
                headers = None
                token_data.update(client_id=self.__client_id)

            res = self.__session.post(
                f"{OAuth2Client.api_url}/2/oauth2/revoke",
                headers=headers,
                data=token_data,
            )
            res.raise_for_status()
            assert res.json()["revoked"] is True
            self.__refresh_token = None
