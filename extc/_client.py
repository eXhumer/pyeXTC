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
from hashlib import sha1
from hmac import new as hmac_new
from io import BufferedIOBase
from json import loads
from mimetypes import guess_type
from pkg_resources import require
from random import choice, randrange
from string import ascii_letters, digits
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import parse_qs, quote, urlparse
from webbrowser import open
from wsgiref.simple_server import make_server

from requests import Session
from requests_toolbelt import MultipartEncoder

from ._auth import OAuth1ExchangeWSGIApp, OAuth2PKCECodeExchangeWSGIApp, OAuth2Scope
from ._utils import NoLoggingWSGIRequestHandler


__version__ = require(__package__)[0].version


def _percent_encode(src: str):
    return quote(src, safe="")


class OAuth1Client:
    api_url = "https://api.twitter.com"

    @staticmethod
    def __authorize_request(method: str, url: str, oauth_consumer_key: str,
                            oauth_consumer_secret: str, oauth_timestamp: datetime,
                            oauth_nonce: Optional[str] = None, oauth_token: Optional[str] = None,
                            oauth_token_secret: Optional[str] = None,
                            params: Optional[Dict[str, str]] = None,
                            json: Optional[Dict[str, str]] = None,
                            data: Optional[Dict[str, str]] = None):
        oauth_signature, oauth_nonce = OAuth1Client.__request_signature_hmac_sha1(
            method, url, oauth_consumer_key, oauth_consumer_secret, oauth_timestamp,
            oauth_nonce=oauth_nonce, oauth_token=oauth_token,
            oauth_token_secret=oauth_token_secret, params=params, json=json, data=data)

        oauth_params = {
            "oauth_consumer_key": oauth_consumer_key,
            "oauth_nonce": oauth_nonce,
            "oauth_signature": oauth_signature,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": f"{int(oauth_timestamp.timestamp())}",
            "oauth_version": "1.0",
        }

        if oauth_token:
            oauth_params |= {"oauth_token": oauth_token}

        oauth_data = ", ".join((
            f"{_percent_encode(key)}=\"{_percent_encode(oauth_params[key])}\""
            for key
            in sorted(oauth_params, key=lambda key: _percent_encode(key))
        ))

        return f"OAuth {oauth_data}"

    @staticmethod
    def __request_signature_hmac_sha1(method: str, url: str, oauth_consumer_key: str,
                                      oauth_consumer_secret: str, oauth_timestamp: datetime,
                                      oauth_nonce: Optional[str] = None,
                                      oauth_token: Optional[str] = None,
                                      oauth_token_secret: Optional[str] = None,
                                      params: Optional[Dict[str, str]] = None,
                                      json: Optional[Dict[str, str]] = None,
                                      data: Optional[Dict[str, str]] = None):
        if not oauth_nonce:
            oauth_nonce = "".join((
                choice(ascii_letters + digits)
                for _ in range(randrange(32, 64))
            ))

        request_params = {
            "oauth_consumer_key": oauth_consumer_key,
            "oauth_nonce": oauth_nonce,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": f"{int(oauth_timestamp.timestamp())}",
            "oauth_version": "1.0",
        }

        if oauth_token is not None:
            request_params |= {"oauth_token": oauth_token}

        if params is not None:
            request_params |= params

        if data is not None and isinstance(data, dict):
            request_params |= data

        oauth_param_str = "&".join((
            f"{_percent_encode(key)}={_percent_encode(request_params[key])}"
            for key
            in sorted(request_params, key=lambda key: _percent_encode(key))
        ))

        sig_str = "&".join((
            method.upper(),
            _percent_encode(url),
            _percent_encode(oauth_param_str),
        ))

        sig_key = f"{_percent_encode(oauth_consumer_secret)}&"

        if oauth_token_secret:
            sig_key += _percent_encode(oauth_token_secret)

        return b64encode(
            hmac_new(
                sig_key.encode("ascii"),
                sig_str.encode("ascii"),
                sha1,
            ).digest(),
        ).decode("ascii"), oauth_nonce

    def __init__(self, oauth_consumer_key: str, oauth_consumer_secret: str, oauth_token: str,
                 oauth_token_secret: str, session: Optional[Session] = None):
        self.__oauth_consumer_key = oauth_consumer_key
        self.__oauth_consumer_secret = oauth_consumer_secret
        self.__oauth_token = oauth_token
        self.__oauth_token_secret = oauth_token_secret

        if session is None:
            session = Session()

        self.__session = session
        self.__session.headers["User-Agent"] = f"pyeXTC/{__version__}"

    @classmethod
    def __exchange_verifier(cls, oauth_consumer_key: str, oauth_consumer_secret: str,
                            oauth_token: str, oauth_verifier: str,
                            session: Optional[Session] = None):
        if session is None:
            session = Session()

        res = session.post(
            f"{OAuth1Client.api_url}/oauth/access_token",
            data={
                "oauth_consumer_key": oauth_consumer_key,
                "oauth_token": oauth_token,
                "oauth_verifier": oauth_verifier,
            },
        )
        res.raise_for_status()

        oauth_token_data = parse_qs(res.content.decode("ascii"))
        oauth_token = oauth_token_data["oauth_token"][0]
        oauth_token_secret = oauth_token_data["oauth_token_secret"][0]

        print(
            "\n".join((
                "New OAuth1 token",
                f"oauth_consumer_key={oauth_consumer_key}",
                f"oauth_consumer_secret={oauth_consumer_secret}",
                f"oauth_token={oauth_token}",
                f"oauth_token_secret={oauth_token_secret}",
            ))
        )

        return cls(oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret)

    @classmethod
    def new_user_authorization(cls, oauth_callback: str, oauth_consumer_key: str,
                               oauth_consumer_secret: str,
                               x_auth_access_type: Literal["read", "write"] = "read",
                               session: Optional[Session] = None):
        if session is None:
            session = Session()

        params = {"oauth_callback": oauth_callback, "x_auth_access_type": x_auth_access_type}
        timestamp = datetime.utcnow()
        request_token_url = f"{OAuth1Client.api_url}/oauth/request_token"
        authorization = OAuth1Client.__authorize_request("POST", request_token_url,
                                                         oauth_consumer_key, oauth_consumer_secret,
                                                         timestamp, params=params)

        res = session.post(request_token_url, params=params,
                           headers={"Authorization": authorization})
        res.raise_for_status()

        oauth_token_data = parse_qs(res.content.decode("ascii"))
        oauth_token = oauth_token_data["oauth_token"][0]

        url_parts = urlparse(oauth_callback)
        assert url_parts.scheme.lower() == "http"
        assert url_parts.netloc.lower().startswith(("localhost", "127.0.0.1"))
        netloc_parts = url_parts.netloc.split(":", maxsplit=1)
        host = netloc_parts[0]
        port = int(netloc_parts[1]) if len(netloc_parts) == 2 else 80

        wsgi_app = OAuth1ExchangeWSGIApp(oauth_token, oauth_callback)

        with make_server(host, port, wsgi_app, handler_class=NoLoggingWSGIRequestHandler) as srv:
            srv.timeout = 1
            open(f"http://{host}:{port}/authorize")

            while wsgi_app.oauth_verifier is None:
                srv.handle_request()

        return cls.__exchange_verifier(oauth_consumer_key, oauth_consumer_secret, oauth_token,
                                       wsgi_app.oauth_verifier, session=session)

    def _request(self, method: str, url: str, params: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None,
                 json: Optional[Dict[str, str]] = None, files: Optional[Dict[str, Any]] = None):
        authorization = OAuth1Client.__authorize_request(
            method, url, self.__oauth_consumer_key, self.__oauth_consumer_secret,
            datetime.utcnow(), oauth_token=self.__oauth_token,
            oauth_token_secret=self.__oauth_token_secret, params=params, json=json, data=data)

        if headers is not None and isinstance(headers, dict):
            headers |= {"Authorization": authorization}

        else:
            headers = {"Authorization": authorization}

        return self.__session.request(method, url, params=params, headers=headers, data=data,
                                      files=files, json=json)

    def revoke(self):
        return self._request("POST", f"{OAuth1Client.api_url}/1.1/oauth/invalidate_token.json")


class OAuth1UploadClient(OAuth1Client):
    upload_url = "https://upload.twitter.com/1.1/media/upload.json"

    def __chunked_upload_append(self, media_id: str, media_filename: str, media_bytes: bytes,
                                segment_index: int):
        mp_data = MultipartEncoder(
            fields={
                "command": "APPEND",
                "media_id": f"{media_id}",
                "segment_index": f"{segment_index}",
                "media": (media_filename, media_bytes, "application/octet-stream"),
            },
        )
        return self._request("POST", OAuth1UploadClient.upload_url, data=mp_data,
                             headers={"Content-Type": mp_data.content_type})

    def __chunked_upload_finalize(self, media_id: str):
        return self._request("POST", OAuth1UploadClient.upload_url,
                             data={"command": "FINALIZE", "media_id": media_id})

    def __chunked_upload_init(
        self,
        media_mimetype: str,
        media_size: int,
        media_category: Optional[
            Literal[
                "amplify_video",
                "tweet_gif",
                "tweet_image",
                "tweet_video",
            ]
        ] = None,
        additional_owners: Optional[List[str]] = None,
    ):
        data = {
            "command": "INIT",
            "total_bytes": media_size,
            "media_type": media_mimetype,
        }

        if media_category:
            data |= {"media_category": media_category}

        if additional_owners:
            data |= {"additional_owners": additional_owners}

        return self._request("POST", OAuth1UploadClient.upload_url, data=data)

    def __simple_upload(
        self,
        media_bytes: bytes,
        media_category: Optional[
            Literal[
                "amplify_video",
                "tweet_gif",
                "tweet_image",
                "tweet_video",
            ]
        ] = None,
        additional_owners: Optional[List[str]] = None,
    ):
        fields = {"media": media_bytes}
        if media_category is not None:
            fields |= {"media_category": media_category}

        if additional_owners is not None:
            fields |= {"additional_owners": additional_owners}

        mp_data = MultipartEncoder(fields=fields)

        return self._request("POST", OAuth1UploadClient.upload_url, data=mp_data,
                             headers={"Content-Type": mp_data.content_type})

    def upload_media(
        self,
        media_filename: str,
        media_size: int,
        media_io: BufferedIOBase,
        media_category: Optional[
            Literal[
                "amplify_video",
                "tweet_gif",
                "tweet_image",
                "tweet_video",
            ]
        ] = None,
        additional_owners: Optional[List[str]] = None,
        upload_type: Literal["simple", "chunked"] = "chunked",
    ):
        if upload_type == "simple":
            return self.__simple_upload(media_io.read(), media_category=media_category,
                                        additional_owners=additional_owners)

        else:
            res = self.__chunked_upload_init(guess_type(media_filename, strict=False)[0],
                                             media_size, media_category=media_category,
                                             additional_owners=additional_owners)
            res.raise_for_status()

            media_id: str = str(loads(res.content.decode("utf-8"))["media_id"])
            segment_index = 0

            while media_chunk := media_io.read(4 * (2 ** 10) ** 2):
                res = self.__chunked_upload_append(media_id, media_filename, media_chunk,
                                                   segment_index)
                res.raise_for_status()
                segment_index += 1

            return self.__chunked_upload_finalize(media_id)


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
            open(f"http://{host}:{port}/authorize")

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

    def create_new_tweet(self, text: str):
        return self.post("2/tweets", json={"text": text})
