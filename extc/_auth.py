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

from base64 import urlsafe_b64encode
from enum import Enum
from hashlib import sha256
from random import choice, randrange
from string import ascii_letters, digits
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse


class OAuth2Scope(str, Enum):
    TWEET_READ = "tweet.read"
    TWEET_WRITE = "tweet.write"
    TWEET_MODERATE_WRITE = "tweet.moderate.write"
    USERS_READ = "users.read"
    FOLLOWS_READ = "follows.read"
    FOLLOWS_WRITE = "follows.write"
    OFFLINE_ACCESS = "offline.access"
    SPACE_READ = "space.read"
    MUTE_READ = "mute.read"
    MUTE_WRITE = "mute.write"
    LIKE_READ = "like.read"
    LIKE_WRITE = "like.write"
    LIST_READ = "list.read"
    LIST_WRITE = "list.write"
    BLOCK_READ = "block.read"
    BLOCK_WRITE = "block.write"
    BOOKMARK_READ = "bookmark.read"
    BOOKMARK_WRITE = "bookmark.write"


class OAuth2PKCECodeExchangeWSGIApp:
    def __init__(self, client_id: str, redirect_uri: str, scopes: List[OAuth2Scope],
                 state: Optional[str] = None):
        if state is None:
            state = "".join((choice(ascii_letters + digits) for _ in range(randrange(20, 500))))

        self.__authorization_code: Optional[str] = None
        self.__code_verifier = "".join((
            choice(ascii_letters + digits + "-._~")
            for _ in range(randrange(43, 128))
        )).encode("ascii")
        self.__client_id = client_id
        self.__redirect_uri = redirect_uri
        self.__scopes = scopes
        self.__state = state
        self.__authorize_endpoint = "/authorize"
        self.__callback_endpoint = urlparse(self.__redirect_uri).path

    def __call__(self, environ: Dict[str, str],
                 start_resp: Callable[[str, List[Tuple[str, str]]], None]):
        method = environ["REQUEST_METHOD"]
        query_string = environ["QUERY_STRING"]
        query = parse_qs(query_string)
        uri = environ["PATH_INFO"]

        if method != "GET":
            start_resp("405 Method Not Allowed", [])
            return [b"Authorization exchange server only supports HTTP GET requests!"]

        if uri not in (self.__authorize_endpoint, self.__callback_endpoint):
            start_resp("404 Not Found", [])
            return [b"Unknown URI!"]

        if uri == self.__authorize_endpoint:
            start_resp("302 Moved Temporarily", [("Location", self.authorization_url)])
            return [b""]

        if not ("code" in query and "state" in query):
            start_resp("200 OK", [])
            return [
                b"Unsuccessful callback! \"code\" and \"state\" query ",
                b"parameters expected in successful callback\n\n",
                b"Received Callback: " + query_string.encode("ascii"),
            ]

        if query["state"][0] != self.__state:
            start_resp("200 OK", [])
            return [
                "\n".join([
                    "State Mismatch!",
                    f"Expected: {self.__state}",
                    f"Received: {query['state'][0]}"
                ]).encode("ascii")
            ]

        self.__authorization_code = query["code"][0]
        start_resp("200 OK", [])
        return [b"Received OAuth2 authorization code! You can close this page!"]

    @property
    def __code_challenge(self):
        return sha256(self.__code_verifier).digest()

    @property
    def authorization_code(self):
        return self.__authorization_code

    @property
    def authorization_url(self):
        return "?".join((
            "https://twitter.com/i/oauth2/authorize",
            urlencode({
                "response_type": "code",
                "client_id": self.__client_id,
                "redirect_uri": self.__redirect_uri,
                "scope": " ".join(self.__scopes),
                "state": self.__state,
                "code_challenge": urlsafe_b64encode(self.__code_challenge).rstrip(b"="),
                "code_challenge_method": "S256",
            }),
        ))

    @property
    def code_verifier(self):
        return self.__code_verifier.decode("ascii")
