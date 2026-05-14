from contextlib import asynccontextmanager
from datetime import date
import secrets
from typing import Optional

import aiohttp

from mal.errors import (
    AuthenticationError,
    BadRequestError,
    ForbiddenError,
    HTTPError,
    InputError,
    NotFoundError,
    OAuthConfigError,
    UnauthorizedError,
)
from mal.models import Anime, Auth, User, WatchStatus
from mal.types import SEASONAL_LIST_SORT, SEASONS, USER_ANIME_STATUS, USER_LIST_SORT

AUTH_URL = "https://myanimelist.net/v1"
BASE_URL = "https://api.myanimelist.net/v1"
N_BYTES = 96
QUERY_LIMIT = 100
OFFSET_LIMIT = 100
VERIFIER_LENGTH = 128
CODE_CHALLENGE_METHOD = "plain"


class Client:
    """
    Client used to interact with MyAnimeList API
    """

    __ANIME_FIELDS = (
        "id,title,main_picture,alternative_titles,start_date,end_date,synopsis,"
        "mean,rank,popularity,num_list_users,num_scoring_users,nsfw,genres,created_at,updated_at,"
        "media_type,status,my_list_status,num_episodes,start_season,broadcast,source,average_episode_duration,"
        "rating,pictures,background,related_anime,related_manga,recommendations,statistics,studios"
    )

    __USER_FIELDS = "id,name,picture,gender,birthday,location,joined_at,anime_statistics,time_zone,is_supporter"

    def __init__(
        self,
        *,
        client_secret: Optional[str] = None,
        client_id: Optional[str] = None,
        callback_url: Optional[str] = None,
        session: Optional[aiohttp.ClientSession] = None,
        resuse_session: bool = False,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = session
        self._callback_url = callback_url

        if resuse_session and not self._session:
            self._session = aiohttp.ClientSession()

    @asynccontextmanager
    async def _get_session(self):
        if self._session:
            yield self._session
        else:
            async with aiohttp.ClientSession() as session:
                yield session

    def _set_headers(self, args: dict):
        headers = args.pop("headers", {})

        token = args.pop("token", None)
        if not token and not self._client_id:
            raise AuthenticationError("Client ID or User Access Token Must Be Provided")

        if token:
            headers["Authorization"] = f"Bearer {token}"

        if self._client_id:
            headers["X-MAL-CLIENT-ID"] = self._client_id

        headers["User-Agent"] = "Mal.py (https://github.com/SageTendo/mal.py)"
        args["headers"] = headers

    def _handle_error(self, resp: aiohttp.ClientResponse, data: dict):
        if resp.status == 400:
            raise BadRequestError(resp, data.get("error", "Bad Request"))
        if resp.status == 401:
            raise UnauthorizedError(
                resp,
                data.get("error", "Unauthorized: No/Invalid Token Provided"),
            )
        if resp.status == 403:
            raise ForbiddenError(
                resp,
                data.get(
                    "error",
                    "Forbidden: No/Invalid Token Provided or User Not Found",
                ),
            )
        if resp.status == 404:
            raise NotFoundError(resp, data.get("error", "Resource Not Found"))

    async def _get(self, url: str, **kwargs) -> dict:
        self._set_headers(kwargs)
        async with self._get_session() as session:
            async with session.get(url, **kwargs) as resp:
                data = await resp.json()

                if resp.status == 200:
                    return data

                if 400 <= resp.status < 500:
                    self._handle_error(resp, data)
                raise HTTPError(resp, await resp.text() or "Unknown Error")

    async def _post(self, url: str, **kwargs) -> dict:
        self._set_headers(kwargs)
        async with self._get_session() as session:
            async with session.post(url, **kwargs) as resp:
                data = await resp.json()

                if resp.status == 200:
                    return data

                if 400 <= resp.status < 500:
                    self._handle_error(resp, data)
                raise HTTPError(resp, await resp.text() or "Unknown Error")

    async def _put(self, url: str, **kwargs) -> dict:
        self._set_headers(kwargs)
        async with self._get_session() as session:
            async with session.put(url, **kwargs) as resp:
                data = await resp.json()

                if resp.status == 200:
                    return data

                if 400 <= resp.status < 500:
                    self._handle_error(resp, data)
                raise HTTPError(resp, await resp.text() or "Unknown Error")

    def _check_required_oauth_info(self):
        if not self._client_id:
            raise OAuthConfigError("Client ID Must Be Provided For OAuth Flow")

        if not self._client_secret:
            raise OAuthConfigError("Client Secret Must Be Provided For OAuth Flow")

        if not self._callback_url:
            raise OAuthConfigError("Redirect URI Must Be Provided For OAuth Flow")

    def _generate_verifier_challenger_pair(self, method: str = ""):
        """
        Generate a verifier and challenge as a tuple
        :param length: The length of the verifier string
        :param method: The method to use to generate the challenge
        :return: verifier, challenge
        """
        verifier = self._generate_verifier()
        return verifier, self._generate_challenge(verifier, method)

    def _generate_verifier(self):
        """
        Generate a random verifier string using the Secrets library
        :param length: The length of the verifier string
        :return: verifier
        """
        if not 43 <= VERIFIER_LENGTH <= 128:
            raise OAuthConfigError(
                "Param: 'Length' must be a min of 43 or a max of 128"
            )
        return secrets.token_urlsafe(N_BYTES)[:VERIFIER_LENGTH]

    def _generate_challenge(self, verifier, method):
        """
        Generate a challenge string using the Secrets library
        :param verifier: The verifier string
        :param method: The method to use to generate the challenge
        :return: the generated challenge
        """
        if not method or method == "plain":
            return verifier
        return None

    def get_auth(self) -> tuple[str, str]:
        """
        Get the authorization URL for MyAnimeList API
        :return: Authorization URL & Code Verifier
        """
        self._check_required_oauth_info()
        state = secrets.token_urlsafe(N_BYTES)[:16]
        code_verifier, code_challenge = self._generate_verifier_challenger_pair(
            method=CODE_CHALLENGE_METHOD
        )

        query_params = (
            f"response_type=code"
            f"&client_id={self._client_id}"
            f"&state={state}"
            f"&code_challenge={code_challenge}"
            f"&code_challenge_method={CODE_CHALLENGE_METHOD}"
            f"&redirect_uri={self._callback_url}"
        )
        return f"{AUTH_URL}/oauth2/authorize?{query_params}", code_verifier

    async def get_access_token(
        self, authorization_code: str, code_verifier: str
    ) -> Auth:
        """
        Get the access token for MyAnimeList
        :param authorization_code: Generated by MAL API when a user authorizes the app
        :param code_verifier: A unique string generated upon every authorization request by the client
        :return: Auth
        """
        self._check_required_oauth_info()
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "authorization_code",
            "code": authorization_code,
            "code_verifier": code_verifier,
            "redirect_uri": self._callback_url,
        }

        resp = await self._post(url=f"{AUTH_URL}/oauth2/token", data=data)
        return Auth(resp)

    async def refresh_token(self, refresh_token: str) -> Auth:
        """
        Refresh the access token for MyAnimeList
        :param refresh_token: Refresh Token
        :return: Auth
        """
        self._check_required_oauth_info()
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        resp = await self._post(url=f"{AUTH_URL}/oauth2/token", data=data)
        return Auth(resp)

    async def get_user_details(self, *, token: str) -> User:
        """
        Get the user's details from MyAnimeList
        :param token: The user's access token
        :return: User
        """
        if not token:
            raise InputError("User Access Token Must Be Provided")

        url = f"{BASE_URL}/users/@me?fields={self.__USER_FIELDS}"
        resp = await self._get(url, token=token)
        return User(resp)

    async def get_user_anime_list(
        self,
        *,
        token: str,
        limit: int = 1,
        offset: int = 0,
        sort: USER_LIST_SORT = "list_updated_at",
        status: USER_ANIME_STATUS = "watching",
        nsfw: bool = False,
    ) -> list[Anime]:
        """
        Get a user's list of anime from MyAnimeList
        :param token: The user's access token
        :param limit: The number of results to return
        :param offset: The number of results to skip (used for pagination)
        :param sort: Sort results by the given sort type
        :param status: Filter results by the status of the anime
        :return: list[Anime]
        """
        if not token:
            raise InputError("User Access Token Must Be Provided")

        limit = max(0, min(limit, QUERY_LIMIT))
        offset = max(0, min(offset, OFFSET_LIMIT))

        url = (
            f"{BASE_URL}/users/@me/animelist"
            f"?limit={limit}"
            f"&offset={offset}"
            f"&sort={sort}"
            f"&status={status}"
            f"&fields={self.__ANIME_FIELDS}"
            f"&nsfw={nsfw}"
        )
        resp = await self._get(url, token=token)
        return [Anime(anime["node"], client=self) for anime in resp["data"]]
    
    async def get_seasonal_anime_list(
        self,
        *,
        token: str,
        limit: int = 1,
        offset: int = 0,
        sort: SEASONAL_LIST_SORT = "anime_num_list_users",
        nsfw: bool = False,
        year: int = 2026,
        season: SEASONS = "summer",
    ) -> list[Anime]:
        """
        Get a list of seasonal anime from MyAnimeList
        :param token: The user's access token
        :param limit: The number of results to return
        :param offset: The number of results to skip (used for pagination)
        :param sort: Sort results by the given sort type
        :param nsfw: Whether to include NSFW content
        :param year: The year of the season
        :param season: The season
        :return: list[Anime]
        """
        limit = max(0, min(limit, QUERY_LIMIT))
        offset = max(0, min(offset, OFFSET_LIMIT))
        season = season.lower()

        url = (
            f"{BASE_URL}/anime/season/{year}/{season}"
            f"?limit={limit}"
            f"&offset={offset}"
            f"&sort={sort}"
            f"&fields={self.__ANIME_FIELDS}"
            f"&nsfw={nsfw}"
        )
        resp = await self._get(url, token=token)
        return [Anime(anime["node"], client=self) for anime in resp["data"]]

    async def search_anime(
        self,
        *,
        query: str,
        limit: int = 100,
        offset: int = 0,
        nsfw: bool = False,
    ) -> list[Anime]:
        """
        Get a list of anime from MyAnimeList
        :param token: The user's access token
        :param query: The search query
        :return: list[Anime]
        """
        if not query:
            raise InputError("A Valid Query Must Be Provided")

        if len(query) < 3:
            raise InputError("Query Must Be At Least 3 Characters")

        limit = max(0, min(limit, QUERY_LIMIT))
        offset = max(0, min(offset, OFFSET_LIMIT))

        url = f"{BASE_URL}/anime?q={query}&limit={limit}&offset={offset}&fields={self.__ANIME_FIELDS}&nsfw={nsfw}"
        resp = await self._get(url)
        return [Anime(anime["node"], client=self) for anime in resp["data"]]

    async def get_anime_details(
        self, *, anime_id: str, token: Optional[str] = None
    ) -> Anime:
        """
        Get anime details from MyAnimeList
        :param token: The user's access token
        :param anime_id: The ID of the anime to get details for
        :return: Anime
        """
        if not anime_id:
            raise InputError("A Valid Anime ID Must Be Provided")

        url = f"{BASE_URL}/anime/{anime_id}?fields={self.__ANIME_FIELDS}"
        resp = await self._get(url, token=token)
        return Anime(resp, client=self)

    async def update_watch_status(
        self,
        *,
        anime_id: str,
        episode: int,
        status: USER_ANIME_STATUS = "watching",
        start_date: str = "",
        finish_date: str = "",
        token: Optional[str] = None,
    ) -> WatchStatus:
        """
        Update the watch status of an anime in a user's watchlist
        :param token: The user's access token
        :param anime_id: The ID of the anime
        :param episode: The episode that is being watched
        :param status: The status to update the anime to
        :param start_date: The date the user started watching the anime
        :param finish_date: The date the user finished watching the anime
        :return: WatchStatus
        """
        if not anime_id:
            raise InputError("A Valid Anime ID Must Be Provided")

        url = f"{BASE_URL}/anime/{anime_id}/my_list_status"
        body = {"status": status, "num_watched_episodes": episode}

        if start_date:
            try:
                date.fromisoformat(start_date)
                body["start_date"] = start_date
            except ValueError:
                raise InputError("Invalid Start Date Provided")

        if finish_date:
            try:
                date.fromisoformat(finish_date)
                body["finish_date"] = finish_date
            except ValueError:
                raise InputError("Invalid Finish Date Provided")

        resp = await self._put(url, data=body, token=token)
        return WatchStatus(resp, anime_id=anime_id)

    async def close(self):
        if self._session:
            await self._session.close()
