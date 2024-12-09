from typing import Dict, Optional
from loguru import logger
from .config import WidgetConfig
from ._segments import OAuthV4Segment
from ._base_v4_request import BaseV4Request

class OAuthApiClient(BaseV4Request):
    """
    Основной клиент для работы с OAuth 2.0 API AmoCRM.
    """
    # TODO: Добавить методы для amojo и drive

    def __init__(self,
                 widget: WidgetConfig,
                 debug: bool,
                 segment: str,
                 subdomain: Optional[str] = None
    ):
        """
        Инициализация клиента OAuth.

        Параметры:
            config (OAuthConfig): Конфигурация OAuth для клиента.
        """


        self.debug: bool = True

        self.config: OAuthV4ApiClient = config
        self.segment: OAuthV4Segment = OAuthV4Segment(self.config)

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._longlive_token: Optional[str] = None
        self._api_key: Optional[str] = None
        self._subdomain: Optional[str] = None


    def exchange_api_key(self) -> str:
        """
        Обмен API ключа на код авторизации OAuth.
        """
        # Пока не реализовано
        pass

    def get_access_token(self, authorization_code: str, subdomain: str, segment: str) -> Dict[str, str]:
        """
        TODO: Переименовать метод чтобы было более понятнее
        Обмен авторизационного кода на токен доступа.

        Параметры:
            authorization_code (str): Код авторизации, полученный от сервера.
            subdomain (str): Поддомен учетной записи AmoCRM.

        Возвращаемое значение:
            Dict[str, str]: Словарь с данными токенов (access_token, refresh_token).
        """
        __base_url = self.segment.get_base_domain_url()
        url = f"{__base_url}/oauth2/access_token"

        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
            "code": authorization_code,
            "grant_type": "authorization_code",
        }

        token_data = self._make_post_request(url, data)
        self.access_token = token_data["access_token"]
        self.refresh_token = token_data.get("refresh_token")
        return token_data

    def refresh_access_token(self) -> Dict[str, str]:
        """
        Обновление токена доступа с использованием refresh токена.

        Возвращаемое значение:
            Dict[str, str]: Словарь с обновленным токеном доступа и возможным refresh токеном.
        """
        if not self.refresh_token:
            raise Exception("No refresh token available")

        url = f"{self.base_url}/oauth2/access_token"
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token
        }

        token_data = self._make_post_request(url, data)
        self.access_token = token_data["access_token"]
        self.refresh_token = token_data.get("refresh_token")
        return token_data


    def make_v4_authenticated_request(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        "Здесь обарщается мидлварь"
        pass


    def make_drive_authenticated_request(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        "Здесь обарщается мидлварь"
        pass

    def make_amojo_authenticated_request(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        "Здесь обарщается мидлварь"
        pass
