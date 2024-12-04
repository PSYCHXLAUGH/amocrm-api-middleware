import requests
import logging
from typing import Dict, Optional
from .exceptions import OAuthError
from .config import OAuthConfig
from .._utils import _decode_jwt, _compare_timestamp_with_current
from amocrm_api_middleware import __version__

logger = logging.getLogger(__name__)

class OAuthClient:
    """
    Основной клиент для работы с OAuth 2.0 API AmoCRM.
    """
    # TODO: Добавить методы для amojo и drive

    def __init__(self, config: OAuthConfig):
        """
        Инициализация клиента OAuth.

        Параметры:
            config (OAuthConfig): Конфигурация OAuth для клиента.
        """
        self.config: OAuthConfig = config
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.longlive_token: Optional[str] = None
        self.api_key: Optional[str] = None
        self.base_url: Optional[str] = None

    def get_domain_info(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """
        Получение информации о домене.
        """
        endpoint = "api/v4/domain"
        return self._make_authenticated_request(endpoint, method="GET")

    def get_authorization_url(self, state: Optional[str] = None, mode: Optional[str] = None) -> str:
        """
        Генерирует URL для получения авторизационного кода.

        Параметры:
            state (Optional[str]): Необязательный параметр, который будет передан в запрос.
            mode (Optional[str]): Необязательный параметр, который будет передан в запрос, если state не указан.

        Возвращаемое значение:
            str: Сгенерированный URL для авторизации.
        """
        params = {
            "client_id": self.config.client_id,
            "state": state,
            "mode": mode
        }

        # Фильтруем None значения из параметров
        params = {key: value for key, value in params.items() if value is not None}

        return f"https://www.amocrm.ru/oauth?{self._encode_params(params)}"

    def exchange_api_key(self) -> str:
        """
        Обмен API ключа на код авторизации OAuth.
        """
        # Пока не реализовано
        pass

    def set_oauth_credentials(self, access_token: str, refresh_token: str, subdomain: str) -> bool:
        """
        Устанавливает OAuth креденшелы.
        """
        self.base_url = f"https://{subdomain}.amocrm.ru"
        self.access_token = access_token
        self.refresh_token = refresh_token
        return True

    def set_longlive_token(self, longlive_token: str, subdomain: str) -> bool:
        """
        Устанавливает longlive токен.
        """
        self.base_url = f"https://{subdomain}.amocrm.ru"
        self.longlive_token = longlive_token
        return True

    def get_access_token(self, authorization_code: str, subdomain: str) -> Dict[str, str]:
        """
        Обмен авторизационного кода на токен доступа.

        Параметры:
            authorization_code (str): Код авторизации, полученный от сервера.
            subdomain (str): Поддомен учетной записи AmoCRM.

        Возвращаемое значение:
            Dict[str, str]: Словарь с данными токенов (access_token, refresh_token).
        """
        self.base_url = f"https://{subdomain}.amocrm.ru"
        url = f"{self.base_url}/oauth2/access_token"

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
            raise OAuthError("No refresh token available")

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

    def _make_authenticated_request(self, endpoint: str, method: str = "GET", data: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Выполнение запросов к API с использованием access token.
        """
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.longlive_token if self.longlive_token else self.access_token}",
            "Content-Type": 'application/json',
            'User-Agent': f'amocrm-api-middleware/{__version__}'
        }

        response = self._make_request(url, method, headers, data)
        return response.json()

    def _make_request(self, url: str, method: str, headers: Dict[str, str], data: Optional[Dict[str, str]] = None) -> requests.Response:
        """
        Выполнение HTTP запроса.
        """
        logger.debug(f"[] Making {method} request to {url} with headers: {headers} and data: {data}")

        try:
            if method == "GET":
                return requests.get(url, headers=headers)
            elif method == "POST":
                return requests.post(url, headers=headers, json=data)
            elif method == "PATCH":
                return requests.patch(url, headers=headers, json=data)
            elif method == "PUT":
                return requests.put(url, headers=headers, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
        except requests.RequestException as e:
            logger.error(f"Request to {url} failed: {e}")
            raise OAuthError(f"Request failed: {e}")

    def _make_post_request(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        """
        Упрощение для выполнения POST запросов.
        """
        response = self._make_request(url, "POST", headers={}, data=data)
        if response.status_code != 200:
            raise OAuthError(f"Failed to post to {url}: {response.text}")
        return response.json()

    def _encode_params(self, params: Dict[str, str]) -> str:
        """
        Кодирование параметров для URL.
        """
        from urllib.parse import urlencode
        return urlencode(params)

    def decode_jwt(self, token: str) -> Dict[str, str]:
        """
        Декодирует JWT токен.
        """
        return _decode_jwt(token)

    def is_token_expired(self, token: str) -> Optional[bool]:
        """
        Проверяет, истек ли срок действия токена.
        """
        if token is None:
            return None

        jwt = _decode_jwt(token)
        jwt_exp = jwt.get('exp')

        return _compare_timestamp_with_current(jwt_exp)


