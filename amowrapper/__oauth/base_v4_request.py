from loguru import logger
import requests
from typing import Optional, Dict
from amowrapper import __version__


class BaseV4Request:
    """
    Базовый класс с вспомогательными методами для выполнения запросов и работы с токенами.
    """

    def _make_request(self,
                      url: str,
                      method: str,
                      headers: Dict[str, str],
                      data: Optional[Dict[str, str]] = None) -> requests.Response:

        """
        Выполнение HTTP запроса.

        :param url: (str) URL для запроса.
        :param method: (str) HTTP метод (GET, POST, PUT, PATCH).
        :param headers: (Dict[str, str]) Заголовки запроса.
        :param data: (Optional[Dict[str, str]]) Данные для POST/PUT/PATCH запросов.
        :return: (requests.Response) Ответ от сервера.
        """
        logger.debug(f"Making {method} request to {url} with headers: {headers} and data: {data}")
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
            raise Exception(f"Request failed: {e}")

    def _make_v4_authenticated_request(self, endpoint: str, method: str = "GET", data: Optional[Dict[str, str]] = None) -> Dict[str, str]:
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
